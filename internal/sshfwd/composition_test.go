package sshfwd

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeTransport overrides dialRemote, forwardRemote, keepaliveRemote, and
// closeRemoteClient for the duration of a test, restoring the real
// implementations on cleanup. It exists so run()'s and serveConnected's
// composition — the dial→serve→keepalive→teardown→backoff→redial cycle —
// runs for real without a live SSH connection: production Dial/ServeForward
// need a genuine *ssh.Client to operate on, and this package's convention
// (see the top-level review notes) is not to fake that with net.Pipe, so
// these tests instead replace the operations themselves rather than trying
// to fabricate a working transport underneath them.
func fakeTransport(t *testing.T) {
	t.Helper()
	origDial, origForward, origKeepalive, origClose := dialRemote, forwardRemote, keepaliveRemote, closeRemoteClient
	t.Cleanup(func() {
		dialRemote, forwardRemote, keepaliveRemote, closeRemoteClient = origDial, origForward, origKeepalive, origClose
	})
}

// dropOnce returns a forwardRemote replacement that fails with err on its
// first call, then blocks on ctx thereafter — so a test can force exactly
// one drop-and-reconnect and then let the following connection sit healthy
// until the test cancels it.
func dropOnce(err error) func(ctx context.Context, cl *ssh.Client, socket string, target Dialer, onConn func(int)) error {
	var dropped int32
	return func(ctx context.Context, cl *ssh.Client, socket string, target Dialer, onConn func(int)) error {
		if atomic.CompareAndSwapInt32(&dropped, 0, 1) {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}
}

// blockingKeepalive never trips on its own; it only ever returns because
// forwardRemote's error already cancelled connCtx (serveConnected's
// first-of-two-errors rule) or because the outer ctx was cancelled by stop.
func blockingKeepalive(ctx context.Context, cl requestSender, interval time.Duration, strikes int) error {
	<-ctx.Done()
	return ctx.Err()
}

// TestRunConnectServeDropReconnectCycle exercises the feature's entire
// premise end to end: a first successful connect, a forced drop, and a
// second successful connect — asserting the state transitions and that
// Reconnects increments exactly once, not on every intermediate step.
func TestRunConnectServeDropReconnectCycle(t *testing.T) {
	fakeTransport(t)

	var dialCount int32
	dialRemote = func(ctx context.Context, c DialConfig) (*ssh.Client, error) {
		atomic.AddInt32(&dialCount, 1)
		return &ssh.Client{}, nil
	}
	closeRemoteClient = func(c *ssh.Client) error { return nil }
	forwardRemote = dropOnce(errors.New("simulated forward drop"))
	keepaliveRemote = blockingKeepalive

	mr := newManagedRemote(Remote{Host: "foo.example.com", RemoteSocket: "/run/dotvault-test.sock"}, Deps{
		Signers: func() ([]ssh.Signer, error) { return nil, nil },
		User:    func() (string, error) { return "u", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{} },
		Target:  func(ctx context.Context) (net.Conn, error) { return nil, errors.New("not used by this test") },
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		mr.run(ctx)
		close(done)
	}()

	// Wait for the second dial: first connect, forced drop, backoff, redial.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&dialCount) < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&dialCount); got < 2 {
		t.Fatalf("dial count = %d after a forced drop, want >= 2 (a reconnect)", got)
	}

	// Give the second connection a moment to reach StateConnected — dialCount
	// increments inside dialRemote, which returns before run() has finished
	// calling serveConnected and setting the state.
	var got RemoteStatus
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got = mr.status("")
		if got.State == string(StateConnected) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got.State != string(StateConnected) {
		t.Errorf("state after reconnect = %q, want %q", got.State, StateConnected)
	}
	if got.Reconnects != 1 {
		t.Errorf("Reconnects = %d, want exactly 1 (one drop, one reconnect)", got.Reconnects)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run() did not exit after ctx cancellation")
	}
}

// TestRunReResolvesSignersUserPolicyPerAttempt is the regression test for
// the identity design's load-bearing assumption: Signers, User, and Policy
// are re-invoked on every connection attempt, not resolved once and reused.
// Without this, a Vault-CA certificate rotated between the first connection
// and a later reconnect would never be picked up — exactly the scenario
// run's own doc comment calls out.
func TestRunReResolvesSignersUserPolicyPerAttempt(t *testing.T) {
	fakeTransport(t)

	dialRemote = func(ctx context.Context, c DialConfig) (*ssh.Client, error) {
		return &ssh.Client{}, nil
	}
	closeRemoteClient = func(c *ssh.Client) error { return nil }
	forwardRemote = dropOnce(errors.New("simulated forward drop"))
	keepaliveRemote = blockingKeepalive

	var signersCalls, userCalls, policyCalls int32
	mr := newManagedRemote(Remote{Host: "foo.example.com", RemoteSocket: "/run/dotvault-test.sock"}, Deps{
		Signers: func() ([]ssh.Signer, error) {
			atomic.AddInt32(&signersCalls, 1)
			return nil, nil
		},
		User: func() (string, error) {
			atomic.AddInt32(&userCalls, 1)
			return "u", nil
		},
		Policy: func(Remote) *HostKeyPolicy {
			atomic.AddInt32(&policyCalls, 1)
			return &HostKeyPolicy{}
		},
		Target: func(ctx context.Context) (net.Conn, error) { return nil, errors.New("not used by this test") },
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		mr.run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&signersCalls) >= 2 && atomic.LoadInt32(&userCalls) >= 2 && atomic.LoadInt32(&policyCalls) >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if n := atomic.LoadInt32(&signersCalls); n < 2 {
		t.Errorf("Signers called %d times across two connection attempts, want >= 2 (re-resolved per attempt, not cached)", n)
	}
	if n := atomic.LoadInt32(&userCalls); n < 2 {
		t.Errorf("User called %d times across two connection attempts, want >= 2", n)
	}
	if n := atomic.LoadInt32(&policyCalls); n < 2 {
		t.Errorf("Policy called %d times across two connection attempts, want >= 2", n)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run() did not exit after ctx cancellation")
	}
}
