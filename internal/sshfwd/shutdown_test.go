package sshfwd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// promptly runs fn and fails the test if it has not returned within limit.
// The goroutine is deliberately not waited on afterwards: the whole point of
// the assertion is that fn may still be stuck, and blocking on it would turn
// a clean failure into a hung test binary.
func promptly(t *testing.T, limit time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s did not return within %s", what, limit)
	}
}

// TestStopReturnsPromptlyWhileIdentityResolutionBlocks is the regression test
// for the reported Windows shutdown hang. Deps.Signers stands in for the SSH
// agent backend's List(), which resolves under a hardcoded context.Background()
// and so keeps running for its own Vault timeout no matter what the daemon's
// context does. Before run bounded that call, stop()'s wg.Wait() sat behind it.
func TestStopReturnsPromptlyWhileIdentityResolutionBlocks(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	entered := make(chan struct{})
	var once atomic.Bool

	mr := newManagedRemote(remote("foo.example.com"), Deps{
		Signers: func() ([]ssh.Signer, error) {
			if once.CompareAndSwap(false, true) {
				close(entered)
			}
			// Deaf to cancellation, exactly like the real agent backend.
			<-release
			return nil, errors.New("released")
		},
		User:   func() (string, error) { return "gary", nil },
		Policy: func(Remote) *HostKeyPolicy { return &HostKeyPolicy{} },
		Target: func(context.Context) (net.Conn, error) { return nil, errors.New("not used by this test") },
	})

	mr.start(context.Background(), mr.run)

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("run never reached identity resolution")
	}

	promptly(t, 2*time.Second, "stop()", mr.stop)
}

// TestDialCancellationInterruptsHandshake covers the window the run-loop bound
// cannot reach, because the dial runs on the very goroutine stop() waits for:
// a host that completes the TCP connection but never speaks SSH. The listener
// below accepts and then says nothing, so ssh.NewClientConn blocks reading the
// version banner — the wedged-sshd / black-holed-route case. Cancellation must
// interrupt it rather than being noticed only after the dial timeout expires.
//
// A real TCP listener, not net.Pipe: the handshake path needs a genuine
// net.Conn with working deadlines and Close semantics.
func TestDialCancellationInterruptsHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	handshaking := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Read the client's version banner before signalling. Accepting alone
		// would not be enough: the client's DialContext can still be returning
		// at that point, and a cancel landing there is caught by DialContext
		// itself — which would let this test pass on the TCP path without ever
		// exercising the handshake. A banner from the client proves it is
		// inside ssh.NewClientConn.
		if _, err := conn.Read(make([]byte, 64)); err != nil {
			return
		}
		close(handshaking)
		// Now stay silent: never send a version banner back, so the client
		// blocks reading one.
		<-release
		_ = conn.Close()
	}()

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	type dialResult struct {
		client *ssh.Client
		err    error
	}
	res := make(chan dialResult, 1)
	go func() {
		c, err := Dial(ctx, DialConfig{
			Host:    host,
			Port:    port,
			User:    "gary",
			Signers: []ssh.Signer{signer},
			// Never actually consulted — the server sends no banner, so the
			// handshake blocks long before host key verification.
			HostKey: &HostKeyPolicy{Insecure: true},
			// The real DefaultDialTimeout, so a pass proves cancellation did
			// the work rather than a shortened timeout beating the assertion.
			Timeout: DefaultDialTimeout,
		})
		res <- dialResult{c, err}
	}()

	select {
	case <-handshaking:
	case <-time.After(5 * time.Second):
		t.Fatal("dial never got into the SSH handshake")
	}

	cancel()

	select {
	case out := <-res:
		if out.client != nil {
			_ = out.client.Close()
		}
		if !errors.Is(out.err, context.Canceled) {
			t.Errorf("Dial() error = %v, want context.Canceled", out.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Dial did not return within 3s of cancellation (waiting out the %s timeout?)", DefaultDialTimeout)
	}
}

// TestManagerCloseStopsRemotesConcurrently pins that Close costs about one
// remote's teardown, not the sum of all of them. Each runner ignores its
// context for a fixed delay, so a serial Close would take 5×delay.
func TestManagerCloseStopsRemotesConcurrently(t *testing.T) {
	const (
		remotes  = 5
		stopCost = 300 * time.Millisecond
	)

	m := NewManager(context.Background(), Deps{})
	m.newRunner = func(string) func(context.Context) {
		return func(ctx context.Context) {
			<-ctx.Done()
			// Stand in for a teardown that takes real time (an in-flight dial
			// unwinding, forwarding goroutines finishing) — deliberately not
			// cancellable, so the cost cannot be optimised away.
			time.Sleep(stopCost)
		}
	}

	cfgs := make([]Remote, 0, remotes)
	for _, h := range []string{"a", "b", "c", "d", "e"} {
		cfgs = append(cfgs, remote(h+".example.com"))
	}
	if err := m.Reconcile(context.Background(), cfgs); err != nil {
		t.Fatalf("Reconcile() = %v", err)
	}

	start := time.Now()
	m.Close()
	elapsed := time.Since(start)

	// Generous ceiling: concurrent is ~1×stopCost, serial would be 5× (1.5s).
	if limit := 3 * stopCost; elapsed > limit {
		t.Errorf("Close() took %s for %d remotes, want under %s (serial teardown?)", elapsed, remotes, limit)
	}
}
