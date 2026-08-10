package sshfwd

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestWaitForClientReturnsImmediatelyWhenConnected(t *testing.T) {
	mr := newManagedRemote(remote("foo.example.com"), Deps{})
	want := &ssh.Client{}
	mr.setClient(want)

	start := time.Now()
	got, err := mr.WaitForClient(context.Background())
	if err != nil {
		t.Fatalf("WaitForClient() = %v", err)
	}
	if got != want {
		t.Errorf("WaitForClient() returned a different client than the one installed")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("WaitForClient() took %s for an already-connected remote, want immediate", elapsed)
	}
}

func TestWaitForClientBlocksThenSucceedsDuringGracePeriod(t *testing.T) {
	mr := newManagedRemote(remote("foo.example.com"), Deps{})
	want := &ssh.Client{}

	go func() {
		time.Sleep(50 * time.Millisecond)
		mr.setClient(want)
	}()

	got, err := mr.WaitForClient(context.Background())
	if err != nil {
		t.Fatalf("WaitForClient() = %v", err)
	}
	if got != want {
		t.Errorf("WaitForClient() returned a different client than the one installed")
	}
}

// TestTeardownConnectionClearsClientBeforeClosing is the regression test for
// I4: serveConnected must clear the live client pointer before closing the
// underlying transport, not after, so a WaitForClient call racing teardown
// can never be handed a *ssh.Client that is already (or about to be) closed
// out from under it. closeFn stands in for the real transport's Close — the
// property under test is purely about ordering, not about what closing an
// *ssh.Client actually does, so a recording stub is enough and needs no live
// SSH connection.
func TestTeardownConnectionClearsClientBeforeClosing(t *testing.T) {
	mr := newManagedRemote(remote("foo.example.com"), Deps{})
	mr.setClient(&ssh.Client{})

	var clientWasClearedBeforeClose bool
	closeFn := func() error {
		mr.mu.Lock()
		clientWasClearedBeforeClose = mr.client == nil
		mr.mu.Unlock()
		return nil
	}

	mr.teardownConnection(closeFn)

	if !clientWasClearedBeforeClose {
		t.Error("client field was still set when the transport's Close was called; want it cleared first")
	}
}

func TestWaitForClientErrorsWhenGracePeriodExpires(t *testing.T) {
	mr := newManagedRemote(remote("foo.example.com"), Deps{})
	// Shrink the grace period rather than waiting out the real
	// ClientWaitTimeout (10s): the assertion below is on the wall clock, so
	// it must use whatever timeout WaitForClient actually waits on to stay
	// meaningful, and a short one keeps the package's test suite fast.
	const timeout = 50 * time.Millisecond
	mr.clientWaitTimeout = timeout

	start := time.Now()
	_, err := mr.WaitForClient(context.Background())
	if err == nil {
		t.Fatal("WaitForClient() succeeded with no client ever installed; want a timeout error")
	}
	if elapsed := time.Since(start); elapsed < timeout {
		t.Errorf("WaitForClient() returned after %s, want it to wait out the full %s grace period", elapsed, timeout)
	}
}
