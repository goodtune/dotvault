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

func TestWaitForClientErrorsWhenGracePeriodExpires(t *testing.T) {
	mr := newManagedRemote(remote("foo.example.com"), Deps{})

	start := time.Now()
	_, err := mr.WaitForClient(context.Background())
	if err == nil {
		t.Fatal("WaitForClient() succeeded with no client ever installed; want a timeout error")
	}
	if elapsed := time.Since(start); elapsed < ClientWaitTimeout {
		t.Errorf("WaitForClient() returned after %s, want it to wait out the full %s grace period", elapsed, ClientWaitTimeout)
	}
}
