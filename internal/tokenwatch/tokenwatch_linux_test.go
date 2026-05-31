//go:build linux

package tokenwatch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTokenAtomically mirrors how `vault login` and dotvault's own
// writers replace the token file: write a sibling temp file, then
// rename it over the target. This is the IN_MOVED_TO path that an
// inode-level watch would miss.
func writeTokenAtomically(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp token: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename temp token: %v", err)
	}
}

// startWatch runs Watch in a goroutine against a fresh signalling
// channel and returns the token path, a channel that receives on every
// onChange, and a stop func that cancels the watch and waits for it.
func startWatch(t *testing.T) (tokenPath string, changes <-chan struct{}, stop func()) {
	t.Helper()
	dir := t.TempDir()
	tokenPath = filepath.Join(dir, ".vault-token")

	ch := make(chan struct{}, 16)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Watch(ctx, tokenPath, func() { ch <- struct{}{} })
	}()

	// The watch is established synchronously inside Watch before it
	// blocks in Poll, but the goroutine may not have been scheduled yet.
	// A brief settle avoids racing the first write ahead of the watch.
	time.Sleep(50 * time.Millisecond)

	return tokenPath, ch, func() {
		cancel()
		<-done
	}
}

func waitForChange(t *testing.T, changes <-chan struct{}) {
	t.Helper()
	select {
	case <-changes:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for token-change callback")
	}
}

func assertNoChange(t *testing.T, changes <-chan struct{}) {
	t.Helper()
	select {
	case <-changes:
		t.Fatal("unexpected token-change callback")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestWatch_FiresOnAtomicReplace(t *testing.T) {
	tokenPath, changes, stop := startWatch(t)
	defer stop()

	writeTokenAtomically(t, tokenPath, "first")
	waitForChange(t, changes)

	// And again on a subsequent replacement — proving the directory
	// watch survives the inode swap (an inode-level watch would have
	// gone deaf after the first rename).
	writeTokenAtomically(t, tokenPath, "second")
	waitForChange(t, changes)
}

func TestWatch_FiresOnInPlaceWrite(t *testing.T) {
	tokenPath, changes, stop := startWatch(t)
	defer stop()

	if err := os.WriteFile(tokenPath, []byte("created"), 0o600); err != nil {
		t.Fatalf("create token: %v", err)
	}
	waitForChange(t, changes)
}

func TestWatch_IgnoresDelete(t *testing.T) {
	tokenPath, changes, stop := startWatch(t)
	defer stop()

	writeTokenAtomically(t, tokenPath, "present")
	waitForChange(t, changes)

	if err := os.Remove(tokenPath); err != nil {
		t.Fatalf("remove token: %v", err)
	}
	assertNoChange(t, changes)
}

func TestWatch_IgnoresOtherFiles(t *testing.T) {
	tokenPath, changes, stop := startWatch(t)
	defer stop()

	// A sibling file in the same directory must not trigger the
	// token-scoped callback.
	other := filepath.Join(filepath.Dir(tokenPath), "unrelated")
	if err := os.WriteFile(other, []byte("noise"), 0o600); err != nil {
		t.Fatalf("write sibling: %v", err)
	}
	assertNoChange(t, changes)
}

func TestWatch_ReturnsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".vault-token")

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- Watch(ctx, tokenPath, func() {}) }()

	cancel()
	select {
	case err := <-errCh:
		if err != context.Canceled {
			t.Fatalf("Watch returned %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Watch did not return after context cancellation")
	}
}

func TestWatch_ErrorsOnMissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope", ".vault-token")
	err := Watch(context.Background(), missing, func() {})
	if err == nil {
		t.Fatal("expected error watching a non-existent directory, got nil")
	}
}
