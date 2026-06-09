//go:build linux

package tokenwatch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestNew_RegistersBeforeReturn is the critical regression test for the
// startup race. New must complete InotifyAddWatch synchronously, so a
// write that lands in the window between New returning and Run starting
// is queued by the kernel and delivered once Run begins. We prove this
// by writing the token *before* the Run goroutine starts and asserting
// the callback still fires.
func TestNew_RegistersBeforeReturn(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".vault-token")

	ch := make(chan struct{}, 1)
	w, err := New(tokenPath, func() { ch <- struct{}{} })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	// Write in the New→Run gap. The watch is already live (registered
	// synchronously inside New), so the kernel queues this event for
	// delivery when Run starts reading the fd.
	writeTokenAtomically(t, tokenPath, "written-before-run")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()

	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("event written in the New->Run window was not delivered")
	}
}

// TestNew_ErrorsOnMissingDir proves registration failure surfaces
// synchronously from New rather than being deferred into Run.
func TestNew_ErrorsOnMissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope", ".vault-token")
	w, err := New(missing, func() {})
	if err == nil {
		w.Close()
		t.Fatal("expected error from New on a non-existent parent directory, got nil")
	}
}

// TestRun_ReturnsOnContextCancel proves Run honours context
// cancellation and returns context.Canceled.
func TestRun_ReturnsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".vault-token")

	w, err := New(tokenPath, func() {})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- w.Run(ctx) }()

	cancel()
	select {
	case err := <-errCh:
		if err != context.Canceled {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}

// TestNew_ReconcilingReadPattern documents why the caller must issue a
// reconciling read after New: a file that already exists before the
// watch is registered generates no inotify event, so a watch-only
// strategy would never observe a token that predates startup. The
// daemon closes this gap with an explicit read right after New.
func TestNew_ReconcilingReadPattern(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".vault-token")

	// Seed the token before the watch exists.
	if err := os.WriteFile(tokenPath, []byte("pre-existing"), 0o600); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	ch := make(chan struct{}, 1)
	w, err := New(tokenPath, func() { ch <- struct{}{} })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()

	// No write happens after the watch is live, so no event must fire —
	// the pre-existing file is invisible to inotify, which is exactly
	// why the reconciling read is required.
	select {
	case <-ch:
		t.Fatal("unexpected event for a file that predates the watch")
	case <-time.After(300 * time.Millisecond):
	}
}
