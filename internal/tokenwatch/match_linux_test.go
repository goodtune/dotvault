//go:build linux

package tokenwatch

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewMatchReportsMatchingNames(t *testing.T) {
	dir := t.TempDir()
	seen := make(chan string, 8)
	w, err := NewMatch(dir, func(name string) bool {
		return strings.HasPrefix(name, "dotvault.") && strings.HasSuffix(name, ".sock")
	}, func(name string) { seen <- name })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { defer w.Close(); _ = w.Run(ctx) }()

	// A non-matching entry must be ignored.
	if err := os.WriteFile(filepath.Join(dir, "other.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A matching socket creation must be reported by name.
	ln, err := net.Listen("unix", filepath.Join(dir, "dotvault.laptop.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	select {
	case got := <-seen:
		if got != "dotvault.laptop.sock" {
			t.Fatalf("got %q, want dotvault.laptop.sock", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event for matching socket")
	}
	select {
	case got := <-seen:
		t.Fatalf("unexpected extra event %q", got)
	case <-time.After(200 * time.Millisecond):
	}
}
