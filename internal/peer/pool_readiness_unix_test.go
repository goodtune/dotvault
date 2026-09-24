//go:build !windows

package peer

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// bindOnly creates a Unix socket at path that is bound but never listens —
// the state a forward's socket is in between sshd's bind() and listen(),
// which is exactly the moment an inotify-woken borrow can dial it. A dial
// is refused, which the pool would otherwise read as a dead peer.
func bindOnly(t *testing.T, path string) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		syscall.Close(fd)
		t.Fatalf("bind: %v", err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
}

// TestPoolReadinessGraceKeepsFreshSocket pins the fix for a socket being
// evicted before it listens: a refused dial on a socket seen within
// ReadinessGrace must not evict it, and the same failure once the grace has
// passed must.
func TestPoolReadinessGraceKeepsFreshSocket(t *testing.T) {
	dir := sockDir(t)
	sock := filepath.Join(dir, "dotvault.laptop.sock")
	bindOnly(t, sock)
	if _, err := os.Stat(sock); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	clock := func() time.Time { return now }
	p := NewPool([]string{filepath.Join(dir, "dotvault.*.sock")}, WithClock(clock))
	ctx := context.Background()

	// lastSeen is seeded from the socket's mtime, which is "just now" on
	// the fake clock too, so the first refused dial lands inside the grace.
	if tok, src := p.Borrow(ctx); tok != "" || src != "" {
		t.Fatalf("Borrow = (%q, %q), want nothing from a not-yet-listening socket", tok, src)
	}
	if memberEvicted(p, sock) {
		t.Fatal("socket evicted inside ReadinessGrace; a bind-then-listen gap would strand a healthy peer")
	}
	if got := p.Resolve(); len(got) != 1 || got[0].Path != sock {
		t.Fatalf("socket should still be active, Resolve = %+v", got)
	}

	// Past the grace the same refusal is a real verdict.
	now = now.Add(ReadinessGrace + time.Second)
	if tok, _ := p.Borrow(ctx); tok != "" {
		t.Fatalf("Borrow = %q, want nothing", tok)
	}
	if !memberEvicted(p, sock) {
		t.Fatal("socket not evicted after ReadinessGrace; a dead socket must leave rotation")
	}
}
