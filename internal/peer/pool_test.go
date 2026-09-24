package peer

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// sockDir returns a temporary directory with a short path. t.TempDir() names
// the directory after the test, and on macOS that plus the socket name exceeds
// the 103-byte sun_path limit, so the bind would fail before the behaviour
// under test ever ran.
func sockDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "dv")
	if err != nil {
		// Windows has no /tmp; the short path only matters where a socket is
		// bound, so fall back rather than failing a test that may not bind one.
		return t.TempDir()
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// tokenServer serves GET /api/v1/token returning token (401 when empty) and
// POST /api/v1/remote/* answering postStatus, on a Unix socket at path.
func tokenServer(t *testing.T, path, token string, postStatus int) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/token", func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"token":"` + token + `"}`))
	})
	mux.HandleFunc("POST /api/v1/remote/", func(w http.ResponseWriter, r *http.Request) {
		if postStatus == 400 {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"bad input"}`))
			return
		}
		w.WriteHeader(postStatus)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// hangingServer accepts connections and never answers — the shape of an SSH
// forward whose far end has gone away while sshd still holds the socket.
func hangingServer(t *testing.T, path string) net.Listener {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { <-time.After(time.Hour); c.Close() }()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

func setMtime(t *testing.T, path string, at time.Time) {
	t.Helper()
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

func TestPoolResolveOrdersByLastSeen(t *testing.T) {
	dir := sockDir(t)
	old := filepath.Join(dir, "dotvault.desktop.sock")
	fresh := filepath.Join(dir, "dotvault.laptop.sock")
	tokenServer(t, old, "hvs.desktop", 200)
	tokenServer(t, fresh, "hvs.laptop", 200)
	now := time.Now()
	setMtime(t, old, now.Add(-time.Hour))
	setMtime(t, fresh, now)

	p := NewPool([]string{filepath.Join(dir, "dotvault.*.sock")})
	got := p.Resolve()
	if len(got) != 2 || got[0].Path != fresh || got[1].Path != old {
		t.Fatalf("order = %+v, want laptop first", got)
	}
	tok, src := p.Borrow(context.Background())
	if tok != "hvs.laptop" || src != fresh {
		t.Errorf("Borrow = (%q, %q), want laptop", tok, src)
	}
}

func TestPoolLiteralBeforeGlobOnTie(t *testing.T) {
	dir := sockDir(t)
	// The names are chosen so the path tiebreak points the *other* way: the
	// glob's match sorts first alphabetically, so only the pattern-index rule
	// can put the literal ahead of it.
	lit := filepath.Join(dir, "dotvault.z.sock")
	glob := filepath.Join(dir, "dotvault.a.sock")
	tokenServer(t, lit, "a", 200)
	tokenServer(t, glob, "b", 200)
	at := time.Now()
	setMtime(t, lit, at)
	setMtime(t, glob, at)
	p := NewPool([]string{lit, filepath.Join(dir, "dotvault.*.sock")})
	got := p.Resolve()
	if len(got) != 2 || got[0].Path != lit {
		t.Fatalf("order = %+v, want literal first on tie", got)
	}
}

func TestPoolBorrowSkipsUnauthenticatedPeerWithoutEvicting(t *testing.T) {
	dir := sockDir(t)
	noTok := filepath.Join(dir, "dotvault.a.sock")
	hasTok := filepath.Join(dir, "dotvault.b.sock")
	tokenServer(t, noTok, "", 200)
	tokenServer(t, hasTok, "hvs.b", 200)
	setMtime(t, noTok, time.Now())
	setMtime(t, hasTok, time.Now().Add(-time.Minute))

	p := NewPool([]string{filepath.Join(dir, "dotvault.*.sock")})
	tok, src := p.Borrow(context.Background())
	if tok != "hvs.b" || src != hasTok {
		t.Fatalf("Borrow = (%q, %q)", tok, src)
	}
	for _, m := range p.Status().Members {
		if m.Evicted {
			t.Errorf("%s evicted after a 401; a live peer with no token must stay", m.Path)
		}
	}
}

// The whole pool answering 401 is the ordinary cold-start shape — every peer
// serving but none authenticated yet — so it must report "no token" and leave
// the pool intact. Evicting there would take the peers dark for a whole
// EvictProbeInterval precisely when they are about to acquire a token.
func TestPoolBorrowAllPeersUnauthenticated(t *testing.T) {
	dir := sockDir(t)
	a := filepath.Join(dir, "dotvault.a.sock")
	b := filepath.Join(dir, "dotvault.b.sock")
	tokenServer(t, a, "", 200)
	tokenServer(t, b, "", 200)

	p := NewPool([]string{filepath.Join(dir, "dotvault.*.sock")})
	tok, src := p.Borrow(context.Background())
	if tok != "" || src != "" {
		t.Errorf("Borrow = (%q, %q), want empty when no peer holds a token", tok, src)
	}
	members := p.Status().Members
	if len(members) != 2 {
		t.Fatalf("Status members = %+v, want both sockets", members)
	}
	for _, m := range members {
		if m.Evicted {
			t.Errorf("%s evicted after a 401; a live peer with no token must stay", m.Path)
		}
	}
}

func TestPoolEvictsOnTransportFailureAndReadmitsOnRecreate(t *testing.T) {
	dir := sockDir(t)
	hung := filepath.Join(dir, "dotvault.laptop.sock")
	good := filepath.Join(dir, "dotvault.desktop.sock")
	hangingServer(t, hung)
	tokenServer(t, good, "hvs.desktop", 200)
	setMtime(t, hung, time.Now())
	setMtime(t, good, time.Now().Add(-time.Minute))

	p := NewPool([]string{filepath.Join(dir, "dotvault.*.sock")}, withFetchTimeout(300*time.Millisecond))
	ctx := context.Background()
	if tok, _ := p.Borrow(ctx); tok != "hvs.desktop" {
		t.Fatalf("first borrow = %q", tok)
	}
	if !memberEvicted(p, hung) {
		t.Fatal("hung socket should be evicted after a timeout")
	}
	// Evicted members are not dialled: the borrow is now fast.
	start := time.Now()
	if tok, _ := p.Borrow(ctx); tok != "hvs.desktop" {
		t.Fatalf("second borrow = %q", tok)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Errorf("second borrow dialled the evicted socket (took %v)", time.Since(start))
	}

	// Recreate the socket (new inode) with a healthy server: readmitted.
	if err := os.Remove(hung); err != nil {
		t.Fatal(err)
	}
	tokenServer(t, hung, "hvs.laptop", 200)
	setMtime(t, hung, time.Now())
	if tok, src := p.Borrow(ctx); tok != "hvs.laptop" || src != hung {
		t.Fatalf("after recreate Borrow = (%q, %q), want laptop", tok, src)
	}
}

// TestPoolEvictIgnoresStaleIdentity covers the window where a fetch hangs for
// its whole timeout while the forward underneath it reconnects: the failure
// that finally surfaces names a socket that no longer exists, and must not
// evict the healthy replacement that took its name.
func TestPoolEvictIgnoresStaleIdentity(t *testing.T) {
	dir := sockDir(t)
	sock := filepath.Join(dir, "dotvault.sock")
	tokenServer(t, sock, "hvs.a", 200)
	p := NewPool([]string{sock})
	ctx := context.Background()

	// Snapshot exactly as Borrow does: the identity it is about to dial.
	p.mu.Lock()
	p.resolveLocked(ctx)
	act := p.activeLocked()
	p.mu.Unlock()
	if len(act) != 1 {
		t.Fatalf("active = %+v, want one member", act)
	}
	stale := act[0].id
	if stale == (identity{}) {
		t.Skip("no filesystem identity on this platform; eviction cannot be identity-guarded")
	}

	// The forward reconnects mid-dial: same name, new inode.
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	tokenServer(t, sock, "hvs.b", 200)
	if got := p.Resolve(); len(got) != 1 {
		t.Fatalf("after recreate, active = %+v, want the replacement", got)
	}

	p.evict(ctx, sock, stale, errors.New("i/o timeout"))
	if memberEvicted(p, sock) {
		t.Error("a stale in-flight failure evicted the recreated socket")
	}

	// A failure carrying the current identity still evicts, so the guard has
	// not simply disabled eviction.
	p.mu.Lock()
	current := p.members[sock].id
	p.mu.Unlock()
	p.evict(ctx, sock, current, errors.New("i/o timeout"))
	if !memberEvicted(p, sock) {
		t.Error("a failure naming the current socket must still evict")
	}
}

func TestPoolReadmitsAfterProbeWindow(t *testing.T) {
	dir := sockDir(t)
	sock := filepath.Join(dir, "dotvault.sock")
	hangingServer(t, sock)
	now := time.Now()
	clock := func() time.Time { return now }
	p := NewPool([]string{sock}, WithClock(clock), withFetchTimeout(300*time.Millisecond))
	p.Borrow(context.Background())
	if !memberEvicted(p, sock) {
		t.Fatal("expected eviction")
	}
	now = now.Add(EvictProbeInterval + time.Second)
	if got := p.Resolve(); len(got) != 1 {
		t.Fatalf("after probe window, active = %+v, want the socket back", got)
	}
}

func TestPoolBroadcastAnySuccess(t *testing.T) {
	dir := sockDir(t)
	ok := filepath.Join(dir, "dotvault.a.sock")
	bad := filepath.Join(dir, "dotvault.b.sock")
	tokenServer(t, ok, "", 200)
	tokenServer(t, bad, "", 503)
	p := NewPool([]string{filepath.Join(dir, "dotvault.*.sock")})
	if err := p.Broadcast(context.Background(), "/api/v1/remote/notify", url.Values{"title": {"x"}}); err != nil {
		t.Fatalf("Broadcast = %v, want nil when one peer accepted", err)
	}
}

func TestPoolBroadcast4xxWins(t *testing.T) {
	dir := sockDir(t)
	ok := filepath.Join(dir, "dotvault.a.sock")
	bad := filepath.Join(dir, "dotvault.b.sock")
	tokenServer(t, ok, "", 200)
	tokenServer(t, bad, "", 400)
	p := NewPool([]string{filepath.Join(dir, "dotvault.*.sock")})
	err := p.Broadcast(context.Background(), "/api/v1/remote/notify", url.Values{"title": {"x"}})
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 400 {
		t.Fatalf("Broadcast = %v, want *StatusError 400", err)
	}
}

func TestPoolBroadcastNoPeers(t *testing.T) {
	p := NewPool([]string{filepath.Join(sockDir(t), "dotvault.*.sock")})
	err := p.Broadcast(context.Background(), "/api/v1/remote/notify", nil)
	if !errors.Is(err, ErrNoPeers) || !errors.Is(err, ErrPeerUnreachable) {
		t.Fatalf("Broadcast = %v, want ErrNoPeers wrapping ErrPeerUnreachable", err)
	}
}

func TestPoolBroadcastAllFailedWrapsUnreachable(t *testing.T) {
	dir := sockDir(t)
	sock := filepath.Join(dir, "dotvault.sock")
	hangingServer(t, sock)
	p := NewPool([]string{sock}, withPostTimeout(300*time.Millisecond))
	err := p.Broadcast(context.Background(), "/api/v1/remote/notify", nil)
	if !errors.Is(err, ErrPeerUnreachable) || errors.Is(err, ErrNoPeers) {
		t.Fatalf("Broadcast = %v, want ErrPeerUnreachable (not ErrNoPeers)", err)
	}
	if !memberEvicted(p, sock) {
		t.Error("hung socket should be evicted by Broadcast too")
	}
}

func TestPoolNilReceiver(t *testing.T) {
	var p *Pool
	if tok, src := p.Borrow(context.Background()); tok != "" || src != "" {
		t.Error("nil pool must borrow nothing")
	}
	if err := p.Broadcast(context.Background(), "/x", nil); !errors.Is(err, ErrNoPeers) {
		t.Errorf("nil pool Broadcast = %v, want ErrNoPeers", err)
	}
	if err := p.Watch(context.Background()); err != nil {
		t.Errorf("nil pool Watch = %v", err)
	}
	if s := p.Status(); len(s.Members) != 0 {
		t.Error("nil pool Status must be empty")
	}
}

// watchSupported reports whether Watch actually registers a watcher here.
// Off Linux tokenwatch is inert and the pool relies on re-resolve instead, so
// the event this test waits for is never produced. Test-only: production code
// needs no such branch, because Watch degrades on its own.
func watchSupported() bool { return runtime.GOOS == "linux" }

func TestPoolWatchOnChangeFires(t *testing.T) {
	if !watchSupported() {
		t.Skip("no inotify on this platform")
	}
	dir := sockDir(t)
	var fired atomic.Int32
	// withWatchReady rather than a sleep: the socket must not be created until
	// every watcher is registered, and a guessed interval is both slower than
	// necessary and not a guarantee on a loaded machine.
	ready := make(chan struct{})
	p := NewPool([]string{filepath.Join(dir, "dotvault.*.sock")},
		WithOnChange(func() { fired.Add(1) }), withWatchReady(ready))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Watch(ctx) }()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not report its watchers registered")
	}
	tokenServer(t, filepath.Join(dir, "dotvault.laptop.sock"), "t", 200)
	deadline := time.Now().Add(2 * time.Second)
	for fired.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if fired.Load() == 0 {
		t.Fatal("OnChange did not fire on socket creation")
	}
	m := p.Status().Members
	if len(m) != 1 || m[0].LastSeen.Before(time.Now().Add(-time.Second)) {
		t.Errorf("member not admitted with a fresh LastSeen: %+v", m)
	}
}

// TestStatusEvictedAtSetOnlyWhenEvicted pins the pointer invariant: a zero
// time.Time is a struct, so `omitempty` never elided it and an active member
// reported a meaningless "evicted_at":"0001-01-01T00:00:00Z" on
// GET /api/v1/status. EvictedAt must be non-nil if and only if Evicted.
func TestStatusEvictedAtSetOnlyWhenEvicted(t *testing.T) {
	dir := sockDir(t)
	sock := filepath.Join(dir, "dotvault.a.sock")
	hangingServer(t, sock)

	now := time.Now()
	p := NewPool([]string{filepath.Join(dir, "dotvault.*.sock")},
		WithClock(func() time.Time { return now }), withFetchTimeout(200*time.Millisecond))

	for _, m := range p.Status().Members {
		if m.Evicted {
			t.Fatalf("%s: evicted before any failure", m.Path)
		}
		if m.EvictedAt != nil {
			t.Errorf("%s: active member carries EvictedAt = %v, want nil", m.Path, *m.EvictedAt)
		}
	}

	// The dial times out against a socket nothing answers on, which evicts it.
	p.Borrow(context.Background())

	var found bool
	for _, m := range p.Status().Members {
		if m.Path != sock {
			continue
		}
		found = true
		if !m.Evicted {
			t.Fatalf("%s: not evicted after a failed dial", m.Path)
		}
		if m.EvictedAt == nil {
			t.Fatal("evicted member carries no EvictedAt")
		}
		if !m.EvictedAt.Equal(now) {
			t.Errorf("EvictedAt = %v, want the eviction clock %v", *m.EvictedAt, now)
		}
	}
	if !found {
		t.Fatalf("%s not present in Status()", sock)
	}
}

func memberEvicted(p *Pool, path string) bool {
	for _, m := range p.Status().Members {
		if m.Path == path {
			return m.Evicted
		}
	}
	return false
}
