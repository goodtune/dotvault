package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakePeer is a workstation dotvault's API on a Unix socket: status (with a
// version), the remotes list, csrf, and a PATCH recorder.
// statusBody, when set, replaces the JSON status response verbatim — a peer
// answering with something that is not JSON at all (a proxy's error page, a
// future daemon serving HTML on that path).
type fakePeer struct {
	version    string
	statusBody string
	// hostnameLabel is what the peer reports as its own {{HOSTNAME}}
	// expansion. Defaults to "desktop"; set it to "-" to serve no label at
	// all, the shape a peer that cannot derive one produces.
	hostnameLabel string
	remotes       []map[string]any
	mu            sync.Mutex
	patches       []struct{ host, body string }
	dropOnPatch   bool

	// afterPatch runs once, in its own goroutine, after the first PATCH is
	// recorded — the hook a test uses to stand up the renamed socket the
	// migrator is about to go looking for.
	afterPatch func()
	patchOnce  sync.Once
}

// defaultHostnameLabel is the label fakePeer reports unless told otherwise.
// It is deliberately longer than one character: a single-character stand-in
// is exactly what let `dotvault.?.sock` pass the old guard.
const defaultHostnameLabel = "desktop"

func (f *fakePeer) label() string {
	switch f.hostnameLabel {
	case "":
		return defaultHostnameLabel
	case "-":
		return ""
	default:
		return f.hostnameLabel
	}
}

func (f *fakePeer) serve(t *testing.T, path string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if f.statusBody != "" {
			_, _ = w.Write([]byte(f.statusBody))
			return
		}
		body := map[string]any{"version": f.version}
		if label := f.label(); label != "" {
			body["hostname_label"] = label
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("GET /api/v1/ssh/remotes", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"remotes": f.remotes})
	})
	mux.HandleFunc("GET /api/v1/csrf", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "csrf-1"})
	})
	mux.HandleFunc("PATCH /api/v1/ssh/remotes/{host}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-CSRF-Token") != "csrf-1" {
			w.WriteHeader(403)
			return
		}
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.patches = append(f.patches, struct{ host, body string }{r.PathValue("host"), string(b)})
		f.mu.Unlock()
		if f.afterPatch != nil {
			f.patchOnce.Do(func() { go f.afterPatch() })
		}
		if f.dropOnPatch {
			if hj, ok := w.(http.Hijacker); ok {
				c, _, _ := hj.Hijack()
				c.Close()
				return
			}
		}
		_, _ = w.Write([]byte(`{"host":"x"}`))
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
}

func (f *fakePeer) patched() []struct{ host, body string } {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]struct{ host, body string }(nil), f.patches...)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not met in time")
	}
}

// globPatterns is the borrow pattern list a correctly-configured host carries:
// the old default plus the glob matching whatever the forward is renamed to.
// Without the second entry the migrator refuses — see
// TestMigrateRefusesWithoutAPatternForTheRenamedSocket.
func globPatterns(sock string) []string {
	return []string{sock, filepath.Join(filepath.Dir(sock), "dotvault.*.sock")}
}

// newTestMigrator builds a migrator whose confirmation wait is short enough
// for a test (the production 45s / 500ms are sized for a real SSH reconnect)
// and whose outcome seam is recorded.
//
// Every test that reaches the PATCH must wait on the returned recorder before
// returning. The wait values are package vars, so a confirmation goroutine
// still running after its test finished would read them while the next test's
// cleanup restored them — a real race, and one the detector catches.
func newTestMigrator(t *testing.T, oldDefault string, patterns []string) (*peerMigrator, *outcomes) {
	t.Helper()
	prevWait, prevPoll := migrateConfirmWait, migrateConfirmPoll
	migrateConfirmWait, migrateConfirmPoll = time.Second, 20*time.Millisecond
	t.Cleanup(func() { migrateConfirmWait, migrateConfirmPoll = prevWait, prevPoll })

	got := &outcomes{}
	m := newPeerMigrator(oldDefault, patterns)
	m.outcome = got.record
	return m, got
}

// outcomes records what the migrator's confirmation seam reported, so a test
// asserts on the verdict itself rather than on log output.
type outcomes struct {
	mu   sync.Mutex
	list []migrateOutcome
}

type migrateOutcome struct {
	host      string
	confirmed bool
}

func (o *outcomes) record(host string, confirmed bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.list = append(o.list, migrateOutcome{host, confirmed})
}

func (o *outcomes) snapshot() []migrateOutcome {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]migrateOutcome(nil), o.list...)
}

// renamedSocketServer stands the workstation's renamed forward up on demand:
// a status-answering socket at a path, which is exactly what the migrator's
// confirmation probe goes looking for.
type renamedSocketServer struct {
	mu  sync.Mutex
	srv *http.Server
}

func (r *renamedSocketServer) start(path string) {
	ln, err := net.Listen("unix", path)
	if err != nil {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"0.34.0"}`))
	})
	s := &http.Server{Handler: mux}
	r.mu.Lock()
	r.srv = s
	r.mu.Unlock()
	_ = s.Serve(ln)
}

func (r *renamedSocketServer) close() {
	r.mu.Lock()
	s := r.srv
	r.mu.Unlock()
	if s != nil {
		_ = s.Close()
	}
}

func selfHost(t *testing.T) string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		t.Skip("no hostname")
	}
	return h
}

func TestVersionAtLeast(t *testing.T) {
	cases := []struct {
		v, min string
		want   bool
	}{
		{"0.34.0", "0.34.0", true}, {"0.35.1", "0.34.0", true}, {"1.0.0", "0.34.0", true},
		{"0.33.9", "0.34.0", false}, {"v0.34.0", "0.34.0", true}, {"0.34.0-rc1", "0.34.0", true},
		{"", "0.34.0", true}, {"dev", "0.34.0", true}, {"garbage.x", "0.34.0", true},
	}
	for _, c := range cases {
		if got := versionAtLeast(c.v, c.min); got != c.want {
			t.Errorf("versionAtLeast(%q,%q) = %v, want %v", c.v, c.min, got, c.want)
		}
	}
}

// withLookupHost swaps the resolver seam for the duration of a test. No test
// in this package resolves a real name: the answer would depend on the host's
// search domains and every lookup — negative ones included — is a network
// round trip.
func withLookupHost(t *testing.T, fn func(context.Context, string) ([]string, error)) {
	t.Helper()
	prev := lookupHost
	lookupHost = fn
	t.Cleanup(func() { lookupHost = prev })
}

// firstLocalAddr returns one non-loopback address this machine's interfaces
// carry, or "" when it has none (a fully isolated container).
func firstLocalAddr() string {
	for a := range localAddrs() {
		return a
	}
	return ""
}

func TestHostIsSelf(t *testing.T) {
	ctx := context.Background()

	// The name branch answers before the resolver is reached, so a lookup here
	// is a bug in itself — fail loudly rather than returning something.
	withLookupHost(t, func(context.Context, string) ([]string, error) {
		t.Error("hostname equality must not reach the resolver")
		return nil, nil
	})
	if !hostIsSelf(ctx, selfHost(t)) {
		t.Error("own hostname should match")
	}
	if hostIsSelf(ctx, "localhost") || hostIsSelf(ctx, "127.0.0.1") {
		t.Error("loopback must never match")
	}

	withLookupHost(t, func(_ context.Context, host string) ([]string, error) {
		return nil, fmt.Errorf("no such host: %s", host)
	})
	if hostIsSelf(ctx, "definitely-not-this-host.invalid") {
		t.Error("unknown host must not match")
	}

	if local := firstLocalAddr(); local == "" {
		t.Log("no non-loopback interface address; skipping the address-match case")
	} else {
		withLookupHost(t, func(context.Context, string) ([]string, error) {
			return []string{local}, nil
		})
		if !hostIsSelf(ctx, "some-alias.example") {
			t.Errorf("a host resolving to this machine's %s should match", local)
		}
	}

	// Loopback is rejected in the address branch too, not just as a literal:
	// every machine resolves it to itself, so admitting it would make every
	// borrower claim every loopback entry.
	withLookupHost(t, func(context.Context, string) ([]string, error) {
		return []string{"127.0.0.1"}, nil
	})
	if hostIsSelf(ctx, "loopback-alias.example") {
		t.Error("a host resolving only to loopback must not match")
	}
}

func TestMigratePatchesOwnOldDefaultEntry(t *testing.T) {
	sock := filepath.Join(sockDir(t), "dotvault.sock")
	srv := &fakePeer{version: "0.34.0", remotes: []map[string]any{
		{"host": selfHost(t), "remote_socket": "~/.ssh/dotvault.sock", "port": 22, "enabled": true},
		{"host": "other.example", "remote_socket": "~/.ssh/dotvault.sock", "port": 22, "enabled": true},
		{"host": selfHost(t) + "-alias", "remote_socket": "/abs/dotvault.sock", "port": 22, "enabled": true},
	}}
	srv.serve(t, sock)

	m, outcome := newTestMigrator(t, sock, globPatterns(sock))
	m.maybeMigrate(context.Background(), sock)
	waitFor(t, func() bool { return len(srv.patched()) == 1 })
	got := srv.patched()[0]
	if got.host != selfHost(t) {
		t.Errorf("patched host = %q", got.host)
	}
	// The delay is what lets this response get home before the forward is
	// rebound, so it is part of the request's contract, not a detail.
	if got.body != `{"reconcile_delay":"10s","remote_socket":"~/.ssh/dotvault.{{HOSTNAME}}.sock"}` {
		t.Errorf("body = %s", got.body)
	}
	// Once per socket identity per process.
	m.maybeMigrate(context.Background(), sock)
	time.Sleep(100 * time.Millisecond)
	if len(srv.patched()) != 1 {
		t.Errorf("migrated twice: %v", srv.patched())
	}

	// Nothing ever binds the renamed socket in this fixture, so the wait runs
	// out. Waiting on it before returning is what keeps the confirmation
	// goroutine from outliving the test.
	waitFor(t, func() bool { return len(outcome.snapshot()) == 1 })
}

func TestMigrateSkipsOldPeerVersion(t *testing.T) {
	sock := filepath.Join(sockDir(t), "dotvault.sock")
	srv := &fakePeer{version: "0.33.0", remotes: []map[string]any{
		{"host": selfHost(t), "remote_socket": "~/.ssh/dotvault.sock"},
	}}
	srv.serve(t, sock)
	m := newPeerMigrator(sock, globPatterns(sock))
	m.maybeMigrate(context.Background(), sock)
	time.Sleep(200 * time.Millisecond)
	if len(srv.patched()) != 0 {
		t.Errorf("old peer must not be patched: %v", srv.patched())
	}
}

// A peer whose status is not JSON at all — a proxy error page, an HTML
// response — must not be patched, and must not be retried either: the identity
// is claimed before the attempt, so a peer that cannot be understood is left
// alone until its socket is re-created. Without that, an unparseable peer would
// be re-attempted on every borrow.
func TestMigrateSkipsPeerWithUnparseableStatus(t *testing.T) {
	sock := filepath.Join(sockDir(t), "dotvault.sock")
	srv := &fakePeer{statusBody: "<html>not a dotvault</html>", remotes: []map[string]any{
		{"host": selfHost(t), "remote_socket": "~/.ssh/dotvault.sock"},
	}}
	srv.serve(t, sock)

	m := newPeerMigrator(sock, globPatterns(sock))
	m.maybeMigrate(context.Background(), sock)
	time.Sleep(200 * time.Millisecond)
	if len(srv.patched()) != 0 {
		t.Errorf("patched a peer whose status could not be parsed: %v", srv.patched())
	}

	m.maybeMigrate(context.Background(), sock)
	time.Sleep(200 * time.Millisecond)
	if len(srv.patched()) != 0 {
		t.Errorf("patched on a second attempt: %v", srv.patched())
	}

	// Directly: the identity is claimed, so the second maybeMigrate above did
	// no work at all rather than repeating the failed exchange.
	id, ok := socketIdentity(sock)
	if !ok {
		t.Skip("socket identity unavailable on this platform")
	}
	if m.claim(id) {
		t.Error("the socket identity was not claimed, so every borrow would retry")
	}
}

func TestMigrateIgnoresOtherSockets(t *testing.T) {
	dir := sockDir(t)
	old := filepath.Join(dir, "dotvault.sock")
	other := filepath.Join(dir, "dotvault.laptop.sock")
	srv := &fakePeer{version: "0.34.0", remotes: []map[string]any{
		{"host": selfHost(t), "remote_socket": "~/.ssh/dotvault.sock"},
	}}
	srv.serve(t, other)
	m := newPeerMigrator(old, globPatterns(old))
	m.maybeMigrate(context.Background(), other)
	time.Sleep(200 * time.Millisecond)
	if len(srv.patched()) != 0 {
		t.Errorf("only the old default socket triggers migration: %v", srv.patched())
	}
}

// A lost PATCH response is no longer ambiguous: the renamed socket answering
// is the evidence the migration took, whether or not the reply got home.
func TestMigrateConfirmsAfterDroppedResponse(t *testing.T) {
	dir := sockDir(t)
	sock := filepath.Join(dir, "dotvault.sock")
	expected := filepath.Join(dir, "dotvault."+defaultHostnameLabel+".sock")

	later := &renamedSocketServer{}
	t.Cleanup(later.close)
	srv := &fakePeer{version: "dev", dropOnPatch: true, remotes: []map[string]any{
		{"host": selfHost(t), "remote_socket": "~/.ssh/dotvault.sock"},
	}, afterPatch: func() {
		time.Sleep(100 * time.Millisecond)
		later.start(expected)
	}}
	srv.serve(t, sock)

	m, got := newTestMigrator(t, sock, globPatterns(sock))
	m.maybeMigrate(context.Background(), sock)

	waitFor(t, func() bool { return len(got.snapshot()) == 1 })
	if o := got.snapshot()[0]; !o.confirmed {
		t.Errorf("outcome = %+v, want the renamed socket confirmed despite the dropped response", o)
	}

	// A second nudge for the same identity must not retry.
	m.maybeMigrate(context.Background(), sock)
	time.Sleep(100 * time.Millisecond)
	if len(srv.patched()) != 1 {
		t.Errorf("retried after a dropped response: %v", srv.patched())
	}
}

// The happy path end to end: the peer answers the PATCH, its forward rebinds
// a moment later, and the migrator proves it can still borrow through the new
// path before calling the migration done.
func TestMigrateConfirmsRenamedSocket(t *testing.T) {
	dir := sockDir(t)
	sock := filepath.Join(dir, "dotvault.sock")
	expected := filepath.Join(dir, "dotvault."+defaultHostnameLabel+".sock")

	later := &renamedSocketServer{}
	t.Cleanup(later.close)
	srv := &fakePeer{version: "0.34.0", remotes: []map[string]any{
		{"host": selfHost(t), "remote_socket": "~/.ssh/dotvault.sock"},
	}, afterPatch: func() {
		time.Sleep(100 * time.Millisecond)
		later.start(expected)
	}}
	srv.serve(t, sock)

	m, got := newTestMigrator(t, sock, globPatterns(sock))
	m.maybeMigrate(context.Background(), sock)

	waitFor(t, func() bool { return len(got.snapshot()) == 1 })
	o := got.snapshot()[0]
	if !o.confirmed {
		t.Errorf("outcome = %+v, want confirmed", o)
	}
	if o.host != selfHost(t) {
		t.Errorf("outcome host = %q, want %q", o.host, selfHost(t))
	}
}

// When the renamed socket never appears the migration is reported uncertain,
// not successful and not failed: the workstation may well have applied it, and
// the next reconnect re-checks its configuration either way.
func TestMigrateReportsUncertainWhenSocketNeverAppears(t *testing.T) {
	sock := filepath.Join(sockDir(t), "dotvault.sock")
	srv := &fakePeer{version: "0.34.0", remotes: []map[string]any{
		{"host": selfHost(t), "remote_socket": "~/.ssh/dotvault.sock"},
	}}
	srv.serve(t, sock)

	m, got := newTestMigrator(t, sock, globPatterns(sock))
	m.maybeMigrate(context.Background(), sock)

	waitFor(t, func() bool { return len(got.snapshot()) == 1 })
	if o := got.snapshot()[0]; o.confirmed {
		t.Errorf("outcome = %+v, want uncertain: nothing ever bound the renamed socket", o)
	}
}

// The guard is against the exact path the peer's own hostname label produces.
// A pattern that matches some other shape — `dotvault.?.sock` matches a
// one-character label and nothing longer — must refuse, and a peer that
// reports no label at all must refuse too: there is then no way to know the
// rename is survivable.
func TestMigrateGuardUsesThePeersRealLabel(t *testing.T) {
	cases := []struct {
		name      string
		label     string
		patterns  func(dir string) []string
		wantPatch bool
	}{
		{
			name:      "single-character glob misses a real label",
			patterns:  func(dir string) []string { return []string{filepath.Join(dir, "dotvault.?.sock")} },
			wantPatch: false,
		},
		{
			name:      "wildcard glob covers it",
			patterns:  func(dir string) []string { return []string{filepath.Join(dir, "dotvault.*.sock")} },
			wantPatch: true,
		},
		{
			name:      "peer reports no label",
			label:     "-",
			patterns:  func(dir string) []string { return []string{filepath.Join(dir, "dotvault.*.sock")} },
			wantPatch: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := sockDir(t)
			sock := filepath.Join(dir, "dotvault.sock")
			srv := &fakePeer{version: "0.34.0", hostnameLabel: c.label, remotes: []map[string]any{
				{"host": selfHost(t), "remote_socket": "~/.ssh/dotvault.sock"},
			}}
			srv.serve(t, sock)

			m, outcome := newTestMigrator(t, sock, c.patterns(dir))
			m.maybeMigrate(context.Background(), sock)
			if c.wantPatch {
				waitFor(t, func() bool { return len(srv.patched()) == 1 })
				// Nothing binds the renamed socket here, so the wait runs
				// out; waiting for it keeps the goroutine inside the test.
				waitFor(t, func() bool { return len(outcome.snapshot()) == 1 })
				return
			}
			time.Sleep(200 * time.Millisecond)
			if len(srv.patched()) != 0 {
				t.Errorf("patched despite the guard: %v", srv.patched())
			}
		})
	}
}

// A host whose only borrow pattern is the old default literal would be left
// with no token source the moment the workstation renamed its forward — and no
// borrow left through which to notice. It must refuse.
func TestMigrateRefusesWithoutAPatternForTheRenamedSocket(t *testing.T) {
	sock := filepath.Join(sockDir(t), "dotvault.sock")
	srv := &fakePeer{version: "0.34.0", remotes: []map[string]any{
		{"host": selfHost(t), "remote_socket": "~/.ssh/dotvault.sock"},
	}}
	srv.serve(t, sock)

	m, _ := newTestMigrator(t, sock, []string{sock})
	m.maybeMigrate(context.Background(), sock)
	time.Sleep(200 * time.Millisecond)
	if len(srv.patched()) != 0 {
		t.Errorf("migrated despite having no pattern for the renamed socket: %v", srv.patched())
	}

	// The same peer with a glob in the list does migrate, so the refusal above
	// is the pattern check and not something else about this fixture.
	m2, outcome := newTestMigrator(t, sock, globPatterns(sock))
	m2.maybeMigrate(context.Background(), sock)
	waitFor(t, func() bool { return len(srv.patched()) == 1 })
	waitFor(t, func() bool { return len(outcome.snapshot()) == 1 })
}

// canFindRenamedSocket is the whole guard, so pin its cases directly. Every
// case is checked against the peer's real label: the single-character
// stand-in an earlier version probed made `dotvault.?.sock` and
// `dotvault.[a-z].sock` look safe when they match no real hostname.
func TestCanFindRenamedSocket(t *testing.T) {
	const old = "/home/u/.ssh/dotvault.sock"
	const label = "desktop"
	cases := []struct {
		name     string
		label    string
		patterns []string
		want     bool
	}{
		{"old default only", label, []string{old}, false},
		{"no patterns", label, nil, false},
		{"shipped default pair", label, []string{old, "/home/u/.ssh/dotvault.*.sock"}, true},
		{"glob only", label, []string{"/home/u/.ssh/dotvault.*.sock"}, true},
		{"literal per-host socket", label, []string{"/home/u/.ssh/dotvault." + label + ".sock"}, true},
		{"glob in another directory", label, []string{"/run/dotvault/dotvault.*.sock"}, false},
		// The reviewer's case: matches a one-character stand-in, matches no
		// real hostname label.
		{"single-character glob", label, []string{"/home/u/.ssh/dotvault.?.sock"}, false},
		{"single-character class", label, []string{"/home/u/.ssh/dotvault.[a-z].sock"}, false},
		// The stand-in itself is no longer privileged: a pattern is judged
		// against whatever the peer actually calls itself.
		{"stand-in label is not special", "x", []string{"/home/u/.ssh/dotvault.?.sock"}, true},
		{"no label at all", "", []string{"/home/u/.ssh/dotvault.*.sock"}, false},
	}
	for _, c := range cases {
		if got := newPeerMigrator(old, c.patterns).canFindRenamedSocket(c.label); got != c.want {
			t.Errorf("%s: canFindRenamedSocket(%q) = %v, want %v", c.name, c.label, got, c.want)
		}
	}
}

// The once-per-identity bookkeeping is bounded, so a daemon whose forward
// reconnects for months does not accumulate identities for the life of the
// process — and the identity it is currently using is never the one evicted.
func TestMigratorClaimIsBounded(t *testing.T) {
	m := newPeerMigrator("/nonexistent/dotvault.sock", nil)
	const n = maxMigratedIdentities * 3
	for i := 0; i < n; i++ {
		if !m.claim(peerIdentity{dev: 1, ino: uint64(i)}) {
			t.Fatalf("claim(%d) returned false for an unseen identity", i)
		}
	}
	if len(m.done) != maxMigratedIdentities || len(m.order) != maxMigratedIdentities {
		t.Errorf("done=%d order=%d, want %d each", len(m.done), len(m.order), maxMigratedIdentities)
	}
	// The most recent claim is still remembered (no repeat migration), while
	// the oldest has aged out and would be attempted again.
	if m.claim(peerIdentity{dev: 1, ino: n - 1}) {
		t.Error("the most recent identity was forgotten")
	}
	if !m.claim(peerIdentity{dev: 1, ino: 0}) {
		t.Error("the oldest identity should have aged out")
	}
}
