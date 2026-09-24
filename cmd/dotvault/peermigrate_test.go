package main

import (
	"context"
	"encoding/json"
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
type fakePeer struct {
	version     string
	remotes     []map[string]any
	mu          sync.Mutex
	patches     []struct{ host, body string }
	dropOnPatch bool
}

func (f *fakePeer) serve(t *testing.T, path string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"version": f.version})
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

func TestHostIsSelf(t *testing.T) {
	ctx := context.Background()
	if !hostIsSelf(ctx, selfHost(t)) {
		t.Error("own hostname should match")
	}
	if hostIsSelf(ctx, "localhost") || hostIsSelf(ctx, "127.0.0.1") {
		t.Error("loopback must never match")
	}
	if hostIsSelf(ctx, "definitely-not-this-host.invalid") {
		t.Error("unknown host must not match")
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

	m := newPeerMigrator(sock)
	m.maybeMigrate(context.Background(), sock)
	waitFor(t, func() bool { return len(srv.patched()) == 1 })
	got := srv.patched()[0]
	if got.host != selfHost(t) {
		t.Errorf("patched host = %q", got.host)
	}
	if got.body != `{"remote_socket":"~/.ssh/dotvault.{{HOSTNAME}}.sock"}` {
		t.Errorf("body = %s", got.body)
	}
	// Once per socket identity per process.
	m.maybeMigrate(context.Background(), sock)
	time.Sleep(100 * time.Millisecond)
	if len(srv.patched()) != 1 {
		t.Errorf("migrated twice: %v", srv.patched())
	}
}

func TestMigrateSkipsOldPeerVersion(t *testing.T) {
	sock := filepath.Join(sockDir(t), "dotvault.sock")
	srv := &fakePeer{version: "0.33.0", remotes: []map[string]any{
		{"host": selfHost(t), "remote_socket": "~/.ssh/dotvault.sock"},
	}}
	srv.serve(t, sock)
	m := newPeerMigrator(sock)
	m.maybeMigrate(context.Background(), sock)
	time.Sleep(200 * time.Millisecond)
	if len(srv.patched()) != 0 {
		t.Errorf("old peer must not be patched: %v", srv.patched())
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
	m := newPeerMigrator(old)
	m.maybeMigrate(context.Background(), other)
	time.Sleep(200 * time.Millisecond)
	if len(srv.patched()) != 0 {
		t.Errorf("only the old default socket triggers migration: %v", srv.patched())
	}
}

func TestMigrateTreatsDroppedResponseAsApplied(t *testing.T) {
	sock := filepath.Join(sockDir(t), "dotvault.sock")
	srv := &fakePeer{version: "dev", dropOnPatch: true, remotes: []map[string]any{
		{"host": selfHost(t), "remote_socket": "~/.ssh/dotvault.sock"},
	}}
	srv.serve(t, sock)
	m := newPeerMigrator(sock)
	m.maybeMigrate(context.Background(), sock)
	waitFor(t, func() bool { return len(srv.patched()) == 1 })
	// A second nudge for the same identity must not retry: the drop is the
	// expected shape of success.
	m.maybeMigrate(context.Background(), sock)
	time.Sleep(100 * time.Millisecond)
	if len(srv.patched()) != 1 {
		t.Errorf("retried after a dropped response: %v", srv.patched())
	}
}
