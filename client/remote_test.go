package client

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// newUnixActionServer starts an httptest server bound to a Unix socket serving
// the two remote-action endpoints with the given handler. Skips where AF_UNIX
// is unavailable.
func newUnixActionServer(t *testing.T, sockPath string, handler http.HandlerFunc) {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix domain sockets unavailable on this platform: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/remote/browse", handler)
	mux.HandleFunc("POST /api/v1/remote/notify", handler)
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
}

func newBrowseClient(t *testing.T, sock string) *Client {
	t.Helper()
	c, err := New(&Config{Vault: VaultConfig{Address: "http://127.0.0.1:8200", TokenSocket: sock}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBrowse_PostsToPeer(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "peer.sock")
	var path, gotURL string
	newUnixActionServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		path, gotURL = r.URL.Path, r.PostFormValue("url")
		_, _ = w.Write([]byte(`{"status":"browser opened"}`))
	})

	if err := newBrowseClient(t, sock).Browse(context.Background(), "https://example.com/x"); err != nil {
		t.Fatalf("Browse: %v", err)
	}
	if path != "/api/v1/remote/browse" || gotURL != "https://example.com/x" {
		t.Errorf("peer got path=%q url=%q, want the browse endpoint and URL", path, gotURL)
	}
}

func TestNotify_PostsToPeer(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "peer.sock")
	var level, title, body string
	newUnixActionServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		level, title, body = r.PostFormValue("level"), r.PostFormValue("title"), r.PostFormValue("body")
		_, _ = w.Write([]byte(`{"status":"notification delivered"}`))
	})

	if err := newBrowseClient(t, sock).Notify(context.Background(), "error", "Job failed", "see logs"); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if level != "error" || title != "Job failed" || body != "see logs" {
		t.Errorf("peer got level=%q title=%q body=%q, want the posted fields", level, title, body)
	}
}

func TestBrowse_NoSocketConfigured(t *testing.T) {
	c, err := New(&Config{Vault: VaultConfig{Address: "http://127.0.0.1:8200"}}) // no TokenSocket
	if err != nil {
		t.Fatal(err)
	}
	err = c.Browse(context.Background(), "https://example.com")
	if !errors.Is(err, ErrPeerUnavailable) {
		t.Fatalf("err = %v, want ErrPeerUnavailable when no socket is configured", err)
	}
}

func TestBrowse_PeerUnreachable(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock") // never bound
	err := newBrowseClient(t, sock).Browse(context.Background(), "https://example.com")
	if !errors.Is(err, ErrPeerUnavailable) {
		t.Fatalf("err = %v, want ErrPeerUnavailable for an unreachable peer", err)
	}
}

func TestBrowse_PeerRejectsInvalid(t *testing.T) {
	// A 400 from the peer (it validated and rejected the request) is a caller
	// error, NOT ErrPeerUnavailable — the message must surface plainly.
	sock := filepath.Join(t.TempDir(), "peer.sock")
	newUnixActionServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"unsupported url scheme \"file\""}`))
	})

	err := newBrowseClient(t, sock).Browse(context.Background(), "file:///etc/passwd")
	if err == nil {
		t.Fatal("expected an error for a peer-rejected URL")
	}
	if errors.Is(err, ErrPeerUnavailable) {
		t.Errorf("a 400 must not map to ErrPeerUnavailable: %v", err)
	}
	if !strings.Contains(err.Error(), "unsupported url scheme") {
		t.Errorf("err = %q, want it to carry the peer's rejection message", err)
	}
}

func TestNotify_PeerActionFailedIsUnavailable(t *testing.T) {
	// A 502 (peer reached, delivery failed) maps to ErrPeerUnavailable.
	sock := filepath.Join(t.TempDir(), "peer.sock")
	newUnixActionServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"no notification daemon"}`))
	})

	err := newBrowseClient(t, sock).Notify(context.Background(), "info", "hi", "")
	if !errors.Is(err, ErrPeerUnavailable) {
		t.Fatalf("err = %v, want ErrPeerUnavailable for a 502 delivery failure", err)
	}
}
