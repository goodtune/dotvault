package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// newUnixBrowseServer starts an httptest server bound to a Unix socket at
// sockPath, serving POST /api/v1/remote/browse with the given handler. If the
// platform cannot bind a Unix-domain socket the test is skipped — the browse
// client's socket side targets the same Linux/macOS topology as the token
// borrow.
func newUnixBrowseServer(t *testing.T, sockPath string, handler http.HandlerFunc) {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix domain sockets unavailable on this platform: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/remote/browse", handler)
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
}

func TestPostBrowseToSocket_Success(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "dotvault.sock")
	var gotURL, gotHost string
	newUnixBrowseServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		gotURL = r.FormValue("url")
		gotHost = r.Host
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"browser opened"}`))
	})

	if err := postBrowseToSocket(context.Background(), sock, "https://example.com/x"); err != nil {
		t.Fatalf("postBrowseToSocket: %v", err)
	}
	if gotURL != "https://example.com/x" {
		t.Errorf("peer received url = %q, want %q", gotURL, "https://example.com/x")
	}
	// "localhost" is on the peer web server's DNS-rebinding Host allowlist;
	// anything else would be rejected by the middleware before the handler.
	if gotHost != "localhost" {
		t.Errorf("peer received Host = %q, want %q", gotHost, "localhost")
	}
}

func TestPostBrowseToSocket_MissingSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")
	if err := postBrowseToSocket(context.Background(), sock, "https://example.com"); err == nil {
		t.Fatal("expected an error for a missing socket so the caller falls back locally")
	}
}

func TestPostBrowseToSocket_StaleSocket(t *testing.T) {
	// A regular file with no listener stands in for a socket left behind by a
	// dead SSH session: the dial fails and the caller falls back locally.
	sock := filepath.Join(t.TempDir(), "stale.sock")
	if err := os.WriteFile(sock, []byte("not a socket"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := postBrowseToSocket(context.Background(), sock, "https://example.com"); err == nil {
		t.Fatal("expected an error for a stale socket")
	}
}

func TestPostBrowseToSocket_PeerError(t *testing.T) {
	// A non-200 from the peer (e.g. its browser launch failed) must surface
	// as an error carrying the peer's message.
	sock := filepath.Join(t.TempDir(), "dotvault.sock")
	newUnixBrowseServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"failed to open browser: no display"}`))
	})

	err := postBrowseToSocket(context.Background(), sock, "https://example.com")
	if err == nil {
		t.Fatal("expected an error for a non-200 peer response")
	}
	if got := err.Error(); got != "peer returned 502: failed to open browser: no display" {
		t.Errorf("error = %q, want the peer's message included", got)
	}
}

func TestPostBrowseToSocket_ExpandsHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)        // Linux/macOS
	t.Setenv("USERPROFILE", home) // Windows
	// Keep the socket path short: Unix socket paths have a ~104-byte limit.
	sock := filepath.Join(home, "b.sock")
	served := false
	newUnixBrowseServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		served = true
		_, _ = w.Write([]byte(`{"status":"browser opened"}`))
	})

	if err := postBrowseToSocket(context.Background(), "~/b.sock", "https://example.com"); err != nil {
		t.Fatalf("postBrowseToSocket: %v", err)
	}
	if !served {
		t.Error("peer handler was never reached through the ~-expanded path")
	}
}
