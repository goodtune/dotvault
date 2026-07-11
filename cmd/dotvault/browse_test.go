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

// writeBrowseConfig writes a minimal valid config naming socketPath as the
// peer socket and returns its path.
func writeBrowseConfig(t *testing.T, socketPath string) string {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := `vault:
  address: http://127.0.0.1:8200
  token_socket: ` + socketPath + `
rules:
  - name: dummy
    vault_key: dummy
    target:
      path: ~/dummy.txt
      format: text
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

// runBrowseWith drives runBrowse with a fake local opener and the given
// --config override, returning the command error and the URL (if any) the
// local opener received.
func runBrowseWith(t *testing.T, cfgPath, target string) (error, string) {
	t.Helper()
	prevCfg := flagConfig
	flagConfig = cfgPath
	prevOpen := openLocalBrowser
	var openedLocally string
	openLocalBrowser = func(u string) error {
		openedLocally = u
		return nil
	}
	t.Cleanup(func() {
		flagConfig = prevCfg
		openLocalBrowser = prevOpen
	})

	cmd := newBrowseCmd()
	cmd.SetContext(context.Background())
	err := runBrowse(cmd, []string{target})
	return err, openedLocally
}

func TestRunBrowse_PrefersPeerSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "p.sock")
	var peerGot string
	newUnixBrowseServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		peerGot = r.FormValue("url")
		_, _ = w.Write([]byte(`{"status":"browser opened"}`))
	})

	err, openedLocally := runBrowseWith(t, writeBrowseConfig(t, sock), "https://example.com/a")
	if err != nil {
		t.Fatalf("runBrowse: %v", err)
	}
	if peerGot != "https://example.com/a" {
		t.Errorf("peer received %q, want the URL", peerGot)
	}
	if openedLocally != "" {
		t.Errorf("local opener was called (%q) despite a healthy peer", openedLocally)
	}
}

func TestRunBrowse_FallsBackWhenPeerUnreachable(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")

	err, openedLocally := runBrowseWith(t, writeBrowseConfig(t, sock), "https://example.com/b")
	if err != nil {
		t.Fatalf("runBrowse: %v", err)
	}
	if openedLocally != "https://example.com/b" {
		t.Errorf("local opener got %q, want the URL after peer fallback", openedLocally)
	}
}

func TestRunBrowse_FallsBackWhenConfigUnloadable(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "missing.yaml")

	err, openedLocally := runBrowseWith(t, cfgPath, "https://example.com/c")
	if err != nil {
		t.Fatalf("runBrowse: %v", err)
	}
	if openedLocally != "https://example.com/c" {
		t.Errorf("local opener got %q, want the URL when config load fails", openedLocally)
	}
}

func TestRunBrowse_RejectsInvalidURLBeforeAnything(t *testing.T) {
	err, openedLocally := runBrowseWith(t, "", "file:///etc/passwd")
	if err == nil {
		t.Fatal("expected an error for a non-http(s) URL")
	}
	if openedLocally != "" {
		t.Errorf("local opener was called (%q) for a rejected URL", openedLocally)
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
