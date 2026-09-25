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
	"testing"
)

// newUnixTokenServer starts an httptest server bound to a Unix socket at
// sockPath, serving GET /api/v1/token with the given handler. It returns the
// server so the caller can Close it. If the platform cannot bind a Unix-domain
// socket (some Windows configurations lack AF_UNIX server support) the test is
// skipped rather than failed — the borrow feature's listener side is Linux/macOS
// in the documented topology, and the pure-logic cases run regardless.
func newUnixTokenServer(t *testing.T, sockPath string, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix domain sockets unavailable on this platform: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/token", handler)
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchToken_Success(t *testing.T) {
	sock := filepath.Join(sockDir(t), "dotvault.sock")
	newUnixTokenServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"hvs.peer-token"}`))
	})

	got, err := FetchToken(context.Background(), sock)
	if err != nil {
		t.Fatalf("FetchToken: %v", err)
	}
	if got != "hvs.peer-token" {
		t.Errorf("token = %q, want %q", got, "hvs.peer-token")
	}
}

func TestFetchToken_EmptyPath(t *testing.T) {
	got, err := FetchToken(context.Background(), "")
	if err != nil || got != "" {
		t.Errorf("got (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestFetchToken_MissingSocket(t *testing.T) {
	// A path that does not exist must resolve to ("", nil) — the peer simply
	// isn't connected, and the caller carries on with its normal auth flow.
	sock := filepath.Join(sockDir(t), "absent.sock")
	got, err := FetchToken(context.Background(), sock)
	if err != nil || got != "" {
		t.Errorf("got (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestFetchToken_StaleSocket(t *testing.T) {
	// A regular file at the socket path (no listener) stands in for a stale
	// socket left behind by a dead SSH session: the dial fails and we carry on.
	sock := filepath.Join(sockDir(t), "stale.sock")
	if err := os.WriteFile(sock, []byte("not a socket"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := FetchToken(context.Background(), sock)
	if err != nil || got != "" {
		t.Errorf("got (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestFetchToken_PeerUnauthenticated(t *testing.T) {
	// The peer is reachable but holds no token (mirrors handleToken's 401):
	// best-effort, so we return ("", nil) rather than an error.
	sock := filepath.Join(sockDir(t), "dotvault.sock")
	newUnixTokenServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not authenticated"}`, http.StatusUnauthorized)
	})

	got, err := FetchToken(context.Background(), sock)
	if err != nil || got != "" {
		t.Errorf("got (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestFetchToken_MalformedBody(t *testing.T) {
	sock := filepath.Join(sockDir(t), "dotvault.sock")
	newUnixTokenServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`this is not json`))
	})

	got, err := FetchToken(context.Background(), sock)
	if err != nil || got != "" {
		t.Errorf("got (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestFetchToken_ExpandsHome(t *testing.T) {
	// A leading ~ must be expanded against the user's home directory so the
	// documented "~/.ssh/dotvault.sock" form works.
	home := t.TempDir()
	t.Setenv("HOME", home)        // Linux/macOS
	t.Setenv("USERPROFILE", home) // Windows
	// Keep the socket path short: Unix socket paths have a ~104-byte limit, so
	// place it directly under the (temp) home.
	sock := filepath.Join(home, "d.sock")
	newUnixTokenServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token":"hvs.home-token"}`))
	})

	got, err := FetchToken(context.Background(), "~/d.sock")
	if err != nil {
		t.Fatalf("FetchToken: %v", err)
	}
	if got != "hvs.home-token" {
		t.Errorf("token = %q, want %q", got, "hvs.home-token")
	}
}

// newUnixServer starts an httptest server bound to a Unix socket at sockPath,
// serving the given pattern with handler. Skips where AF_UNIX is unavailable,
// matching newUnixTokenServer's convention.
func newUnixServer(t *testing.T, sockPath, pattern string, handler http.HandlerFunc) {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix domain sockets unavailable on this platform: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(pattern, handler)
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
}

func TestPostForm_Success(t *testing.T) {
	sock := filepath.Join(sockDir(t), "dotvault.sock")
	var gotPath, gotField, gotHost string
	newUnixServer(t, sock, "POST /api/v1/remote/browse", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotPath, gotField, gotHost = r.URL.Path, r.PostFormValue("url"), r.Host
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	err := PostForm(context.Background(), sock, "/api/v1/remote/browse", url.Values{"url": {"https://example.com"}})
	if err != nil {
		t.Fatalf("PostForm: %v", err)
	}
	if gotPath != "/api/v1/remote/browse" {
		t.Errorf("peer path = %q, want the apiPath", gotPath)
	}
	if gotField != "https://example.com" {
		t.Errorf("peer url field = %q, want the posted value", gotField)
	}
	if gotHost != "localhost" {
		t.Errorf("peer Host = %q, want localhost (DNS-rebinding allowlist)", gotHost)
	}
}

func TestPostForm_MissingSocketIsUnreachable(t *testing.T) {
	sock := filepath.Join(sockDir(t), "absent.sock")
	err := PostForm(context.Background(), sock, "/api/v1/remote/browse", url.Values{})
	if !errors.Is(err, ErrPeerUnreachable) {
		t.Fatalf("err = %v, want it to wrap ErrPeerUnreachable", err)
	}
}

func TestPostForm_StaleSocketIsUnreachable(t *testing.T) {
	sock := filepath.Join(sockDir(t), "stale.sock")
	if err := os.WriteFile(sock, []byte("not a socket"), 0600); err != nil {
		t.Fatal(err)
	}
	err := PostForm(context.Background(), sock, "/api/v1/remote/browse", url.Values{})
	if !errors.Is(err, ErrPeerUnreachable) {
		t.Fatalf("err = %v, want it to wrap ErrPeerUnreachable", err)
	}
}

func TestPostForm_NonOKIsStatusError(t *testing.T) {
	sock := filepath.Join(sockDir(t), "dotvault.sock")
	newUnixServer(t, sock, "POST /api/v1/remote/browse", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"unsupported url scheme"}`))
	})

	err := PostForm(context.Background(), sock, "/api/v1/remote/browse", url.Values{"url": {"file:///etc"}})
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want a *StatusError", err)
	}
	if se.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", se.Status)
	}
	if se.Message != "unsupported url scheme" {
		t.Errorf("message = %q, want the peer's error body", se.Message)
	}
	if got := se.Error(); got != "peer returned 400: unsupported url scheme" {
		t.Errorf("Error() = %q, want the peer status + message", got)
	}
}

func TestStatusError_NoMessage(t *testing.T) {
	e := &StatusError{Status: http.StatusBadGateway}
	if got := e.Error(); got != "peer returned 502" {
		t.Errorf("Error() = %q, want %q", got, "peer returned 502")
	}
}
