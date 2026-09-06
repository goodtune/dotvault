package auth

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

func TestPostFormToPeer_Success(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "dotvault.sock")
	var gotPath, gotField, gotHost string
	newUnixServer(t, sock, "POST /api/v1/remote/browse", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotPath, gotField, gotHost = r.URL.Path, r.PostFormValue("url"), r.Host
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	err := PostFormToPeer(context.Background(), sock, "/api/v1/remote/browse", url.Values{"url": {"https://example.com"}})
	if err != nil {
		t.Fatalf("PostFormToPeer: %v", err)
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

func TestPostFormToPeer_MissingSocketIsUnreachable(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")
	err := PostFormToPeer(context.Background(), sock, "/api/v1/remote/browse", url.Values{})
	if !errors.Is(err, ErrPeerUnreachable) {
		t.Fatalf("err = %v, want it to wrap ErrPeerUnreachable", err)
	}
}

func TestPostFormToPeer_StaleSocketIsUnreachable(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "stale.sock")
	if err := os.WriteFile(sock, []byte("not a socket"), 0600); err != nil {
		t.Fatal(err)
	}
	err := PostFormToPeer(context.Background(), sock, "/api/v1/remote/browse", url.Values{})
	if !errors.Is(err, ErrPeerUnreachable) {
		t.Fatalf("err = %v, want it to wrap ErrPeerUnreachable", err)
	}
}

func TestPostFormToPeer_NonOKIsStatusError(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "dotvault.sock")
	newUnixServer(t, sock, "POST /api/v1/remote/browse", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"unsupported url scheme"}`))
	})

	err := PostFormToPeer(context.Background(), sock, "/api/v1/remote/browse", url.Values{"url": {"file:///etc"}})
	var se *PeerStatusError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want a *PeerStatusError", err)
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

func TestPeerStatusError_NoMessage(t *testing.T) {
	e := &PeerStatusError{Status: http.StatusBadGateway}
	if got := e.Error(); got != "peer returned 502" {
		t.Errorf("Error() = %q, want %q", got, "peer returned 502")
	}
}
