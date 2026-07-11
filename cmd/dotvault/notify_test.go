package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/goodtune/dotvault/internal/notify"
)

// newUnixNotifyServer starts an httptest server bound to a Unix socket at
// sockPath, serving POST /api/v1/remote/notify. Skips where AF_UNIX is
// unavailable, matching the browse/token-borrow test convention.
func newUnixNotifyServer(t *testing.T, sockPath string, handler http.HandlerFunc) {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix domain sockets unavailable on this platform: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/remote/notify", handler)
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
}

func TestPostNotifyToSocket_Success(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "dotvault.sock")
	var level, title, body, host string
	newUnixNotifyServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		level, title, body, host = r.FormValue("level"), r.FormValue("title"), r.FormValue("body"), r.Host
		_, _ = w.Write([]byte(`{"status":"notification delivered"}`))
	})

	msg := notify.Message{Level: notify.LevelError, Title: "Backup failed", Body: "see logs"}
	if err := postNotifyToSocket(context.Background(), sock, msg); err != nil {
		t.Fatalf("postNotifyToSocket: %v", err)
	}
	if level != "error" || title != "Backup failed" || body != "see logs" {
		t.Errorf("peer got level=%q title=%q body=%q, want the message fields", level, title, body)
	}
	if host != "localhost" {
		t.Errorf("peer Host = %q, want localhost (the DNS-rebinding allowlist)", host)
	}
}

func TestPostNotifyToSocket_MissingSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")
	msg := notify.Message{Level: notify.LevelInfo, Title: "t"}
	if err := postNotifyToSocket(context.Background(), sock, msg); err == nil {
		t.Fatal("expected an error for a missing socket so the caller falls back locally")
	}
}

func TestPostNotifyToSocket_PeerError(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "dotvault.sock")
	newUnixNotifyServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"failed to deliver notification: no daemon"}`))
	})

	msg := notify.Message{Level: notify.LevelInfo, Title: "t"}
	err := postNotifyToSocket(context.Background(), sock, msg)
	if err == nil {
		t.Fatal("expected an error for a non-200 peer response")
	}
	if got := err.Error(); got != "peer returned 502: failed to deliver notification: no daemon" {
		t.Errorf("error = %q, want the peer's message included", got)
	}
}

// runNotifyWith drives runNotify with a fake local notifier and the given
// --config override, returning the command error and the message (if any) the
// local notifier received.
func runNotifyWith(t *testing.T, cfgPath string, args ...string) (error, *notify.Message) {
	t.Helper()
	prevCfg := flagConfig
	flagConfig = cfgPath
	prevSend := sendLocalNotification
	var localMsg *notify.Message
	sendLocalNotification = func(m notify.Message) error {
		localMsg = &m
		return nil
	}
	t.Cleanup(func() {
		flagConfig = prevCfg
		sendLocalNotification = prevSend
	})

	cmd := newNotifyCmd()
	cmd.SetContext(context.Background())
	err := runNotify(cmd, args)
	return err, localMsg
}

func TestRunNotify_PrefersPeerSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "p.sock")
	var peerTitle string
	newUnixNotifyServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		peerTitle = r.FormValue("title")
		_, _ = w.Write([]byte(`{"status":"notification delivered"}`))
	})

	err, localMsg := runNotifyWith(t, writeBrowseConfig(t, sock), "info", "Peer title", "desc")
	if err != nil {
		t.Fatalf("runNotify: %v", err)
	}
	if peerTitle != "Peer title" {
		t.Errorf("peer got title %q, want the posted title", peerTitle)
	}
	if localMsg != nil {
		t.Errorf("local notifier was called (%+v) despite a healthy peer", localMsg)
	}
}

func TestRunNotify_ActionURLFlagReachesPeer(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "p.sock")
	var peerActionURL string
	newUnixNotifyServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		peerActionURL = r.FormValue("action_url")
		_, _ = w.Write([]byte(`{"status":"notification delivered"}`))
	})

	prevCfg := flagConfig
	flagConfig = writeBrowseConfig(t, sock)
	t.Cleanup(func() { flagConfig = prevCfg })

	cmd := newNotifyCmd()
	cmd.SetContext(context.Background())
	if err := cmd.Flags().Set("action-url", "https://ci.example/build/42"); err != nil {
		t.Fatal(err)
	}
	if err := runNotify(cmd, []string{"info", "Build done"}); err != nil {
		t.Fatalf("runNotify: %v", err)
	}
	if peerActionURL != "https://ci.example/build/42" {
		t.Errorf("peer got action_url = %q, want the flag value", peerActionURL)
	}
}

func TestRunNotify_RejectsBadActionURLFlag(t *testing.T) {
	cmd := newNotifyCmd()
	cmd.SetContext(context.Background())
	if err := cmd.Flags().Set("action-url", "file:///etc/passwd"); err != nil {
		t.Fatal(err)
	}
	// A bad action URL must fail locally before config load or any peer/local
	// delivery, like a bad level.
	prevSend := sendLocalNotification
	called := false
	sendLocalNotification = func(notify.Message) error { called = true; return nil }
	t.Cleanup(func() { sendLocalNotification = prevSend })

	if err := runNotify(cmd, []string{"info", "t"}); err == nil {
		t.Fatal("expected an error for a non-http(s) action URL")
	}
	if called {
		t.Error("local notifier was called despite a rejected action URL")
	}
}

func TestRunNotify_FallsBackWhenPeerUnreachable(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")

	err, localMsg := runNotifyWith(t, writeBrowseConfig(t, sock), "warning", "Local title", "desc")
	if err != nil {
		t.Fatalf("runNotify: %v", err)
	}
	if localMsg == nil {
		t.Fatal("local notifier was not called after peer fallback")
	}
	if localMsg.Title != "Local title" || localMsg.Level != notify.LevelWarning {
		t.Errorf("local notifier got %+v, want the parsed message", localMsg)
	}
}

func TestRunNotify_FallsBackWhenPeerErrors(t *testing.T) {
	// The peer is reachable but returns a non-200 (e.g. its notification
	// backend failed): runNotify must fall back to the local notifier rather
	// than surfacing the peer error.
	sock := filepath.Join(t.TempDir(), "p.sock")
	newUnixNotifyServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"no daemon"}`))
	})

	err, localMsg := runNotifyWith(t, writeBrowseConfig(t, sock), "info", "Fallback", "d")
	if err != nil {
		t.Fatalf("runNotify: %v", err)
	}
	if localMsg == nil || localMsg.Title != "Fallback" {
		t.Errorf("local notifier got %+v, want the message after peer error", localMsg)
	}
}

func TestRunNotify_FallsBackWhenConfigUnloadable(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "missing.yaml")

	err, localMsg := runNotifyWith(t, cfgPath, "info", "T", "d")
	if err != nil {
		t.Fatalf("runNotify: %v", err)
	}
	if localMsg == nil || localMsg.Title != "T" {
		t.Errorf("local notifier got %+v, want the message when config load fails", localMsg)
	}
}

func TestRunNotify_RejectsBadLevelBeforeAnything(t *testing.T) {
	err, localMsg := runNotifyWith(t, "", "bogus", "T", "d")
	if err == nil {
		t.Fatal("expected an error for an unknown level")
	}
	if localMsg != nil {
		t.Errorf("local notifier was called (%+v) for a rejected level", localMsg)
	}
}

func TestRunNotify_BodyOptional(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")

	err, localMsg := runNotifyWith(t, writeBrowseConfig(t, sock), "info", "No body")
	if err != nil {
		t.Fatalf("runNotify: %v", err)
	}
	if localMsg == nil || localMsg.Title != "No body" || localMsg.Body != "" {
		t.Errorf("local notifier got %+v, want a body-less message", localMsg)
	}
}
