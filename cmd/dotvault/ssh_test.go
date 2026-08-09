package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/sshfwd"
)

// shortSocketPath returns a short, unique path under the OS temp root for a
// Unix-domain socket. t.TempDir() embeds the test's full name in the path,
// which can exceed the ~104-byte sun_path limit for a longer test name (seen
// on this package's own longer-named tests); this stays short regardless.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(os.TempDir(), "dv-"+hex.EncodeToString(b)+".sock")
	t.Cleanup(func() { os.Remove(p) })
	return p
}

// newUnixSSHServer starts an httptest server bound to a Unix socket at
// sockPath, serving the given mux. Mirrors newUnixBrowseServer/
// newUnixNotifyServer: skip when AF_UNIX is unavailable on this platform.
func newUnixSSHServer(t *testing.T, sockPath string, mux *http.ServeMux) {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix domain sockets unavailable on this platform: %v", err)
	}
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
}

// useSSHDaemonConfig writes a minimal valid config pointing `dotvault ssh` at
// the local API socket sockPath, loads it directly via config.Load, and
// stubs sshLoadConfig to return it for the duration of the test.
//
// This deliberately bypasses --config / flagConfig and the
// resolveConfigSource system-config gate those exercise (see
// browse_test.go's writeBrowseConfig for that ordinary path): a real
// system-wide dotvault install on the test host — exactly the scenario
// main_test.go already skips around — would otherwise make every ssh
// subcommand test fail with "a system-wide configuration is present" instead
// of exercising the behaviour under test.
func useSSHDaemonConfig(t *testing.T, sockPath string) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	yaml := `vault:
  address: http://127.0.0.1:8200
api:
  enabled: true
  unix:
    path: ` + sockPath + `
rules:
  - name: dummy
    vault_key: dummy
    target:
      path: ~/dummy.txt
      format: text
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load(%s): %v", cfgPath, err)
	}

	prev := sshLoadConfig
	sshLoadConfig = func() (*config.Config, string, error) { return cfg, cfgPath, nil }
	t.Cleanup(func() { sshLoadConfig = prev })
}

// sshCSRFHandler serves a fixed CSRF token — the fakes below don't need real
// one-time-use enforcement, only to exercise the client's fetch-then-attach
// flow.
func sshCSRFHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"token":"test-csrf-token"}`))
}

func TestSSHListRendersDaemonState(t *testing.T) {
	sock := shortSocketPath(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"ssh": [
				{"host": "zeta.example.com", "state": "connected", "remote_socket": "~/.ssh/dotvault.sock", "reconnects": 0, "last_error": ""},
				{"host": "alpha.example.com", "state": "offline", "remote_socket": "~/.ssh/dotvault.sock", "reconnects": 3, "last_error": "connection refused"}
			]
		}`))
	})
	newUnixSSHServer(t, sock, mux)
	useSSHDaemonConfig(t, sock)

	cmd := newSSHListCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	if err := runSSHList(cmd, nil); err != nil {
		t.Fatalf("runSSHList: %v", err)
	}

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("output = %q, want a header line and two rows", out.String())
	}
	if !strings.HasPrefix(lines[0], "HOST") {
		t.Errorf("header line = %q, want it to start with HOST", lines[0])
	}
	// Rows must be sorted by host: alpha before zeta, regardless of the
	// daemon's own response order.
	if !strings.Contains(lines[1], "alpha.example.com") || !strings.Contains(lines[1], "offline") {
		t.Errorf("row 1 = %q, want alpha.example.com/offline first", lines[1])
	}
	if !strings.Contains(lines[2], "zeta.example.com") || !strings.Contains(lines[2], "connected") {
		t.Errorf("row 2 = %q, want zeta.example.com/connected second", lines[2])
	}
}

func TestSSHListDegradesWhenDaemonDown(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))

	sshPath, err := paths.SSHConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	f := &sshfwd.File{Remotes: []sshfwd.Remote{
		{Host: "offline-daemon.example.com", Port: 22, RemoteSocket: sshfwd.DefaultRemoteSocket},
	}}
	if err := sshfwd.Save(sshPath, f); err != nil {
		t.Fatal(err)
	}

	sock := shortSocketPath(t) // never bound: the daemon is "down"
	useSSHDaemonConfig(t, sock)

	cmd := newSSHListCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	if err := runSSHList(cmd, nil); err != nil {
		t.Fatalf("runSSHList: %v, want a fallback to ssh.yaml instead of an error", err)
	}

	got := out.String()
	if !strings.Contains(got, "offline-daemon.example.com") {
		t.Errorf("output = %q, want the host read from ssh.yaml", got)
	}
	if !strings.Contains(got, "unavailable") {
		t.Errorf("output = %q, want \"unavailable\" in the STATUS column when the daemon can't be reached", got)
	}
}

// TestSSHListDegradesWhenDaemonDownAndNoSSHYAML covers the other half of the
// fallback: no daemon AND no ssh.yaml ever written (a brand-new install).
// sshfwd.Load treats a missing file as an empty document rather than an
// error, so this must still succeed and print just the header row, not fail
// the way it would if the fallback conflated "empty" with "unreadable".
func TestSSHListDegradesWhenDaemonDownAndNoSSHYAML(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	// Deliberately no sshfwd.Save call: ssh.yaml does not exist.

	sock := shortSocketPath(t) // never bound: the daemon is "down"
	useSSHDaemonConfig(t, sock)

	cmd := newSSHListCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	if err := runSSHList(cmd, nil); err != nil {
		t.Fatalf("runSSHList: %v, want a fallback to an empty table, not an error", err)
	}

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "HOST") {
		t.Errorf("output = %q, want just the header row for a brand-new install", out.String())
	}
}

func TestSSHAddPromptsOnFingerprint409(t *testing.T) {
	sock := shortSocketPath(t)
	mux := http.NewServeMux()
	var posts int
	var lastAcceptFingerprint string
	mux.HandleFunc("GET /api/v1/csrf", sshCSRFHandler)
	mux.HandleFunc("POST /api/v1/ssh/remotes", func(w http.ResponseWriter, r *http.Request) {
		posts++
		var req sshAddRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		lastAcceptFingerprint = req.AcceptFingerprint
		w.Header().Set("Content-Type", "application/json")
		if req.AcceptFingerprint == "" {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"host":"new.example.com","fingerprint":"SHA256:abc123"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"host":"new.example.com","port":22,"remote_socket":"~/.ssh/dotvault.sock","enabled":true}`))
	})
	newUnixSSHServer(t, sock, mux)
	useSSHDaemonConfig(t, sock)

	cmd := newSSHAddCmd()
	var errOut bytes.Buffer
	cmd.SetErr(&errOut)
	cmd.SetContext(context.Background())
	if err := cmd.Flags().Set("accept-host-key", "true"); err != nil {
		t.Fatal(err)
	}
	if err := runSSHAdd(cmd, []string{"new.example.com"}); err != nil {
		t.Fatalf("runSSHAdd: %v", err)
	}

	if posts != 2 {
		t.Fatalf("daemon received %d POSTs, want 2 (initial + fingerprint-confirmed re-POST)", posts)
	}
	if lastAcceptFingerprint != "SHA256:abc123" {
		t.Errorf("re-POST accept_fingerprint = %q, want the echoed fingerprint", lastAcceptFingerprint)
	}
	if !strings.Contains(errOut.String(), "SHA256:abc123") {
		t.Errorf("stderr = %q, want the fingerprint printed for the user to see", errOut.String())
	}
}

func TestSSHAddNonTTYRequiresAcceptFlag(t *testing.T) {
	sock := shortSocketPath(t)
	mux := http.NewServeMux()
	var posts int
	mux.HandleFunc("GET /api/v1/csrf", sshCSRFHandler)
	mux.HandleFunc("POST /api/v1/ssh/remotes", func(w http.ResponseWriter, r *http.Request) {
		posts++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"host":"new.example.com","fingerprint":"SHA256:abc123"}`))
	})
	newUnixSSHServer(t, sock, mux)
	useSSHDaemonConfig(t, sock)

	cmd := newSSHAddCmd()
	var errOut bytes.Buffer
	cmd.SetErr(&errOut)
	cmd.SetContext(context.Background())
	// --accept-host-key is deliberately NOT set. A test process's stdin is
	// not a TTY, so this must fail rather than silently accepting or hanging
	// on a prompt nothing will ever answer.
	err := runSSHAdd(cmd, []string{"new.example.com"})
	if err == nil {
		t.Fatal("runSSHAdd() = nil, want an error: a 409 on a non-interactive session without --accept-host-key must not succeed")
	}
	if posts != 1 {
		t.Errorf("daemon received %d POSTs, want exactly 1 (no blind re-POST)", posts)
	}
}

// withInteractiveSSHAdd forces sshIsInteractive() to report true for the
// duration of the test, so the interactive confirm-prompt branch of
// runSSHAdd runs instead of the --accept-host-key-required branch.
func withInteractiveSSHAdd(t *testing.T) {
	t.Helper()
	prev := sshIsInteractive
	sshIsInteractive = func() bool { return true }
	t.Cleanup(func() { sshIsInteractive = prev })
}

// newSSHAddFingerprintServer starts a fake daemon that returns 409 until a
// POST arrives with accept_fingerprint == "SHA256:abc123", then 201. It
// reports the number of POSTs received.
func newSSHAddFingerprintServer(t *testing.T) (sock string, posts *int) {
	t.Helper()
	sock = shortSocketPath(t)
	posts = new(int)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/csrf", sshCSRFHandler)
	mux.HandleFunc("POST /api/v1/ssh/remotes", func(w http.ResponseWriter, r *http.Request) {
		*posts++
		var req sshAddRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		if req.AcceptFingerprint != "SHA256:abc123" {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"host":"new.example.com","fingerprint":"SHA256:abc123"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"host":"new.example.com","port":22,"remote_socket":"~/.ssh/dotvault.sock","enabled":true}`))
	})
	newUnixSSHServer(t, sock, mux)
	return sock, posts
}

// TestSSHAddInteractiveAccepts covers the primary path the whole 409 design
// exists to protect: a human at a terminal, typing "y" or "yes", must have
// their answer actually reach the daemon as the confirmed fingerprint — and
// must have seen that fingerprint printed before being asked to confirm it.
func TestSSHAddInteractiveAccepts(t *testing.T) {
	for _, answer := range []string{"y\n", "Y\n", "yes\n", "YES\n"} {
		t.Run(answer, func(t *testing.T) {
			sock, posts := newSSHAddFingerprintServer(t)
			useSSHDaemonConfig(t, sock)
			withInteractiveSSHAdd(t)

			cmd := newSSHAddCmd()
			var errOut bytes.Buffer
			cmd.SetErr(&errOut)
			cmd.SetIn(strings.NewReader(answer))
			cmd.SetContext(context.Background())
			if err := runSSHAdd(cmd, []string{"new.example.com"}); err != nil {
				t.Fatalf("runSSHAdd: %v", err)
			}

			if *posts != 2 {
				t.Fatalf("daemon received %d POSTs, want 2 (initial + confirmed re-POST)", *posts)
			}
			fpIdx := strings.Index(errOut.String(), "SHA256:abc123")
			promptIdx := strings.Index(errOut.String(), "Trust this host key")
			if fpIdx == -1 || promptIdx == -1 || fpIdx > promptIdx {
				t.Errorf("stderr = %q, want the fingerprint displayed before the prompt asking to confirm it", errOut.String())
			}
		})
	}
}

// TestSSHAddInteractiveDeclines is the other half: "n", a bare Enter, or any
// other input must decline and — critically — must NOT send a second POST.
// Asserting the request count is what would catch an inverted
// answer == "y" check; asserting only the returned error would not, since an
// inverted check that still errors out for an unrelated reason could pass a
// message-only assertion.
func TestSSHAddInteractiveDeclines(t *testing.T) {
	for _, answer := range []string{"n\n", "no\n", "\n", "whatever\n"} {
		t.Run(answer, func(t *testing.T) {
			sock, posts := newSSHAddFingerprintServer(t)
			useSSHDaemonConfig(t, sock)
			withInteractiveSSHAdd(t)

			cmd := newSSHAddCmd()
			var errOut bytes.Buffer
			cmd.SetErr(&errOut)
			cmd.SetIn(strings.NewReader(answer))
			cmd.SetContext(context.Background())
			err := runSSHAdd(cmd, []string{"new.example.com"})
			if err == nil {
				t.Fatal("runSSHAdd() = nil, want a decline error")
			}
			if !strings.Contains(err.Error(), "was not accepted") {
				t.Errorf("error = %q, want it to say the host key was not accepted", err.Error())
			}
			if *posts != 1 {
				t.Errorf("daemon received %d POSTs, want exactly 1 (a decline must never re-POST)", *posts)
			}
		})
	}
}

// erroringReader always fails, simulating a broken stdin.
type erroringReader struct{}

func (erroringReader) Read([]byte) (int, error) { return 0, errors.New("stdin broken") }

// TestSSHAddInteractiveStdinReadErrorDeclines: a read error must be treated
// as a failure to confirm, never as acceptance — the failure mode that
// matters is a broken/closed stdin silently behaving like a "yes".
func TestSSHAddInteractiveStdinReadErrorDeclines(t *testing.T) {
	sock, posts := newSSHAddFingerprintServer(t)
	useSSHDaemonConfig(t, sock)
	withInteractiveSSHAdd(t)

	cmd := newSSHAddCmd()
	var errOut bytes.Buffer
	cmd.SetErr(&errOut)
	cmd.SetIn(erroringReader{})
	cmd.SetContext(context.Background())
	err := runSSHAdd(cmd, []string{"new.example.com"})
	if err == nil {
		t.Fatal("runSSHAdd() = nil, want an error when stdin cannot be read")
	}
	if *posts != 1 {
		t.Errorf("daemon received %d POSTs, want exactly 1 (a stdin read error must never re-POST)", *posts)
	}
}

// TestSSHAddFlagsReachRequestBody proves --force/--port/--socket actually
// reach the POST body, not just that Registry.Add (tested separately in
// internal/sshfwd) honours them once they arrive.
func TestSSHAddFlagsReachRequestBody(t *testing.T) {
	sock := shortSocketPath(t)
	var got sshAddRequest
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/csrf", sshCSRFHandler)
	mux.HandleFunc("POST /api/v1/ssh/remotes", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"host":"flagged.example.com","port":2200,"remote_socket":"/custom/sock","enabled":true}`))
	})
	newUnixSSHServer(t, sock, mux)
	useSSHDaemonConfig(t, sock)

	cmd := newSSHAddCmd()
	cmd.SetContext(context.Background())
	for flag, value := range map[string]string{"port": "2200", "socket": "/custom/sock", "force": "true"} {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := runSSHAdd(cmd, []string{"flagged.example.com"}); err != nil {
		t.Fatalf("runSSHAdd: %v", err)
	}

	if got.Host != "flagged.example.com" {
		t.Errorf("request Host = %q, want flagged.example.com", got.Host)
	}
	if got.Port != 2200 {
		t.Errorf("request Port = %d, want 2200 (from --port)", got.Port)
	}
	if got.RemoteSocket != "/custom/sock" {
		t.Errorf("request RemoteSocket = %q, want /custom/sock (from --socket)", got.RemoteSocket)
	}
	if !got.Force {
		t.Error("request Force = false, want true (from --force)")
	}
}

func TestSSHAddReportsDaemonDown(t *testing.T) {
	sock := shortSocketPath(t) // never bound: the daemon is "down"
	useSSHDaemonConfig(t, sock)

	cmd := newSSHAddCmd()
	cmd.SetContext(context.Background())
	err := runSSHAdd(cmd, []string{"new.example.com"})
	if err == nil {
		t.Fatal("runSSHAdd() = nil, want an error when the daemon is unreachable")
	}
	if !strings.Contains(err.Error(), "daemon") {
		t.Errorf("error = %q, want it to name the daemon rather than surface a bare transport error", err.Error())
	}
}

func TestSSHRemoveIsIdempotent(t *testing.T) {
	sock := shortSocketPath(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/csrf", sshCSRFHandler)
	mux.HandleFunc("DELETE /api/v1/ssh/remotes/{host}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"no remote configured for that host"}`))
	})
	newUnixSSHServer(t, sock, mux)
	useSSHDaemonConfig(t, sock)

	cmd := newSSHRemoveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	if err := runSSHRemove(cmd, []string{"never-added.example.com"}); err != nil {
		t.Fatalf("runSSHRemove() = %v, want nil (idempotent on an unknown host)", err)
	}
	if !strings.Contains(out.String(), "never-added.example.com") {
		t.Errorf("output = %q, want a message naming the host", out.String())
	}
}
