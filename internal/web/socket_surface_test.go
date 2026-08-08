//go:build !windows

package web

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/uds"
	"github.com/goodtune/dotvault/internal/vault"
)

// socketClient builds an http.Client that reaches the server over its Unix
// socket, mirroring what auth.PeerSocketClient does on the borrow side.
func socketClient(path string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
		Timeout: 5 * time.Second,
	}
}

// startSocketServer stands up a socket-only server (web.enabled false) and
// returns it with a client wired to the socket.
func startSocketServer(t *testing.T, vaultHandler http.Handler) (*Server, *http.Client, string) {
	t.Helper()

	ts := httptest.NewServer(vaultHandler)
	t.Cleanup(ts.Close)
	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "peer-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	sock := filepath.Join(t.TempDir(), "api.sock")
	s, err := NewServer(ServerConfig{
		WebCfg:        config.WebConfig{Enabled: false},
		VaultCfg:      config.VaultConfig{Address: ts.URL, KVMount: "kv", UserPrefix: "users/"},
		APICfg:        config.APIConfig{Enabled: true},
		APISocketPath: sock,
		Vault:         vc,
		Username:      "testuser",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go s.Start()
	if err := s.WaitReady(); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.Shutdown(ctx)
	})
	return s, socketClient(sock), sock
}

// TestSocketOnlyServerServesToken is the whole point of the feature: a daemon
// with no web UI still lends its live token to a local client over the
// socket, which is what lets a process survive the SSH session it started in.
func TestSocketOnlyServerServesToken(t *testing.T) {
	_, client, sock := startSocketServer(t, http.HandlerFunc(fakeVaultHandler))

	if fi, err := os.Stat(sock); err != nil {
		t.Fatalf("socket not created: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("socket perm = %v, want 0600", fi.Mode().Perm())
	}

	resp, err := client.Get("http://localhost/api/v1/token")
	if err != nil {
		t.Fatalf("GET token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Token != "peer-token" {
		t.Errorf("token = %q, want %q", body.Token, "peer-token")
	}
}

// TestSocketOnlyServerOmitsUIRoutes proves the socket surface does not
// publish the browser-facing routes. They build redirect URIs from a bound
// TCP address that does not exist here, so serving them could only produce a
// login flow that cannot complete.
func TestSocketOnlyServerOmitsUIRoutes(t *testing.T) {
	_, client, _ := startSocketServer(t, http.HandlerFunc(fakeVaultHandler))

	for _, path := range []string{
		"/auth/oidc/start",
		"/auth/ldap/status",
		"/api/v1/enrol/prompt",
		"/", // the SPA
	} {
		resp, err := client.Get("http://localhost" + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: status = %d, want 404 (route should not be registered)", path, resp.StatusCode)
		}
	}
}

// TestSocketOnlyServerServesHealthAndStatus confirms the operational
// endpoints stay available: monitoring a daemon without opening a TCP port is
// a legitimate reason to run socket-only.
func TestSocketOnlyServerServesHealthAndStatus(t *testing.T) {
	_, client, _ := startSocketServer(t, http.HandlerFunc(fakeVaultHandler))

	for _, path := range []string{"/healthz", "/api/v1/status"} {
		resp, err := client.Get("http://localhost" + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status = %d, want 200", path, resp.StatusCode)
		}
	}
}

// TestSocketOnlyServerURLIsEmpty guards the daemon's browser-open paths: with
// no TCP listener there is nowhere to point a browser, and a well-formed-
// looking "http:///" would have them try anyway.
func TestSocketOnlyServerURLIsEmpty(t *testing.T) {
	s, _, _ := startSocketServer(t, http.HandlerFunc(fakeVaultHandler))
	if got := s.URL(); got != "" {
		t.Errorf("URL() = %q, want empty for a socket-only server", got)
	}
}

// TestSocketOnlyServerRejectsOrigin covers the peer-action Origin check on a
// server with no TCP listener. Nothing this daemon serves can be the origin
// of a page, so any Origin header is a proxied request — and the fallback the
// check would otherwise take (hostname-only, when no listen port is known)
// would admit a page served by any other loopback listener.
func TestSocketOnlyServerRejectsOrigin(t *testing.T) {
	_, client, _ := startSocketServer(t, http.HandlerFunc(fakeVaultHandler))

	req, err := http.NewRequest("POST", "http://localhost/api/v1/remote/browse",
		strings.NewReader("url=https://example.com"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://127.0.0.1:9000")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST browse: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for an Origin on a socket-only daemon", resp.StatusCode)
	}
}

// TestNewServerRequiresASurface stops a misconfiguration from producing a
// server that binds nothing and silently answers no one.
func TestNewServerRequiresASurface(t *testing.T) {
	_, err := NewServer(ServerConfig{
		WebCfg: config.WebConfig{Enabled: false},
	})
	if err == nil {
		t.Fatal("NewServer succeeded with neither surface enabled, want error")
	}
	if !strings.Contains(err.Error(), "no surface") {
		t.Errorf("err = %v, want a 'no surface to serve' error", err)
	}
}

// TestSocketAndTCPShareOneMux confirms enabling both surfaces serves the same
// API on each, so a client's behaviour does not depend on which one it found.
func TestSocketAndTCPShareOneMux(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(fakeVaultHandler))
	defer ts.Close()
	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "peer-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	sock := filepath.Join(t.TempDir(), "api.sock")
	s, err := NewServer(ServerConfig{
		WebCfg:        config.WebConfig{Enabled: true, Listen: "127.0.0.1:0"},
		VaultCfg:      config.VaultConfig{Address: ts.URL, KVMount: "kv", UserPrefix: "users/"},
		APICfg:        config.APIConfig{Enabled: true},
		APISocketPath: sock,
		Vault:         vc,
		Username:      "testuser",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go s.Start()
	if err := s.WaitReady(); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.Shutdown(ctx)
	}()

	for name, client := range map[string]*http.Client{
		"socket": socketClient(sock),
		"tcp":    {Timeout: 5 * time.Second},
	} {
		url := "http://localhost/api/v1/token"
		if name == "tcp" {
			url = s.URL() + "api/v1/token"
		}
		resp, err := client.Get(url)
		if err != nil {
			t.Fatalf("%s: GET token: %v", name, err)
		}
		var body struct {
			Token string `json:"token"`
		}
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if body.Token != "peer-token" {
			t.Errorf("%s: token = %q, want %q", name, body.Token, "peer-token")
		}
	}
}

// TestShutdownRemovesSocket keeps a stopped daemon from leaving a node behind
// that the next start has to prove is stale.
func TestShutdownRemovesSocket(t *testing.T) {
	s, _, sock := startSocketServer(t, http.HandlerFunc(fakeVaultHandler))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("socket still present after Shutdown")
	}
}

// TestLosingServerDoesNotUnlinkWinnersSocket is the regression test for the
// worst failure this feature can produce. A second daemon started against a
// socket a live instance already owns is correctly refused by uds.Listen —
// but the daemon then runs its deferred Shutdown on the way out. If that
// Shutdown unlinked the socket node unconditionally it would delete the
// *winning* daemon's socket: the winner keeps serving an inode nobody can
// reach, every client loses the borrow endpoint, and `dotvault status`
// reports the daemon as not running. The failure is silent on both sides.
func TestLosingServerDoesNotUnlinkWinnersSocket(t *testing.T) {
	winner, client, sock := startSocketServer(t, http.HandlerFunc(fakeVaultHandler))

	ts := httptest.NewServer(http.HandlerFunc(fakeVaultHandler))
	defer ts.Close()
	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "loser-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	loser, err := NewServer(ServerConfig{
		WebCfg:        config.WebConfig{Enabled: false},
		VaultCfg:      config.VaultConfig{Address: ts.URL, KVMount: "kv", UserPrefix: "users/"},
		APICfg:        config.APIConfig{Enabled: true},
		APISocketPath: sock, // the same socket the winner is serving
		Vault:         vc,
		Username:      "testuser",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	startErr := make(chan error, 1)
	go func() { startErr <- loser.Start() }()
	if err := loser.WaitReady(); err == nil {
		t.Fatal("second server bound a socket the first was serving, want refusal")
	} else if !strings.Contains(err.Error(), "already serving") {
		t.Errorf("err = %v, want an already-serving error", err)
	}
	<-startErr

	// The daemon's shutdown path runs even when startup failed.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := loser.Shutdown(ctx); err != nil {
		t.Fatalf("loser Shutdown: %v", err)
	}

	// The winner's socket node must still exist and still serve.
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("winner's socket was removed by the losing server: %v", err)
	}
	resp, err := client.Get("http://localhost/api/v1/token")
	if err != nil {
		t.Fatalf("winner no longer reachable after loser shut down: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 — winner should be unaffected", resp.StatusCode)
	}
	_ = winner
}

// TestPartialBindCleansUpBoundListeners covers the other half of listen():
// when a later bind fails, the listeners already opened must be closed rather
// than left dangling — including the socket node, which would otherwise have
// to be proven stale on the next start.
func TestPartialBindCleansUpBoundListeners(t *testing.T) {
	// Occupy a TCP port, then ask for it explicitly so the TCP bind fails
	// after the socket path has been chosen.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	ts := httptest.NewServer(http.HandlerFunc(fakeVaultHandler))
	defer ts.Close()
	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "t"})
	if err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(t.TempDir(), "api.sock")
	s, err := NewServer(ServerConfig{
		WebCfg:        config.WebConfig{Enabled: true, Listen: occupied.Addr().String()},
		VaultCfg:      config.VaultConfig{Address: ts.URL},
		APICfg:        config.APIConfig{Enabled: true},
		APISocketPath: sock,
		Vault:         vc,
		Username:      "testuser",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go s.Start()
	if err := s.WaitReady(); err == nil {
		t.Fatal("Start succeeded despite an occupied TCP port")
	}

	// The TCP listener is bound first, so the socket was never created here.
	// What matters is that nothing is left listening: a subsequent bind on
	// the same socket path must succeed cleanly.
	ln, err := uds.Listen(sock)
	if err != nil {
		t.Fatalf("socket path unusable after a failed Start: %v", err)
	}
	ln.Close()
}

// fakeReauthGate reports a fixed re-auth state.
type fakeReauthGate struct{ needs bool }

func (f fakeReauthGate) NeedsReauth() bool { return f.needs }

// TestTokenEndpointDeclinesDuringReauth: once the daemon knows its own token
// is dead, lending it out just moves the failure to the borrower — which on a
// headless host has no way to recover on its own.
func TestTokenEndpointDeclinesDuringReauth(t *testing.T) {
	s, client, _ := startSocketServer(t, http.HandlerFunc(fakeVaultHandler))

	// Healthy first, to be sure the 401 below is the gate and not the setup.
	resp, err := client.Get("http://localhost/api/v1/token")
	if err != nil {
		t.Fatalf("GET token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d before gate, want 200", resp.StatusCode)
	}

	s.SetReauthGate(fakeReauthGate{needs: true})

	resp, err = client.Get("http://localhost/api/v1/token")
	if err != nil {
		t.Fatalf("GET token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d during re-auth, want 401", resp.StatusCode)
	}
}

// fakeActivatedListener installs a stand-in for systemd socket activation
// that hands out listeners for path, mimicking the retained-master model:
// each call binds is wrong — systemd's fd is one socket — so a single real
// listener is created once and duplicated per claim via File(), exactly as
// uds.ActivatedListener dups its retained master.
func fakeActivatedListener(t *testing.T, path string) func() {
	t.Helper()
	master, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate FileListener-derived semantics: closing a claim must not
	// unlink systemd's node.
	master.(*net.UnixListener).SetUnlinkOnClose(false)

	orig := activatedAPIListener
	activatedAPIListener = func() (net.Listener, string, error) {
		f, err := master.(*net.UnixListener).File()
		if err != nil {
			return nil, "", err
		}
		ln, err := net.FileListener(f)
		f.Close()
		if err != nil {
			return nil, "", err
		}
		return ln, path, nil
	}
	return func() {
		activatedAPIListener = orig
		master.Close()
	}
}

// TestSocketActivatedAPIServesAndSurvivesShutdown covers the activated
// branch of Server.listen end to end: the daemon serves the API over the
// inherited listener, adopts the activated path as its own, and — because
// systemd owns the node — its Shutdown must not unlink it. Reverting the
// socketBound skip or the activated branch fails this test.
func TestSocketActivatedAPIServesAndSurvivesShutdown(t *testing.T) {
	dir := t.TempDir()
	activatedPath := filepath.Join(dir, "systemd.sock")
	restore := fakeActivatedListener(t, activatedPath)
	defer restore()

	ts := httptest.NewServer(http.HandlerFunc(fakeVaultHandler))
	defer ts.Close()
	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "peer-token"})
	if err != nil {
		t.Fatal(err)
	}

	configuredPath := filepath.Join(dir, "configured.sock")
	s, err := NewServer(ServerConfig{
		WebCfg:        config.WebConfig{Enabled: false},
		VaultCfg:      config.VaultConfig{Address: ts.URL, KVMount: "kv", UserPrefix: "users/"},
		APICfg:        config.APIConfig{Enabled: true},
		APISocketPath: configuredPath, // deliberately differs: the socket unit's path must win
		Vault:         vc,
		Username:      "testuser",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go s.Start()
	if err := s.WaitReady(); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}

	// Served over the activated socket, at the activated path.
	resp, err := socketClient(activatedPath).Get("http://localhost/api/v1/token")
	if err != nil {
		t.Fatalf("GET token over activated socket: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	// The configured path was never bound: nothing self-bound while an
	// activated fd was available.
	if _, err := os.Stat(configuredPath); !os.IsNotExist(err) {
		t.Errorf("configured path %s exists; the activated socket should have pre-empted self-binding", configuredPath)
	}

	// Shutdown must leave systemd's node alone.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if _, err := os.Stat(activatedPath); err != nil {
		t.Errorf("activated socket node removed by Shutdown; systemd owns it: %v", err)
	}
}
