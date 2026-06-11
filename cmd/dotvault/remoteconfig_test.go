package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// isolateCacheDir points paths.CacheDir at a temp dir (via the env vars it
// derives from per-OS) so the fetcher inside withRemote never reads or writes
// the developer's real ~/.cache/dotvault.
func isolateCacheDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)         // linux / darwin
	t.Setenv("LOCALAPPDATA", dir) // windows
}

// TestWithRemoteOverlay exercises the loader pipeline end-to-end: a base with
// zero local rules but a remote URL parses raw, merges the fetched partial,
// and validates — while the same base without a remote URL fails closed.
func TestWithRemoteOverlay(t *testing.T) {
	isolateCacheDir(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`rules:
  - name: remote-rule
    vault_key: remote
    target:
      path: ~/.dotvault/remote
      format: text
enrolments:
  gh:
    engine: github
`))
	}))
	defer srv.Close()

	baseLoader := func() (*config.Config, error) {
		return &config.Config{
			Vault:        config.VaultConfig{Address: "https://vault.example.com:8200"},
			RemoteConfig: config.RemoteConfig{URL: srv.URL},
		}, nil
	}

	merged, status := withRemote(t.Context(), baseLoader)
	cfg, err := merged()
	if err != nil {
		t.Fatalf("merged loader: %v", err)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].Name != "remote-rule" {
		t.Errorf("Rules = %+v, want the remote rule", cfg.Rules)
	}
	if cfg.Enrolments["gh"].Engine != "github" {
		t.Errorf("Enrolments = %+v, want remote gh enrolment", cfg.Enrolments)
	}
	// Defaults from validation must be applied to the merged result.
	if cfg.Vault.KVMount != config.DefaultKVMount {
		t.Errorf("KVMount = %q, want default applied post-merge", cfg.Vault.KVMount)
	}
	if rs := status(); rs == nil || rs.Source != "remote" {
		t.Errorf("status = %+v, want Source remote", rs)
	}
}

func TestWithRemoteNoURLFailsClosed(t *testing.T) {
	baseLoader := func() (*config.Config, error) {
		return &config.Config{
			Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		}, nil
	}
	merged, status := withRemote(t.Context(), baseLoader)
	if _, err := merged(); err == nil {
		t.Fatal("zero rules without a remote URL must fail validation")
	}
	if rs := status(); rs != nil {
		t.Errorf("status = %+v, want nil when no URL is configured", rs)
	}
}

// TestWithRemoteInvalidSectionRejectedBeforeFetch pins the trust-boundary
// ordering: the base is loaded raw, so the remote_config section's own
// validation must run before any network I/O — a section the validator is
// about to reject (here: userinfo in the URL) must produce zero requests.
func TestWithRemoteInvalidSectionRejectedBeforeFetch(t *testing.T) {
	isolateCacheDir(t)
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write([]byte("rules: []\n"))
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test URL: %v", err)
	}
	baseLoader := func() (*config.Config, error) {
		return &config.Config{
			Vault:        config.VaultConfig{Address: "https://vault.example.com:8200"},
			RemoteConfig: config.RemoteConfig{URL: "http://user:pass@" + u.Host + "/v1/config"},
		}, nil
	}
	merged, _ := withRemote(t.Context(), baseLoader)
	if _, err := merged(); err == nil {
		t.Fatal("expected validation error for a userinfo URL")
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("fetch happened before validation: %d request(s)", n)
	}
}

// TestWithRemoteUnreachableServiceDegradesToBase pins the fail-open ladder at
// the loader level: remote configured but down, no cache ⇒ the base loads
// (zero rules is a warning, not an error) so the daemon can start and
// converge later.
func TestWithRemoteUnreachableServiceDegradesToBase(t *testing.T) {
	isolateCacheDir(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	baseLoader := func() (*config.Config, error) {
		return &config.Config{
			Vault:        config.VaultConfig{Address: "https://vault.example.com:8200"},
			RemoteConfig: config.RemoteConfig{URL: url},
		}, nil
	}
	merged, status := withRemote(t.Context(), baseLoader)
	cfg, err := merged()
	if err != nil {
		t.Fatalf("merged loader with unreachable remote: %v", err)
	}
	if len(cfg.Rules) != 0 {
		t.Errorf("Rules = %+v, want none", cfg.Rules)
	}
	if rs := status(); rs == nil || rs.Source != "none" || rs.LastError == "" {
		t.Errorf("status = %+v, want Source none with an error recorded", rs)
	}
}
