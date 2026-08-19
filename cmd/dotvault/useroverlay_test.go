package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// TestMain points the per-user overlay at a path that does not exist, so the
// rest of this package's tests are not influenced by whatever the developer
// running them happens to have in their own ~/.config/dotvault/config.yaml.
// Tests that exercise the overlay set userConfigPath themselves.
func TestMain(m *testing.M) {
	userConfigPath = func() (string, error) {
		return filepath.Join(os.TempDir(), "dotvault-no-such-user-config", "config.yaml"), nil
	}
	os.Exit(m.Run())
}

// useUserConfig writes a user config into a temp dir and points the resolver
// at it for the duration of the test.
func useUserConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write user config: %v", err)
	}
	prev := userConfigPath
	userConfigPath = func() (string, error) { return path, nil }
	t.Cleanup(func() { userConfigPath = prev })
	return path
}

func baseLoaderWithFUSE(fuse config.FUSEConfig) func() (*config.Config, error) {
	return func() (*config.Config, error) {
		return &config.Config{
			Vault: config.VaultConfig{Address: "https://vault.example.com"},
			FUSE:  fuse,
			Rules: []config.Rule{{
				Name:     "gh",
				VaultKey: "gh",
				Target:   config.Target{Path: "~/.netrc", Format: "netrc"},
			}},
		}, nil
	}
}

func TestWithUserOverlayEnablesWhatTheSystemLeftOff(t *testing.T) {
	useUserConfig(t, "fuse:\n  enabled: true\n  mountpoint: ~/vault\n")

	cfg, err := withUserOverlay(baseLoaderWithFUSE(config.FUSEConfig{}))()
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	if !cfg.FUSE.Enabled {
		t.Error("the user could not enable the filesystem")
	}
	if cfg.FUSE.Mountpoint != "~/vault" {
		t.Errorf("Mountpoint = %q, want ~/vault", cfg.FUSE.Mountpoint)
	}
}

func TestWithUserOverlayCannotDisableWhatTheSystemTurnedOn(t *testing.T) {
	useUserConfig(t, "fuse:\n  enabled: false\n")

	cfg, err := withUserOverlay(baseLoaderWithFUSE(config.FUSEConfig{Enabled: true}))()
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	if !cfg.FUSE.Enabled {
		t.Error("the user disabled a filesystem the system configuration enables")
	}
}

func TestWithUserOverlayCannotGrantItselfWrites(t *testing.T) {
	useUserConfig(t, "fuse:\n  read_write: true\n")

	cfg, err := withUserOverlay(baseLoaderWithFUSE(config.FUSEConfig{Enabled: true}))()
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	if cfg.FUSE.ReadWrite {
		t.Error("the user granted themselves write access the system configuration withholds")
	}
}

func TestWithUserOverlayMayTightenToReadOnly(t *testing.T) {
	useUserConfig(t, "fuse:\n  read_write: false\n")

	cfg, err := withUserOverlay(baseLoaderWithFUSE(config.FUSEConfig{Enabled: true, ReadWrite: true}))()
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	if cfg.FUSE.ReadWrite {
		t.Error("the user could not opt out of write access")
	}
}

// A user file that cannot be parsed is a startup error naming it, rather than
// a preference silently discarded.
func TestWithUserOverlayRejectsAPolicySection(t *testing.T) {
	useUserConfig(t, "vault:\n  address: https://evil.example.com\n")

	_, err := withUserOverlay(baseLoaderWithFUSE(config.FUSEConfig{}))()
	if err == nil {
		t.Fatal("loader accepted a vault section in the user config")
	}
	if !strings.Contains(err.Error(), "vault") {
		t.Errorf("error = %v, want it to name the rejected section", err)
	}
}

func TestWithUserOverlayRejectsAnInvalidValue(t *testing.T) {
	useUserConfig(t, "fuse:\n  cache_ttl: soon\n")

	_, err := withUserOverlay(baseLoaderWithFUSE(config.FUSEConfig{Enabled: true}))()
	if err == nil {
		t.Fatal("loader accepted an unparseable cache_ttl")
	}
	if !strings.Contains(err.Error(), "cache_ttl") {
		t.Errorf("error = %v, want it to name the offending field", err)
	}
}

// No user file at all is the overwhelmingly common case and must be silent.
func TestWithUserOverlayAbsentFileIsANoop(t *testing.T) {
	prev := userConfigPath
	userConfigPath = func() (string, error) {
		return filepath.Join(t.TempDir(), "absent.yaml"), nil
	}
	t.Cleanup(func() { userConfigPath = prev })

	want := config.FUSEConfig{Enabled: true, Mountpoint: "/srv/policy", ReadWrite: true}
	cfg, err := withUserOverlay(baseLoaderWithFUSE(want))()
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	if cfg.FUSE.Enabled != want.Enabled || cfg.FUSE.ReadWrite != want.ReadWrite || cfg.FUSE.Mountpoint != want.Mountpoint {
		t.Errorf("FUSE = %+v, want %+v untouched", cfg.FUSE, want)
	}
}

// An unresolvable path is not the user's mistake — it just means there is no
// overlay — so it must not stop the daemon starting.
func TestWithUserOverlayUnresolvablePathIsNotFatal(t *testing.T) {
	prev := userConfigPath
	userConfigPath = func() (string, error) { return "", os.ErrNotExist }
	t.Cleanup(func() { userConfigPath = prev })

	cfg, err := withUserOverlay(baseLoaderWithFUSE(config.FUSEConfig{Enabled: true}))()
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	if !cfg.FUSE.Enabled {
		t.Error("the base config was lost when the user config path could not be resolved")
	}
}
