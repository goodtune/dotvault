package main

import (
	"runtime"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

func TestResolveFUSEMountpointDisabled(t *testing.T) {
	cfg := &config.Config{}
	if got := resolveFUSEMountpoint(cfg); got != "" {
		t.Errorf("resolveFUSEMountpoint() = %q, want empty when the section is disabled", got)
	}
}

func TestResolveFUSEMountpointEnabled(t *testing.T) {
	cfg := &config.Config{FUSE: config.FUSEConfig{Enabled: true, Mountpoint: "/srv/secrets"}}
	got := resolveFUSEMountpoint(cfg)
	if runtime.GOOS == "windows" {
		// Enabling it on Windows warns and mounts nothing rather than
		// failing the daemon: one config is shared across a mixed fleet.
		if got != "" {
			t.Errorf("resolveFUSEMountpoint() = %q on windows, want empty", got)
		}
		return
	}
	if got != "/srv/secrets" {
		t.Errorf("resolveFUSEMountpoint() = %q, want /srv/secrets", got)
	}
}

func TestResolveFUSEMountpointExpandsHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no filesystem surface on windows")
	}
	cfg := &config.Config{FUSE: config.FUSEConfig{Enabled: true}}
	got := resolveFUSEMountpoint(cfg)
	if got == "" || strings.HasPrefix(got, "~") {
		t.Errorf("resolveFUSEMountpoint() = %q, want the default expanded to an absolute path", got)
	}
}

func TestFUSEAccessMode(t *testing.T) {
	if got := fuseAccessMode(false); got != "read-only" {
		t.Errorf("fuseAccessMode(false) = %q, want read-only", got)
	}
	if got := fuseAccessMode(true); got != "read-write" {
		t.Errorf("fuseAccessMode(true) = %q, want read-write", got)
	}
}

// startFUSE must never take the daemon down. A store it cannot build (no
// username here) has to resolve to "no filesystem" rather than an error the
// caller is obliged to handle.
func TestStartFUSEIsNeverFatal(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{KVMount: "kv", UserPrefix: "users/"},
		FUSE:  config.FUSEConfig{Enabled: true, Mountpoint: "/nonexistent/definitely/not/writable"},
	}
	if svc := startFUSE(t.Context(), cfg, nil, ""); svc != nil {
		t.Error("startFUSE returned a service for an unbuildable store")
	}
}
