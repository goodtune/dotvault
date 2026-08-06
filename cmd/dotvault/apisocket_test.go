package main

import (
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// TestDaemonBorrowSocketsExcludesOwn: the daemon serves the local API socket,
// so it must not appear in the daemon's own borrow list. Borrowing from
// itself would either return the token it already holds — muddying the log
// line that says where a token came from — or, before it has authenticated,
// dial its own listener for a 401.
func TestDaemonBorrowSocketsExcludesOwn(t *testing.T) {
	cfg := &config.Config{
		API:   config.APIConfig{Enabled: true, Unix: config.APIUnixConfig{Path: "/run/dotvault/api.sock"}},
		Vault: config.VaultConfig{TokenSocket: "/home/u/.ssh/dotvault.sock"},
	}

	got := daemonBorrowSockets(cfg, "/run/dotvault/api.sock")
	want := []string{"/home/u/.ssh/dotvault.sock"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("daemonBorrowSockets = %v, want %v", got, want)
	}

	// A client on the same host keeps the full list — borrowing from this
	// daemon is exactly what the socket is for.
	if full := cfg.TokenBorrowSockets(); len(full) != 2 {
		t.Errorf("client borrow list = %v, want both sockets", full)
	}
}

// TestDaemonBorrowSocketsMatchesTildePath covers the comparison detail: the
// configured value may be ~-relative while the resolved own-socket path is
// always absolute, and a mismatch there would silently reinstate the
// self-borrow.
func TestDaemonBorrowSocketsMatchesTildePath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}

	cfg := &config.Config{
		API: config.APIConfig{Enabled: true, Unix: config.APIUnixConfig{Path: "~/dotvault/api.sock"}},
	}
	own := filepath.Join(home, "dotvault", "api.sock")

	if got := daemonBorrowSockets(cfg, own); len(got) != 0 {
		t.Errorf("daemonBorrowSockets = %v, want empty (own socket excluded)", got)
	}
}

// TestDaemonBorrowSocketsWithoutOwnSocket: with the local socket disabled the
// list is unchanged, so an existing deployment behaves exactly as before.
func TestDaemonBorrowSocketsWithoutOwnSocket(t *testing.T) {
	cfg := &config.Config{Vault: config.VaultConfig{TokenSocket: "~/.ssh/dotvault.sock"}}
	got := daemonBorrowSockets(cfg, "")
	want := []string{"~/.ssh/dotvault.sock"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("daemonBorrowSockets = %v, want %v", got, want)
	}
}

// TestResolveAPISocketDisabled: the resolver is the single gate on whether a
// socket is bound at all.
func TestResolveAPISocketDisabled(t *testing.T) {
	cfg := &config.Config{API: config.APIConfig{Unix: config.APIUnixConfig{Path: "/run/dotvault/api.sock"}}}
	if got := resolveAPISocket(cfg); got != "" {
		t.Errorf("resolveAPISocket = %q, want empty when api.enabled is false", got)
	}
}

func TestResolveAPISocketEnabled(t *testing.T) {
	cfg := &config.Config{API: config.APIConfig{Enabled: true, Unix: config.APIUnixConfig{Path: "/run/dotvault/api.sock"}}}
	got := resolveAPISocket(cfg)
	if runtime.GOOS == "windows" {
		// Not supported there yet: warn and serve nothing rather than
		// failing a config shared across a mixed-platform fleet.
		if got != "" {
			t.Errorf("resolveAPISocket = %q on windows, want empty", got)
		}
		return
	}
	if got != "/run/dotvault/api.sock" {
		t.Errorf("resolveAPISocket = %q, want /run/dotvault/api.sock", got)
	}
}
