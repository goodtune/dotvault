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
		Vault: config.VaultConfig{TokenSockets: config.SocketList{"/home/u/.ssh/dotvault.sock"}},
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
		API:   config.APIConfig{Enabled: true, Unix: config.APIUnixConfig{Path: "~/dotvault/api.sock"}},
		Vault: config.VaultConfig{TokenSockets: config.SocketList{}}, // explicit "no peer sockets"; nil would apply the defaults
	}
	own := filepath.Join(home, "dotvault", "api.sock")

	if got := daemonBorrowSockets(cfg, own); len(got) != 0 {
		t.Errorf("daemonBorrowSockets = %v, want empty (own socket excluded)", got)
	}
}

// TestDaemonBorrowSocketsWithoutOwnSocket: with the local socket disabled the
// list is unchanged, so an existing deployment behaves exactly as before.
func TestDaemonBorrowSocketsWithoutOwnSocket(t *testing.T) {
	cfg := &config.Config{Vault: config.VaultConfig{TokenSockets: config.SocketList{"~/.ssh/dotvault.sock"}}}
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

// TestFreshLoginBorrowSocketsExcludesLocal: `dotvault login` exists to run the
// configured fresh-auth flow and ignore any cached token. The local API
// socket is a cache of the token this host already holds, so borrowing from
// it would make the command a silent no-op — the user asks to
// re-authenticate and gets the same token back. A peer socket is different in
// kind (a separate authentication authority where a human actually logged in)
// and stays.
func TestFreshLoginBorrowSocketsExcludesLocal(t *testing.T) {
	cfg := &config.Config{
		API:   config.APIConfig{Enabled: true, Unix: config.APIUnixConfig{Path: "/run/dotvault/api.sock"}},
		Vault: config.VaultConfig{TokenSockets: config.SocketList{"/home/u/.ssh/dotvault.sock"}},
	}
	got := freshLoginBorrowSockets(cfg)
	want := []string{"/home/u/.ssh/dotvault.sock"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("freshLoginBorrowSockets = %v, want %v", got, want)
	}
}

// TestFreshLoginBorrowSocketsKeepsPeerOnly confirms the ordinary headless
// deployment (no local socket) is untouched by that exclusion.
func TestFreshLoginBorrowSocketsKeepsPeerOnly(t *testing.T) {
	cfg := &config.Config{Vault: config.VaultConfig{TokenSockets: config.SocketList{"~/.ssh/dotvault.sock"}}}
	got := freshLoginBorrowSockets(cfg)
	want := []string{"~/.ssh/dotvault.sock"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("freshLoginBorrowSockets = %v, want %v", got, want)
	}
}

// TestNewPeerPoolNilWhenNoPatterns pins the property every call site leans on:
// with nothing configured there is no pool, and a nil *peer.Pool is
// nil-receiver safe throughout — so `Borrower: newPeerPool(...)` stays correct
// for an operator who has configured no peers at all, with no branch at the
// wiring site.
func TestNewPeerPoolNilWhenNoPatterns(t *testing.T) {
	if got := newPeerPool(nil); got != nil {
		t.Errorf("newPeerPool(nil) = %v, want nil", got)
	}
	if got := newPeerPool([]string{}); got != nil {
		t.Errorf("newPeerPool(empty) = %v, want nil", got)
	}
	pool := newPeerPool([]string{"/run/dotvault/api.sock"})
	if pool == nil {
		t.Fatal("newPeerPool returned nil for a non-empty pattern list")
	}
	if got := pool.Patterns(); !reflect.DeepEqual(got, []string{"/run/dotvault/api.sock"}) {
		t.Errorf("Patterns() = %v, want the configured pattern", got)
	}
}

// TestNewBorrowChainTiers pins the local-first borrow order for the one-shot
// commands that may borrow from this host's own daemon. The tiers, not a sort
// key, are what carry it: the local socket is bound once when the long-lived
// daemon starts while a forwarded peer socket is re-created on every SSH
// reconnect, so a single pool over both would order the peer first by recency.
func TestNewBorrowChainTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no local API socket on windows; apiSocketCandidate gates it")
	}
	cfg := &config.Config{
		API:   config.APIConfig{Enabled: true, Unix: config.APIUnixConfig{Path: "/run/dotvault/api.sock"}},
		Vault: config.VaultConfig{TokenSockets: config.SocketList{"/home/u/.ssh/dotvault.*.sock"}},
	}
	tiers := newBorrowChain(cfg).Status()
	if len(tiers) != 2 {
		t.Fatalf("Status() = %d tiers, want 2 (local API socket, then peers)", len(tiers))
	}
	if got := tiers[0].Patterns; !reflect.DeepEqual(got, []string{"/run/dotvault/api.sock"}) {
		t.Errorf("tier 0 = %v, want the local API socket first", got)
	}
	if got := tiers[1].Patterns; !reflect.DeepEqual(got, []string{"/home/u/.ssh/dotvault.*.sock"}) {
		t.Errorf("tier 1 = %v, want the peer pattern", got)
	}
}

// TestNewBorrowChainWithoutLocalSocket: with the local socket disabled the
// chain is the peer tier alone — not an empty tier reported as "none present",
// which would have an operator looking for a socket that can never exist.
func TestNewBorrowChainWithoutLocalSocket(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{TokenSockets: config.SocketList{"/home/u/.ssh/dotvault.sock"}},
	}
	tiers := newBorrowChain(cfg).Status()
	if len(tiers) != 1 {
		t.Fatalf("Status() = %d tiers, want 1 (peers only)", len(tiers))
	}
	if got := tiers[0].Patterns; !reflect.DeepEqual(got, []string{"/home/u/.ssh/dotvault.sock"}) {
		t.Errorf("tier 0 = %v, want the peer socket", got)
	}
}
