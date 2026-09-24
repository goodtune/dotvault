package peer

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestChainPrefersEarlierTierDespiteRecency is the regression the Chain exists
// for. Both tiers hold a usable token and the *second* tier's socket is the
// fresher one — which is the steady state, not an edge case: the local API
// socket is bound once when the daemon starts, while a forwarded peer socket is
// re-created on every SSH reconnect. A single pool over both sorts by lastSeen
// and would hand back the peer's token, inverting the documented local-first
// borrow order; the tier boundary is what keeps the stable source first.
func TestChainPrefersEarlierTierDespiteRecency(t *testing.T) {
	dir := sockDir(t)
	local := filepath.Join(dir, "api.sock")
	remote := filepath.Join(dir, "peer.sock")
	tokenServer(t, local, "hvs.local", 200)
	tokenServer(t, remote, "hvs.remote", 200)
	now := time.Now()
	setMtime(t, local, now.Add(-time.Hour)) // long-lived daemon socket
	setMtime(t, remote, now)                // forward that just reconnected

	c := NewChain(NewPool([]string{local}), NewPool([]string{remote}))
	tok, src := c.Borrow(context.Background())
	if tok != "hvs.local" || src != local {
		t.Errorf("Borrow = (%q, %q), want the first tier's token from %s", tok, src, local)
	}

	// Sanity check that the fresher socket really would have won without the
	// tier boundary, so this test fails for the right reason if Pool's ordering
	// ever changes underneath it.
	flat := NewPool([]string{local, remote})
	if tok, _ := flat.Borrow(context.Background()); tok != "hvs.remote" {
		t.Fatalf("a flat pool returned %q; this test no longer demonstrates the inversion", tok)
	}
}

// TestChainFallsThroughEmptyTier: a tier with nothing present must not be
// terminal — the whole point of the peer tier is to answer when the local
// daemon is not running.
func TestChainFallsThroughEmptyTier(t *testing.T) {
	dir := sockDir(t)
	remote := filepath.Join(dir, "peer.sock")
	tokenServer(t, remote, "hvs.remote", 200)

	c := NewChain(
		NewPool([]string{filepath.Join(dir, "absent.sock")}),
		NewPool([]string{remote}),
	)
	tok, src := c.Borrow(context.Background())
	if tok != "hvs.remote" || src != remote {
		t.Errorf("Borrow = (%q, %q), want the peer tier's token from %s", tok, src, remote)
	}
}

// TestChainFallsThroughUnauthenticatedTier is the same fall-through for a tier
// that is alive but holds no token: a local daemon still waiting to authenticate
// answers 401, and the peer behind it is then the correct source.
func TestChainFallsThroughUnauthenticatedTier(t *testing.T) {
	dir := sockDir(t)
	local := filepath.Join(dir, "api.sock")
	remote := filepath.Join(dir, "peer.sock")
	tokenServer(t, local, "", 200) // 401: serving, but holds no token
	tokenServer(t, remote, "hvs.remote", 200)

	c := NewChain(NewPool([]string{local}), NewPool([]string{remote}))
	tok, src := c.Borrow(context.Background())
	if tok != "hvs.remote" || src != remote {
		t.Errorf("Borrow = (%q, %q), want the peer tier's token from %s", tok, src, remote)
	}
}

// TestChainStatusReportsTiersInOrder pins the diagnostic surface `dotvault
// status` renders, including that a tier the caller had no config for is absent
// rather than reported as an empty one.
func TestChainStatusReportsTiersInOrder(t *testing.T) {
	dir := sockDir(t)
	local := filepath.Join(dir, "api.sock")
	remote := filepath.Join(dir, "peer.sock")
	tokenServer(t, local, "hvs.local", 200)
	tokenServer(t, remote, "hvs.remote", 200)

	var absent *Pool // what a caller with no local socket configured passes
	c := NewChain(absent, NewPool([]string{local}), NewPool([]string{remote}))
	st := c.Status()
	if len(st) != 2 {
		t.Fatalf("Status() returned %d tiers, want 2 (the nil pool skipped)", len(st))
	}
	if len(st[0].Patterns) != 1 || st[0].Patterns[0] != local {
		t.Errorf("tier 0 patterns = %v, want [%s]", st[0].Patterns, local)
	}
	if len(st[1].Patterns) != 1 || st[1].Patterns[0] != remote {
		t.Errorf("tier 1 patterns = %v, want [%s]", st[1].Patterns, remote)
	}
	if len(st[0].Members) != 1 || st[0].Members[0].Path != local {
		t.Errorf("tier 0 members = %+v, want the local socket", st[0].Members)
	}
}

// TestNewLocalFirstChain covers the shared constructor both call sites use
// (cmd/dotvault newBorrowChain, client VaultConfig.borrower): the local socket
// wins even when the peer's is fresher, and an empty local contributes no tier
// at all rather than an empty leading one — which is what keeps Status()'s tiers
// aligned with the labels a caller derives from the same two inputs.
func TestNewLocalFirstChain(t *testing.T) {
	dir := sockDir(t)
	local := filepath.Join(dir, "api.sock")
	remote := filepath.Join(dir, "peer.sock")
	tokenServer(t, local, "hvs.local", 200)
	tokenServer(t, remote, "hvs.remote", 200)
	now := time.Now()
	setMtime(t, local, now.Add(-time.Hour)) // long-lived daemon socket
	setMtime(t, remote, now)                // forward that just reconnected

	c := NewLocalFirstChain(local, []string{remote})
	if tok, src := c.Borrow(context.Background()); tok != "hvs.local" || src != local {
		t.Errorf("Borrow = (%q, %q), want the local socket's token", tok, src)
	}
	if st := c.Status(); len(st) != 2 {
		t.Errorf("Status() = %d tiers, want 2", len(st))
	}

	// No local socket configured: one tier, the peers.
	c = NewLocalFirstChain("", []string{remote})
	if tok, src := c.Borrow(context.Background()); tok != "hvs.remote" || src != remote {
		t.Errorf("Borrow = (%q, %q), want the peer's token", tok, src)
	}
	st := c.Status()
	if len(st) != 1 {
		t.Fatalf("Status() = %d tiers, want 1 (no local tier)", len(st))
	}
	if len(st[0].Patterns) != 1 || st[0].Patterns[0] != remote {
		t.Errorf("tier 0 patterns = %v, want [%s]", st[0].Patterns, remote)
	}

	// Neither configured: a chain that borrows nothing, not a panic.
	if tok, _ := NewLocalFirstChain("", nil).Borrow(context.Background()); tok != "" {
		t.Errorf("an unconfigured chain borrowed %q", tok)
	}
	if st := NewLocalFirstChain("", nil).Status(); len(st) != 0 {
		t.Errorf("an unconfigured chain reported %d tiers", len(st))
	}
}

// TestChainNilReceiver: every method is nil-safe, so a call site with no chain
// wired needs no branch — the same contract Pool holds.
func TestChainNilReceiver(t *testing.T) {
	var c *Chain
	if tok, src := c.Borrow(context.Background()); tok != "" || src != "" {
		t.Errorf("nil Chain Borrow = (%q, %q), want empty", tok, src)
	}
	if st := c.Status(); st != nil {
		t.Errorf("nil Chain Status = %v, want nil", st)
	}
	// An empty chain (every tier unconfigured) behaves the same.
	if tok, _ := NewChain().Borrow(context.Background()); tok != "" {
		t.Errorf("empty Chain borrowed %q", tok)
	}
	if tok, _ := NewChain(nil, nil).Borrow(context.Background()); tok != "" {
		t.Errorf("all-nil Chain borrowed %q", tok)
	}
}
