package main

import (
	"log/slog"
	"runtime"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/peer"
)

// resolveAPISocket returns the path the daemon should bind for the local API
// socket, or "" when it should serve none.
//
// Enabling the socket on Windows warns and serves nothing rather than failing
// the daemon: a fleet shares one config across platforms, and a Windows host
// that has no use for the setting should not refuse to start because of it.
// The Windows analogue (a named pipe with a protected DACL, as the SSH agent
// already serves) is not implemented yet.
func resolveAPISocket(cfg *config.Config) string {
	if cfg.API.Enabled && runtime.GOOS == "windows" {
		// config.APISocketPath already returns "" here — this only surfaces
		// *why* to an operator who set the flag and expects a socket.
		slog.Warn("api.enabled is set but the local API socket is not supported on windows; ignoring")
		return ""
	}
	path, err := cfg.APISocketPath()
	if err != nil {
		slog.Warn("could not resolve api.unix.path; local API socket disabled", "error", err)
		return ""
	}
	return path
}

// borrowSocketsExcluding returns config.TokenBorrowSockets with one path
// removed. Comparison is on expanded forms, since a configured value may be
// ~-relative while a resolved path is always absolute.
func borrowSocketsExcluding(cfg *config.Config, exclude string) []string {
	all := cfg.TokenBorrowSockets()
	if exclude == "" {
		return all
	}
	out := make([]string, 0, len(all))
	for _, p := range all {
		if expanded, err := paths.ExpandHome(p); err == nil && expanded == exclude {
			continue
		}
		out = append(out, p)
	}
	return out
}

// daemonBorrowSockets returns the ordered peer sockets the *daemon* should
// borrow a token from: everything except the socket it serves itself.
//
// Serving a socket and borrowing from it are opposite ends of the same wire.
// A daemon that borrowed from itself would either hand back the token it
// already has — a no-op that muddies the log line saying where a token came
// from — or, before it has authenticated, dial its own listener and get a 401
// for its trouble. Clients on the same machine keep the full list; borrowing
// from this daemon is exactly what the socket is for.
func daemonBorrowSockets(cfg *config.Config, ownSocket string) []string {
	return borrowSocketsExcluding(cfg, ownSocket)
}

// freshLoginBorrowSockets returns the sockets `dotvault login` may borrow
// from: everything except the local daemon's own socket.
//
// `dotvault login` exists to run the configured fresh-auth flow and ignore
// any cached token. The local API socket is precisely a cache of the token
// this host already holds, so borrowing from it would make the command a
// silent no-op — the user asks to re-authenticate and gets back the same
// token the daemon was already serving. A *peer* socket is different in kind:
// the workstation at the far end is a separate authentication authority where
// a human really did log in, so that borrow stays (it predates the local
// socket and is the documented headless path).
func freshLoginBorrowSockets(cfg *config.Config) []string {
	local, err := cfg.APISocketPath()
	if err != nil {
		// Unresolvable means we cannot identify our own socket to exclude.
		// Borrow from everything rather than nothing: a login that reuses a
		// local token is a lesser failure than one that cannot proceed.
		local = ""
	}
	return borrowSocketsExcluding(cfg, local)
}

// newPeerPool builds a transient pool — resolve on demand, no watcher — for
// one-shot commands and the daemon's startup. It returns nil for an empty
// pattern list, which every consumer handles: *peer.Pool is nil-receiver safe,
// so a caller with nothing configured needs no branch.
func newPeerPool(patterns []string, opts ...peer.Option) *peer.Pool {
	if len(patterns) == 0 {
		return nil
	}
	return peer.NewPool(patterns, opts...)
}

// newBorrowChain builds the two-tier borrower the one-shot commands that may
// borrow from this host's own daemon use — `status`, `sync`, `enrol`: the local
// API socket first, then the peers. peer.NewLocalFirstChain owns the tiering and
// the reason it is a tier rather than an ordering hint; this resolves the two
// socket sources and labels the tiers.
//
// The daemon (daemonBorrowSockets) and `dotvault login`
// (freshLoginBorrowSockets) deliberately do NOT use this: both exclude the local
// socket outright, so their lists are peers-only and a single pool is already
// the whole story.
//
// It returns the tier labels alongside the chain, in the same order
// Chain.Status() reports them, so `dotvault status` can say which tier a
// pattern belongs to. They are derived from the same two inputs the chain is
// built from — a non-empty local socket, a non-empty pattern list — so the
// label list and the tier list cannot disagree about which tiers exist.
func newBorrowChain(cfg *config.Config) (*peer.Chain, []string) {
	local, err := cfg.APISocketPath()
	if err != nil {
		// Not fatal — the peers are still borrowable — but silently dropping
		// the tier would leave an operator with a misconfigured api.unix.path
		// wondering why the local daemon is never consulted.
		slog.Warn("could not resolve api.unix.path; local API socket excluded from borrow", "error", err)
		local = ""
	}
	peers := cfg.PeerActionSockets()

	var labels []string
	if local != "" {
		labels = append(labels, borrowTierLocalAPI)
	}
	if len(peers) > 0 {
		labels = append(labels, borrowTierPeers)
	}
	return peer.NewLocalFirstChain(local, peers), labels
}

// borrowTierLocalAPI and borrowTierPeers label the two tiers newBorrowChain
// builds. They are distinct because the tiers answer different questions: the
// first is this host's own daemon, the second the workstations forwarding to
// it, and one shared label made a `dotvault status` listing read as though the
// local socket were just another peer pattern.
const (
	borrowTierLocalAPI = "local API socket"
	borrowTierPeers    = "peer socket pattern"
)

// authBorrowChain is newBorrowChain for the callers that want the borrower
// alone — the auth.Manager wiring, which has no status listing to label.
func authBorrowChain(cfg *config.Config) *peer.Chain {
	chain, _ := newBorrowChain(cfg)
	return chain
}
