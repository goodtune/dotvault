package main

import (
	"log/slog"
	"runtime"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/paths"
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
	if !cfg.API.Enabled {
		return ""
	}
	if runtime.GOOS == "windows" {
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

// daemonBorrowSockets returns the ordered peer sockets the *daemon* should
// borrow a token from, which is config.TokenBorrowSockets minus the daemon's
// own local API socket.
//
// Serving a socket and borrowing from it are opposite ends of the same wire:
// a daemon that borrowed from itself would either hand back the token it
// already has (a no-op that muddies the logs about where a token came from)
// or, before it has authenticated, dial its own listener and get a 401 for
// its trouble. Clients on the same machine keep the full list — borrowing
// from this daemon is exactly what the socket is for.
func daemonBorrowSockets(cfg *config.Config, ownSocket string) []string {
	all := cfg.TokenBorrowSockets()
	if ownSocket == "" {
		return all
	}
	out := make([]string, 0, len(all))
	for _, p := range all {
		// Compare expanded forms: the configured value may be ~-relative
		// while ownSocket is always absolute.
		if expanded, err := paths.ExpandHome(p); err == nil && expanded == ownSocket {
			continue
		}
		out = append(out, p)
	}
	return out
}
