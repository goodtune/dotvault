package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/goodtune/dotvault/internal/paths"
)

// APISocketPath resolves the local API socket path the daemon should bind,
// with a leading ~ expanded. It returns "" when the local API socket is
// disabled, so callers can treat "no path" and "not enabled" identically.
//
// An unset api.unix.path resolves to the per-user runtime default. Resolution
// happens here rather than at config-load time so an exported config
// round-trips the operator's literal value ("" means "use the default")
// instead of baking in one machine's runtime directory.
func (c *Config) APISocketPath() (string, error) {
	if !c.API.Enabled {
		return "", nil
	}
	p := c.API.Unix.Path
	if p == "" {
		p = paths.DefaultAPISocket()
	}
	expanded, err := paths.ExpandHome(p)
	if err != nil {
		return "", fmt.Errorf("api.unix.path %q: %w", p, err)
	}
	return expanded, nil
}

// TokenBorrowSockets returns the ordered list of peer dotvault sockets a
// client should try when borrowing a Vault token, most-stable first.
//
// The local API socket comes first deliberately. Both sockets speak the same
// endpoint, but they differ in how long they survive: the local socket is
// served by the long-lived per-user daemon and outlives any SSH session,
// while vault.token_socket is typically an SSH RemoteForward that disappears
// the moment the connection drops. Preferring the local one means a process
// started inside an SSH session keeps borrowing successfully after that
// session ends — the whole point of the local socket.
//
// Paths are returned unexpanded; FetchTokenFromSocket expands a leading ~ at
// fetch time.
//
// This is the borrow direction only. It is NOT the right order for the peer
// actions (browse / notify / clipboard), which must reach the workstation
// where a human is looking — posting those to the local daemon would open a
// browser on the headless host nobody is sitting at. Those keep using
// vault.token_socket directly.
func (c *Config) TokenBorrowSockets() []string {
	var out []string
	if c.API.Enabled {
		// The literal configured value (or "" for the default) is resolved
		// here rather than reusing APISocketPath so a home-directory failure
		// degrades to "no local candidate" instead of failing the borrow —
		// borrowing is best-effort at every call site.
		p := c.API.Unix.Path
		if p == "" {
			p = paths.DefaultAPISocket()
		}
		if p != "" {
			out = append(out, p)
		}
	}
	if c.Vault.TokenSocket != "" {
		out = append(out, c.Vault.TokenSocket)
	}
	return out
}

// validateAPI checks the local API socket section. The only genuine footgun
// is a relative path: it would be resolved against the daemon's working
// directory, so the daemon and a client started from a different directory
// would silently disagree about where the socket is.
func (c *Config) validateAPI() error {
	p := c.API.Unix.Path
	if p == "" {
		return nil
	}
	if strings.HasPrefix(p, "~") {
		// Expanded at bind/fetch time into an absolute home-relative path.
		return nil
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("api.unix.path %q: must be an absolute path (or ~-relative)", p)
	}
	return nil
}
