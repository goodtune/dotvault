package config

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/goodtune/dotvault/internal/paths"
)

// apiSocketCandidate returns the configured local API socket path — the
// operator's literal value, or the per-user runtime default when unset —
// without expanding a leading ~. It returns "" whenever no socket will exist:
// the section is disabled, or the platform has no local API socket at all.
//
// Windows is gated here rather than only at the daemon's bind site so that
// *every* consumer agrees. A path resolved on Windows would name a socket
// nothing ever binds, which would put a permanently dead candidate in every
// borrow list and make `dotvault status` report a socket as merely "not
// present (daemon not running?)" when in fact it can never appear.
//
// Defaulting happens here rather than at config-load time so an exported
// config round-trips the operator's literal value ("" means "use the
// default") instead of baking in one machine's runtime directory.
func (c *Config) apiSocketCandidate() string {
	if !c.API.Enabled || runtime.GOOS == "windows" {
		return ""
	}
	if p := c.API.Unix.Path; p != "" {
		return p
	}
	return paths.DefaultAPISocket()
}

// APISocketPath resolves the local API socket path the daemon should bind,
// with a leading ~ expanded. It returns "" when no local API socket applies
// (disabled, or an unsupported platform), so callers can treat "no path" and
// "not enabled" identically.
func (c *Config) APISocketPath() (string, error) {
	p := c.apiSocketCandidate()
	if p == "" {
		return "", nil
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
	if p := c.apiSocketCandidate(); p != "" {
		out = append(out, p)
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
