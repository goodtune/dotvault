//go:build windows

package agent

import (
	"log/slog"
	"os"
	"strings"
)

// pipePrefix is the named-pipe namespace root. Reading it enumerates every
// pipe currently open on the machine, which is how existence is tested here:
// os.Stat on a pipe path opens it, and opening a byte-mode agent pipe is a
// connection the agent must then service.
const pipePrefix = `\\.\pipe\`

// candidateEndpoints returns the named pipes that look like an SSH agent this
// user can talk to, most-preferred first, filtered to those that currently
// exist.
//
// Windows deliberately enumerates a short fixed list rather than pattern-
// matching the pipe namespace the way the Unix side globs /tmp. A named pipe
// carries no owning uid a caller can read without opening it and querying its
// security descriptor, so "which pipes are mine" is not a question the
// namespace answers cheaply — and dotvault forwards mutations upstream, so a
// pipe squatted by another user would receive a client's private key on
// `ssh-add`. The two names below are the ones whose access is already
// constrained by construction: the OpenSSH agent service's well-known pipe,
// and the Pageant convention whose name embeds a per-user, per-boot hash that
// another session cannot derive.
func candidateEndpoints() []string {
	var raw []string

	// SSH_AUTH_SOCK carries a pipe name on Windows when it is set at all
	// (Git-for-Windows and WSL interop both do this).
	if s := os.Getenv("SSH_AUTH_SOCK"); s != "" {
		raw = append(raw, s)
	}
	raw = append(raw, defaultWindowsUpstreamPipe)
	if name, err := pageantPipeName(); err == nil && name != "" {
		raw = append(raw, name)
	}

	existing := existingPipes()
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, p := range raw {
		key := strings.ToLower(p)
		if seen[key] || !existing[strings.ToLower(pipeLeafName(p))] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

// existingPipes returns the set of currently-open pipe names, lower-cased.
// Reading the pipe namespace lists names without opening any of them, so an
// agent is never handed a connection just to answer "are you there".
func existingPipes() map[string]bool {
	entries, err := os.ReadDir(pipePrefix)
	if err != nil {
		// Auto-detection finds nothing without this listing, which is a
		// degradation worth a trace rather than a silent "no agents running".
		slog.Debug("ssh agent: cannot enumerate the named-pipe namespace for upstream detection", "error", err)
		return nil
	}
	set := make(map[string]bool, len(entries))
	for _, e := range entries {
		set[strings.ToLower(e.Name())] = true
	}
	return set
}

// pipeLeafName strips the \\.\pipe\ prefix from a pipe path, leaving the name
// as it appears in the namespace listing.
func pipeLeafName(p string) string {
	trimmed := strings.TrimPrefix(strings.ReplaceAll(p, "/", `\`), pipePrefix)
	return strings.TrimPrefix(trimmed, `\`)
}

// resolveEndpointPath has nothing to resolve on Windows: a pipe name is not a
// filesystem path and carries no symlinks. It returns "" so discovery falls
// back to the lower-cased name comparison normalizeEndpoint already performs.
// The unused parameter keeps the signature identical to the Unix build.
func resolveEndpointPath(string) string { return "" }
