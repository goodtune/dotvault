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
// matching the pipe namespace the way the Unix side globs /tmp, because a
// named pipe carries no owning uid a caller can read without opening it and
// querying its security descriptor — so "which pipes are mine" is not a
// question the namespace answers, and peerUID has no implementation here.
//
// Be precise about what that leaves, since mutations are forwarded and a
// squatted pipe would receive a client's private key on `ssh-add`: the two
// well-known names below are NOT tamper-proof. Windows named pipes are
// first-creator-wins, so a local user who creates \\.\pipe\openssh-ssh-agent
// before the OpenSSH agent service starts owns that name for the boot, and the
// Pageant name's per-boot hash comes from CryptProtectMemory with
// CROSS_PROCESS, which any process on the machine can reverse. What can be
// said is narrower and still worth saying: this is exactly the trust model
// Windows OpenSSH's own ssh.exe and every PuTTY client already operate under
// when they dial these same names, so dotvault is not widening the exposure a
// user already has — it is inheriting it. $SSH_AUTH_SOCK is different in kind
// and safer: it comes from this daemon's own environment, which is as trusted
// as its config. The residual risk is documented in docs/guide/ssh-agent.md.
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

	// An enumeration failure must not read as "no agents are running": that
	// would silently disable detection wholesale, including for an endpoint
	// named explicitly by $SSH_AUTH_SOCK. When the namespace cannot be listed,
	// skip the existence filter and let the dial decide — a pipe that is not
	// there fails to open, which is the same answer one round trip later.
	existing, enumerated := existingPipes()
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, p := range raw {
		// Canonicalise before both the dedupe and the emit. The leaf is the
		// pipe's actual identity: \\.\pipe\x, //./pipe/x and a bare "x" all
		// name one pipe, so deduplicating on the raw string let equivalent
		// spellings through as separate endpoints — and emitting the raw
		// string could hand dialEndpoint a bare leaf name it cannot open,
		// which is reachable because $SSH_AUTH_SOCK is whatever the
		// environment says it is.
		leaf := pipeLeafName(p)
		if leaf == "" || seen[leaf] {
			continue
		}
		if enumerated && !existing[leaf] {
			continue
		}
		seen[leaf] = true
		out = append(out, pipePrefix+leaf)
	}
	return out
}

// existingPipes returns the set of currently-open pipe names, lower-cased.
// Reading the pipe namespace lists names without opening any of them, so an
// agent is never handed a connection just to answer "are you there".
//
// ok reports whether the listing succeeded; the caller must not treat an empty
// set from a failed listing as "nothing is running".
func existingPipes() (names map[string]bool, ok bool) {
	entries, err := os.ReadDir(pipePrefix)
	if err != nil {
		slog.Debug("ssh agent: cannot enumerate the named-pipe namespace; falling back to dialling each candidate", "error", err)
		return nil, false
	}
	set := make(map[string]bool, len(entries))
	for _, e := range entries {
		set[strings.ToLower(e.Name())] = true
	}
	return set, true
}

// pipeLeafName strips the \\.\pipe\ prefix from a pipe path and lower-cases the
// result, so it can be compared against the (also lower-cased) namespace
// listing. Case folding happens before the trim as well as after: the pipe
// namespace is case-insensitive, so \\.\Pipe\x names the same pipe as
// \\.\pipe\x and a case-sensitive prefix trim would drop the candidate.
func pipeLeafName(p string) string {
	lowered := strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	return strings.TrimPrefix(strings.TrimPrefix(lowered, pipePrefix), `\`)
}

// resolveEndpointPath has nothing to resolve on Windows: a pipe name is not a
// filesystem path and carries no symlinks. It returns "" so discovery falls
// back to the lower-cased name comparison normalizeEndpoint already performs.
// The unused parameter keeps the signature identical to the Unix build.
func resolveEndpointPath(string) string { return "" }
