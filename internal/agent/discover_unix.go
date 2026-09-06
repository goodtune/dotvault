//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/goodtune/dotvault/internal/paths"
)

// candidateEndpoints returns the Unix-domain sockets on this machine that look
// like an SSH agent this user owns, most-preferred first and already filtered
// to those that exist, are sockets, and belong to the running uid.
//
// The order is the priority order an upstream fan-out uses, and it is not
// arbitrary: $SSH_AUTH_SOCK comes first because it is the agent the user's own
// tooling is already talking to, which makes it the right target for a
// forwarded `ssh-add` (see upstreamSource.Add). Everything after it is a
// well-known location for an agent the user may be running without having
// exported it into this daemon's environment — a per-user systemd unit, a
// keyring daemon, gpg-agent's SSH surface, a password manager's agent, or a
// plain `ssh-agent` fork's temp directory.
//
// Locations rather than a filesystem sweep: scanning for sockets would be both
// slow and unsafe, since "some socket, somewhere, that speaks the agent
// protocol" is not a thing to hand a private key to. Every path below is one a
// known agent implementation documents.
func candidateEndpoints() []string {
	var raw []string

	// The agent this user's shell is already using. May well be dotvault
	// itself once the shadowing is set up — discoverUpstreamEndpoints drops
	// that case by path and by the IDExtension probe.
	if s := os.Getenv("SSH_AUTH_SOCK"); s != "" {
		raw = append(raw, s)
	}

	for _, dir := range runtimeDirs() {
		raw = append(raw,
			// systemd --user ssh-agent.service, and dotvault's own default
			// upstream location.
			filepath.Join(dir, "ssh-agent.socket"),
			// gcr-ssh-agent (GNOME 42+) and the older gnome-keyring surface.
			filepath.Join(dir, "gcr", "ssh"),
			filepath.Join(dir, "keyring", "ssh"),
			// gpg-agent with enable-ssh-support.
			filepath.Join(dir, "gnupg", "S.gpg-agent.ssh"),
		)
	}

	if home, err := os.UserHomeDir(); err == nil {
		raw = append(raw,
			filepath.Join(home, ".gnupg", "S.gpg-agent.ssh"),
			// 1Password's SSH agent (Linux path).
			filepath.Join(home, ".1password", "agent.sock"),
		)
		if runtime.GOOS == "darwin" {
			raw = append(raw,
				// 1Password (macOS) and Secretive, both Secure-Enclave-backed
				// agents a Mac user plausibly already has running.
				filepath.Join(home, "Library", "Group Containers", "2BUA8C4S2C.com.1password", "t", "agent.sock"),
				filepath.Join(home, "Library", "Containers", "com.maxgoedjen.Secretive.SecretAgent", "Data", "socket.ssh"),
			)
		}
	}

	for _, pattern := range tempAgentGlobs() {
		raw = append(raw, glob(pattern)...)
	}

	out := make([]string, 0, len(raw))
	for _, p := range raw {
		if ownedAgentSocket(p) {
			out = append(out, p)
		}
	}
	return out
}

// runtimeDirs returns the per-user runtime directories to look under:
// $XDG_RUNTIME_DIR when set, plus /run/user/<uid> on Linux (deduplicated, so
// the usual case where they are the same yields one entry).
//
// /run/user/<uid> is added whether or not XDG_RUNTIME_DIR is set, not merely
// as a fallback for when it is missing: a daemon started outside a login
// session (a systemd system unit, a cron job, an SSH command invocation) may
// have no XDG_RUNTIME_DIR at all, and one started with the variable pointing
// somewhere else entirely would otherwise never look where the agent actually
// is. Both are cases where auto-detection earns its keep over a configured
// path, so both are covered.
func runtimeDirs() []string {
	var dirs []string
	if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
		dirs = append(dirs, rt)
	}
	if runtime.GOOS == "linux" {
		if uid, err := paths.UID(); err == nil && uid != "" {
			if d := filepath.Join("/run", "user", uid); !contains(dirs, d) {
				dirs = append(dirs, d)
			}
		}
	}
	return dirs
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// tempAgentGlobs returns the glob patterns for agents that live in a temp
// directory: a plain `ssh-agent` fork, which mkdtemp's its own 0700 directory,
// and on macOS launchd's per-session socket plus the sandboxed private TMPDIR
// a forked agent lands in. The uid check in ownedAgentSocket is what makes
// globbing a shared /tmp safe; the directory's own mode is the agent's
// business, not ours.
//
// A function rather than a constant list so the unix discovery tests can
// narrow it (via tempAgentGlobsOverride) to the temp tree they control: a
// developer machine with a real ssh-agent running would otherwise have its own
// /tmp socket join every scan and make the assertions machine-dependent.
func tempAgentGlobs() []string {
	if tempAgentGlobsOverride != nil {
		return tempAgentGlobsOverride()
	}
	patterns := []string{"/tmp/ssh-*/agent.*"}
	if runtime.GOOS == "darwin" {
		patterns = append(patterns, "/private/tmp/com.apple.launchd.*/Listeners")
		if tmp := os.Getenv("TMPDIR"); tmp != "" {
			patterns = append(patterns, filepath.Join(tmp, "ssh-*", "agent.*"))
		}
	}
	return patterns
}

// tempAgentGlobsOverride is nil in every shipped build; see tempAgentGlobs.
var tempAgentGlobsOverride func() []string

// glob is filepath.Glob with the error discarded: the only error it reports is
// a malformed pattern, and every pattern here is a compile-time constant.
func glob(pattern string) []string {
	m, _ := filepath.Glob(pattern)
	return m
}

// ownedAgentSocket reports whether path looks like a socket this user owns.
//
// It is a cheap pre-filter, NOT the security boundary — that is peerUID, taken
// on the connection actually used (see upstreamSource.connect). The
// distinction is load-bearing in both directions:
//
//   - Stat, not Lstat. A symlink must be followed, because the single most
//     important candidate is routinely one: the tmux convention points
//     $SSH_AUTH_SOCK at a stable ~/.ssh/ssh_auth_sock symlink, and 1Password
//     documents `ln -s ... ~/.1password/agent.sock` on macOS. Lstat reports
//     ModeSymlink rather than ModeSocket for those, so it silently dropped the
//     user's real agent — the exact thing auto-detection exists to find.
//   - Following symlinks means this check alone cannot be trusted. It sees who
//     owns the target now; an attacker who controls a path component can
//     re-point it before the dial. Hence the peer-credential check, which asks
//     the kernel who is on the other end of the connection we already hold and
//     so has no window to race.
func ownedAgentSocket(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(st.Uid) == os.Getuid()
}

// resolveEndpointPath returns the fully-resolved path for a Unix socket, for
// the self-reference comparison in discovery. It returns "" when the path
// cannot be resolved (it does not exist yet), leaving the caller with the
// unresolved form — the comparison is a loop guard, not a security boundary,
// and the probe in isSelfAgent is what catches whatever the paths miss.
func resolveEndpointPath(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(endpoint)
	if err != nil {
		return ""
	}
	return resolved
}
