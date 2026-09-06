package sshfwd

import (
	"context"
	"fmt"
	"path"
	"strings"
)

// homeProbeCommand reads the remote account's home directory. Deliberately a
// shell echo rather than an SFTP realpath: the forward needs no subsystem, and
// requiring sftp-server would exclude hosts that only allow exec.
const homeProbeCommand = "echo $HOME"

// CommandRunner runs a single command on the remote and returns its stdout.
// Abstracted so expansion is testable without an SSH server.
type CommandRunner interface {
	Run(ctx context.Context, cmd string) (string, error)
}

// ExpandRemotePath resolves a configured remote_socket to an absolute path on
// the remote host.
//
// An absolute path is returned verbatim and never probes — a needless exec
// channel per connection would be both slow and a reason for the connection to
// fail on a host that restricts commands. Only a "~/" prefix triggers the
// probe. "~user/" is rejected rather than guessed: resolving another account's
// home would need NSS access dotvault does not have, and binding the wrong
// path silently is worse than refusing.
func ExpandRemotePath(ctx context.Context, r CommandRunner, p string) (string, error) {
	if err := ValidateRemoteSocket(p); err != nil {
		return "", err
	}
	if !strings.HasPrefix(p, "~/") {
		return p, nil
	}

	out, err := r.Run(ctx, homeProbeCommand)
	if err != nil {
		return "", fmt.Errorf("probe remote home directory: %w", err)
	}
	home := strings.TrimSpace(out)
	if home == "" {
		return "", fmt.Errorf("remote $HOME is empty")
	}
	if !strings.HasPrefix(home, "/") {
		return "", fmt.Errorf("remote $HOME %q is not an absolute path", home)
	}
	// Reject control characters in the probe result. An interior newline or other
	// control character in $HOME is a sign the remote returned extra output (MOTD,
	// banner, shell startup noise) — either a misconfiguration or an injection
	// attempt. The later shell-command consumer must never see such a value.
	if hasControlChar(home) {
		return "", fmt.Errorf("remote $HOME %q contains control characters", home)
	}
	expanded := path.Join(home, strings.TrimPrefix(p, "~/"))
	// Re-validate the final path: it must still be absolute and control-character
	// free, as a belt-and-braces layer in case a future edit weakens the checks above.
	if !strings.HasPrefix(expanded, "/") || hasControlChar(expanded) {
		return "", fmt.Errorf("expanded remote socket path %q is invalid", expanded)
	}
	return expanded, nil
}

// hasControlChar reports whether s contains an ASCII control character
// (< 0x20 or == 0x7f), a sign of extra or hostile output in the probe result.
func hasControlChar(s string) bool {
	for _, b := range s {
		if b < 0x20 || b == 0x7f {
			return true
		}
	}
	return false
}
