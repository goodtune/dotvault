package sshfwd

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
)

// homeProbeCommand reads the remote account's home directory. Deliberately a
// shell echo rather than an SFTP realpath: the forward needs no subsystem, and
// requiring sftp-server would exclude hosts that only allow exec.
const homeProbeCommand = "echo $HOME"

// hostnameFn is os.Hostname, replaceable in tests.
var hostnameFn = os.Hostname

// LocalHostnameLabel returns this host's name as a socket-safe label: the
// first DNS label of os.Hostname(), lowercased, with every byte outside
// [a-z0-9-] replaced by '-'. Lowercasing matters because the borrower's
// pattern is a filename glob and macOS hostnames are routinely mixed-case.
// An empty result is an error rather than a silent "dotvault..sock".
func LocalHostnameLabel() (string, error) {
	h, err := hostnameFn()
	if err != nil {
		return "", fmt.Errorf("resolve local hostname: %w", err)
	}
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i]
	}
	h = strings.ToLower(h)
	var b strings.Builder
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "", fmt.Errorf("local hostname %q yields no usable label for %s", h, HostnameToken)
	}
	return out, nil
}

// maxHostnameLabel is the DNS limit on a single label, and so the ceiling on
// anything LocalHostnameLabel can legitimately produce.
const maxHostnameLabel = 63

// ValidateHostnameLabel reports whether s is a label LocalHostnameLabel could
// have produced: non-empty, at most 63 bytes, every byte in [a-z0-9-], and no
// leading or trailing '-'.
//
// It exists for the consumer that does not produce its own label but is handed
// one — the pre-1.0 forward migration reads `hostname_label` out of a peer's
// unauthenticated status response and builds a socket path from it, so an
// unchecked value would be path traversal by a hostile or merely broken peer.
// The rule lives here, next to the producer, so the two definitions cannot
// drift; nothing on this side of the boundary needs to call it.
func ValidateHostnameLabel(s string) error {
	if s == "" {
		return fmt.Errorf("hostname label is empty")
	}
	if len(s) > maxHostnameLabel {
		return fmt.Errorf("hostname label is %d bytes, over the %d-byte limit", len(s), maxHostnameLabel)
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return fmt.Errorf("hostname label starts or ends with '-'")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			// Deliberately reports the position, not the byte: the caller
			// logs this and the value came from off-host.
			return fmt.Errorf("hostname label has a character outside [a-z0-9-] at byte %d", i)
		}
	}
	return nil
}

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
// probe; the {{HOSTNAME}} token is substituted locally first and never needs
// one. "~user/" is rejected rather than guessed: resolving another account's
// home would need NSS access dotvault does not have, and binding the wrong
// path silently is worse than refusing.
func ExpandRemotePath(ctx context.Context, r CommandRunner, p string) (string, error) {
	if err := ValidateRemoteSocket(p); err != nil {
		return "", err
	}
	if strings.Contains(p, HostnameToken) {
		label, err := LocalHostnameLabel()
		if err != nil {
			return "", err
		}
		p = strings.ReplaceAll(p, HostnameToken, label)
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
