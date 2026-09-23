package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// SocketList is the value of vault.token_socket: an ordered list of peer
// dotvault socket patterns. It decodes from either a YAML scalar (the pre-list
// spelling, one path) or a sequence, so an existing config keeps loading.
//
// The nil/empty distinction is load-bearing: a nil list means the key was
// absent and the defaults apply (see DefaultPeerSocketPatterns); a non-nil
// empty list — `token_socket: []` or `token_socket: ""` — means the operator
// explicitly disabled peer sockets.
//
// TODO(pre-1.0, #ISSUE): drop the scalar form.
type SocketList []string

// UnmarshalYAML accepts a scalar or a sequence of scalars.
func (s *SocketList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var v string
		if err := n.Decode(&v); err != nil {
			return err
		}
		if v == "" {
			*s = SocketList{}
			return nil
		}
		*s = SocketList{v}
		return nil
	case yaml.SequenceNode:
		var v []string
		if err := n.Decode(&v); err != nil {
			return err
		}
		if v == nil {
			v = []string{}
		}
		*s = SocketList(v)
		return nil
	default:
		return fmt.Errorf("token_socket: expected a string or a list of strings, got %s", nodeKindName(n.Kind))
	}
}

func nodeKindName(k yaml.Kind) string {
	switch k {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.AliasNode:
		return "an alias"
	default:
		return "an unsupported node"
	}
}

// ValidateSocketPattern checks one vault.token_socket entry. A pattern must be
// absolute or ~/-relative (the api.unix.path rule — a relative path resolves
// against the working directory and two processes would disagree about it),
// and glob metacharacters are permitted only in the final path segment. That
// restriction gives every pattern exactly one parent directory to watch and
// keeps a pattern from walking the filesystem.
func ValidateSocketPattern(p string) error {
	switch {
	case p == "":
		return errors.New("must not be empty")
	case strings.ContainsRune(p, 0):
		return errors.New("must not contain a NUL byte")
	case strings.HasPrefix(p, "~/"), p == "~":
		// ~-relative; expanded at resolve time.
	case strings.HasPrefix(p, "~"):
		return errors.New("must be an absolute path (or ~/-relative); ~user/ is not supported")
	case !filepath.IsAbs(p):
		return errors.New("must be an absolute path (or ~/-relative)")
	}
	dir := p[:strings.LastIndex(p, "/")+1]
	if strings.ContainsAny(dir, "*?[") {
		return errors.New("glob metacharacters are allowed only in the final path segment")
	}
	return nil
}

// DefaultPeerSocketPatterns is the vault.token_socket value applied when the
// key is absent: the pre-list default path, so a workstation that has not
// been upgraded keeps working, plus the per-hostname pattern every upgraded
// workstation's managed forward binds (see sshfwd.DefaultRemoteSocket).
//
// TODO(pre-1.0, #ISSUE): drop ~/.ssh/dotvault.sock from the defaults.
var DefaultPeerSocketPatterns = []string{"~/.ssh/dotvault.sock", "~/.ssh/dotvault.*.sock"}

// peerSocketPatterns returns the configured peer patterns with the default
// applied for an absent key. Defaulting happens here rather than at load so
// an exported config round-trips "absent" as absent.
func (c *Config) peerSocketPatterns() []string {
	if c.Vault.TokenSockets == nil {
		return append([]string(nil), DefaultPeerSocketPatterns...)
	}
	return append([]string(nil), c.Vault.TokenSockets...)
}

// PeerActionSockets returns the peer socket patterns the peer actions
// (browse / notify / clipboard) fan out to. Deliberately without the local
// API socket: those actions must reach the workstation where a human is
// looking, and posting them to the local daemon would open a browser on the
// headless host nobody is sitting at.
func (c *Config) PeerActionSockets() []string {
	return c.peerSocketPatterns()
}

// validateTokenSockets checks every vault.token_socket entry.
func (c *Config) validateTokenSockets() error {
	for i, p := range c.Vault.TokenSockets {
		if err := ValidateSocketPattern(p); err != nil {
			return fmt.Errorf("vault.token_socket[%d] %q: %w", i, p, err)
		}
	}
	return nil
}
