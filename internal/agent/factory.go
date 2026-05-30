package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// errSource is a placeholder for a key source that could not be constructed
// (unknown engine, unsupported option). It owns no keys and reports its reason
// via Identities, so the failure shows up in agent status without aborting the
// daemon — mirroring the enrolment picker's "error: …" rows.
type errSource struct {
	name string
	typ  string
	err  error
}

func newErrSource(name, typ string, err error) Source {
	return &errSource{name: name, typ: typ, err: err}
}

func (s *errSource) Name() string                                   { return s.name }
func (s *errSource) Type() string                                   { return s.typ }
func (s *errSource) Identities(context.Context) ([]Identity, error) { return nil, s.err }
func (s *errSource) Sign(context.Context, ssh.PublicKey, []byte, agent.SignatureFlags) (*ssh.Signature, bool, error) {
	return nil, false, nil
}

// NewSourcesFromConfig builds the ordered key sources for the daemon from the
// agent config. kvMount/userPrefix/username come from the running config and
// identity resolution (userPrefix carries its trailing slash).
func NewSourcesFromConfig(agentCfg config.AgentConfig, vc *vault.Client, kvMount, userPrefix, username string) ([]Source, error) {
	base := userPrefix + username + "/"
	sources := make([]Source, 0, len(agentCfg.Keys))
	for i, k := range agentCfg.Keys {
		switch k.Source {
		case "kv":
			p := strings.TrimPrefix(k.PathPrefix, "/")
			if p != "" && !strings.HasSuffix(p, "/") {
				p += "/"
			}
			name := "kv"
			if p != "" {
				name = "kv:" + strings.TrimSuffix(p, "/")
			}
			sources = append(sources, newKVSource(name, vc, kvMount, base+p))
		case "vault-ca":
			ttl, err := parseTTL(k.TTL)
			if err != nil {
				return nil, fmt.Errorf("agent.keys[%d].ttl: %w", i, err)
			}
			name := "vault-ca:" + k.Role
			src, err := newVaultCASource(name, vaultCertSigner{client: vc}, k.Mount, k.Role, k.Principals, username, ttl, k.EphemeralKey)
			if err != nil {
				return nil, fmt.Errorf("agent.keys[%d]: %w", i, err)
			}
			sources = append(sources, src)
		default:
			sources = append(sources, newErrSource(fmt.Sprintf("keys[%d]", i), k.Source, fmt.Errorf("unknown source %q", k.Source)))
		}
	}
	return sources, nil
}

func parseTTL(s string) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	return config.ParseDuration(s)
}
