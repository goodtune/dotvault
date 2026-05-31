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
			p, name := kvPrefixAndName(k.PathPrefix)
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

// kvPrefixAndName normalises a KV source's configured path_prefix (strip a
// leading slash, ensure exactly one trailing slash) and derives the source's
// display name. Shared by the source factory and DescribeConfig so the two
// can't drift on either the resolved path or the reported name.
func kvPrefixAndName(pathPrefix string) (prefix, name string) {
	p := strings.TrimPrefix(pathPrefix, "/")
	if p != "" && !strings.HasSuffix(p, "/") {
		p += "/"
	}
	name = "kv"
	if p != "" {
		name = "kv:" + strings.TrimSuffix(p, "/")
	}
	return p, name
}

// DescribeConfig returns a status snapshot for `dotvault status`. KV sources
// are resolved against Vault (cheap, read-only metadata + secret reads) so the
// CLI shows the live key fingerprints. Vault-CA sources are described from
// configuration WITHOUT minting a certificate: minting in the CLI would
// generate a throwaway in-memory key, hit Vault's sign endpoint on every status
// invocation, and produce a certificate that doesn't even match the one the
// running daemon serves (a different ephemeral key). The daemon's live
// Backend.Status — backed by its cached cert — remains the authoritative view
// of minted certificates for the web dashboard.
func DescribeConfig(ctx context.Context, agentCfg config.AgentConfig, vc *vault.Client, kvMount, userPrefix, username string) Status {
	base := userPrefix + username + "/"
	st := Status{Endpoint: ResolveEndpoint(agentCfg)}
	for i, k := range agentCfg.Keys {
		switch k.Source {
		case "kv":
			prefix, name := kvPrefixAndName(k.PathPrefix)
			ss := SourceStatus{Name: name, Type: "kv"}
			ids, err := newKVSource(name, vc, kvMount, base+prefix).Identities(ctx)
			if err != nil {
				ss.Error = err.Error()
			}
			for _, id := range ids {
				ss.Identities = append(ss.Identities, identityStatus(id))
			}
			st.Sources = append(st.Sources, ss)
		case "vault-ca":
			ttl := strings.TrimSpace(k.TTL)
			if ttl == "" {
				ttl = defaultCertTTL.String()
			}
			st.Sources = append(st.Sources, SourceStatus{
				Name: "vault-ca:" + k.Role,
				Type: "vault-ca",
				Identities: []IdentityStatus{{
					IsCert:  true,
					Comment: fmt.Sprintf("certificate minted on demand (mount=%s, role=%s, ttl=%s)", k.Mount, k.Role, ttl),
				}},
			})
		default:
			st.Sources = append(st.Sources, SourceStatus{
				Name:  fmt.Sprintf("keys[%d]", i),
				Type:  k.Source,
				Error: fmt.Sprintf("unknown source %q", k.Source),
			})
		}
	}
	return st
}
