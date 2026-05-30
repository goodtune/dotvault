package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/goodtune/dotvault/internal/vault"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// kvReader is the slice of the Vault client the KV source needs. *vault.Client
// satisfies it; tests supply a fake.
type kvReader interface {
	ListKVv2(ctx context.Context, mount, path string) ([]string, error)
	ReadKVv2(ctx context.Context, mount, path string) (*vault.Secret, error)
}

// kvSource discovers SSH keys under a KV path prefix. Each secret beneath the
// prefix is treated as a key pair with `public_key` (authorized_keys form) and
// `private_key` (OpenSSH PEM) fields — the schema the SSH enrolment engine
// writes. Keys are discovered, not declared: a secret appearing or disappearing
// in Vault changes the agent's identities on the next List without a restart.
type kvSource struct {
	name   string
	vault  kvReader
	mount  string // KV mount, e.g. "kv"
	prefix string // metadata/data path prefix, e.g. "users/gary/ssh/"
}

func newKVSource(name string, v kvReader, mount, prefix string) *kvSource {
	return &kvSource{name: name, vault: v, mount: mount, prefix: prefix}
}

func (s *kvSource) Name() string { return s.name }
func (s *kvSource) Type() string { return "kv" }

// leaves lists the immediate secret names under the prefix, skipping nested
// "directory" entries (Vault renders those with a trailing slash).
func (s *kvSource) leaves(ctx context.Context) ([]string, error) {
	names, err := s.vault.ListKVv2(ctx, s.mount, s.prefix)
	if err != nil {
		return nil, fmt.Errorf("list %s/%s: %w", s.mount, s.prefix, err)
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if strings.HasSuffix(n, "/") {
			continue
		}
		out = append(out, n)
	}
	return out, nil
}

func (s *kvSource) Identities(ctx context.Context) ([]Identity, error) {
	names, err := s.leaves(ctx)
	if err != nil {
		return nil, err
	}
	var ids []Identity
	for _, name := range names {
		sec, err := s.vault.ReadKVv2(ctx, s.mount, s.prefix+name)
		if err != nil {
			return nil, fmt.Errorf("read %s/%s%s: %w", s.mount, s.prefix, name, err)
		}
		if sec == nil {
			continue
		}
		pub, ok := parsePublicKey(sec.Data)
		if !ok {
			// Not an SSH key secret — skip silently so the prefix can be
			// co-tenanted with unrelated data.
			continue
		}
		ids = append(ids, Identity{PubKey: pub, Comment: s.prefix + name})
	}
	return ids, nil
}

func (s *kvSource) Sign(ctx context.Context, key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, bool, error) {
	names, err := s.leaves(ctx)
	if err != nil {
		return nil, false, err
	}
	for _, name := range names {
		sec, err := s.vault.ReadKVv2(ctx, s.mount, s.prefix+name)
		if err != nil {
			return nil, false, fmt.Errorf("read %s/%s%s: %w", s.mount, s.prefix, name, err)
		}
		if sec == nil {
			continue
		}
		pub, ok := parsePublicKey(sec.Data)
		if !ok || !keyEqual(pub, key) {
			continue
		}
		signer, err := parsePrivateKey(sec.Data)
		if err != nil {
			return nil, false, fmt.Errorf("%s%s: %w", s.prefix, name, err)
		}
		sig, err := signData(signer, data, flags)
		if err != nil {
			return nil, false, fmt.Errorf("%s%s: sign: %w", s.prefix, name, err)
		}
		return sig, true, nil
	}
	return nil, false, nil
}

func parsePublicKey(data map[string]any) (ssh.PublicKey, bool) {
	raw, ok := data["public_key"].(string)
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, false
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil {
		return nil, false
	}
	return pub, true
}

func parsePrivateKey(data map[string]any) (ssh.Signer, error) {
	raw, ok := data["private_key"].(string)
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("secret has no private_key field")
	}
	signer, err := ssh.ParsePrivateKey([]byte(raw))
	if err != nil {
		if _, missing := err.(*ssh.PassphraseMissingError); missing {
			return nil, fmt.Errorf("private key is passphrase-protected; the agent cannot use it (use an unencrypted key or cert mode)")
		}
		return nil, fmt.Errorf("parse private_key: %w", err)
	}
	return signer, nil
}
