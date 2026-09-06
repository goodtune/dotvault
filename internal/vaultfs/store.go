package vaultfs

import (
	"context"
	"fmt"
	"strings"

	"github.com/goodtune/dotvault/internal/vault"
)

// KVClient is the subset of *vault.Client the store needs. Narrowing it here
// rather than taking the concrete type keeps the package's tests free of a
// live Vault and documents exactly which Vault operations a mounted
// filesystem can reach — read, list, write, delete-metadata, and nothing else.
type KVClient interface {
	ListKVv2(ctx context.Context, mount, path string) ([]string, error)
	ReadKVv2(ctx context.Context, mount, path string) (*vault.Secret, error)
	WriteKVv2(ctx context.Context, mount, path string, data map[string]any) error
	DeleteKVv2(ctx context.Context, mount, path string) error
}

// vaultStore adapts a Vault client to Store, binding the KV mount and the
// user's path prefix so everything above it deals in paths relative to the
// mountpoint. This is the only place the two are joined, which is what makes
// "a mounted filesystem cannot address another user's secrets" a structural
// property rather than a check someone has to remember.
type vaultStore struct {
	client KVClient
	mount  string
	prefix string // e.g. "users/gary/", always ends in "/"
}

// NewStore builds a Store over a Vault client for the given KV mount, user
// prefix and username — the same three values the sync engine and enrolment
// manager compose into kv/{user_prefix}{username}/.
func NewStore(client KVClient, kvMount, userPrefix, username string) (Store, error) {
	if client == nil {
		return nil, fmt.Errorf("vaultfs: nil vault client")
	}
	if kvMount == "" {
		return nil, fmt.Errorf("vaultfs: empty kv mount")
	}
	// The prefix is what makes "a mounted filesystem cannot address another
	// user's secrets" structural rather than a check somewhere above, so the
	// two values it is built from are validated rather than assumed. A
	// username carrying a slash or a ".." would let the composed prefix name
	// a subtree other than this user's — paths.Username strips a DOMAIN\
	// prefix but a directory service is not otherwise constrained in what it
	// can return, and an explicit identity override is caller-supplied.
	if err := validateName(username); err != nil {
		return nil, fmt.Errorf("vaultfs: invalid username %q: %w", username, err)
	}
	if userPrefix != "" {
		if _, err := cleanPath(userPrefix); err != nil {
			return nil, fmt.Errorf("vaultfs: invalid user prefix %q: %w", userPrefix, err)
		}
		if !strings.HasSuffix(userPrefix, "/") {
			userPrefix += "/"
		}
	}
	return &vaultStore{
		client: client,
		mount:  kvMount,
		prefix: userPrefix + username + "/",
	}, nil
}

// path joins the user prefix onto a relative path. relPath is always a
// validated, slash-separated path with no leading or trailing slash (see
// cleanPath), so this is a plain concatenation rather than a path join —
// Vault treats logical path segments literally and must not have them
// collapsed.
func (s *vaultStore) path(relPath string) string {
	return s.prefix + relPath
}

func (s *vaultStore) List(ctx context.Context, relPath string) ([]string, error) {
	// Vault's LIST wants a trailing slash on the directory being listed; the
	// root is the prefix itself, which already ends in one.
	p := s.prefix
	if relPath != "" {
		p = s.path(relPath) + "/"
	}
	return s.client.ListKVv2(ctx, s.mount, p)
}

func (s *vaultStore) Read(ctx context.Context, relPath string) (*Secret, error) {
	secret, err := s.client.ReadKVv2(ctx, s.mount, s.path(relPath))
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, nil
	}
	return &Secret{
		Data:        secret.Data,
		Version:     secret.Version,
		CreatedTime: secret.CreatedTime,
	}, nil
}

func (s *vaultStore) Write(ctx context.Context, relPath string, data map[string]any) error {
	return s.client.WriteKVv2(ctx, s.mount, s.path(relPath), data)
}

func (s *vaultStore) Delete(ctx context.Context, relPath string) error {
	return s.client.DeleteKVv2(ctx, s.mount, s.path(relPath))
}
