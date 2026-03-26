package vault

import (
	"context"
	"errors"
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"
)

// Config holds Vault connection settings.
type Config struct {
	Address       string
	Token         string
	CACert        string
	TLSSkipVerify bool
}

// Secret represents a KVv2 secret with its data and version metadata.
type Secret struct {
	Data    map[string]any
	Version int
}

// Client wraps the Vault API client.
type Client struct {
	raw *vaultapi.Client
}

// NewClient creates a new Vault API client.
func NewClient(cfg Config) (*Client, error) {
	vaultCfg := vaultapi.DefaultConfig()
	vaultCfg.Address = cfg.Address

	if cfg.CACert != "" {
		tlsCfg := &vaultapi.TLSConfig{CACert: cfg.CACert}
		if err := vaultCfg.ConfigureTLS(tlsCfg); err != nil {
			return nil, fmt.Errorf("configure TLS: %w", err)
		}
	}
	if cfg.TLSSkipVerify {
		tlsCfg := &vaultapi.TLSConfig{Insecure: true}
		if err := vaultCfg.ConfigureTLS(tlsCfg); err != nil {
			return nil, fmt.Errorf("configure TLS skip verify: %w", err)
		}
	}

	client, err := vaultapi.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("create vault client: %w", err)
	}

	if cfg.Token != "" {
		client.SetToken(cfg.Token)
	}

	return &Client{raw: client}, nil
}

// Raw returns the underlying Vault API client for direct access.
func (c *Client) Raw() *vaultapi.Client {
	return c.raw
}

// SetToken sets the auth token on the client.
func (c *Client) SetToken(token string) {
	c.raw.SetToken(token)
}

// Token returns the current auth token.
func (c *Client) Token() string {
	return c.raw.Token()
}

// ReadKVv2 reads a KVv2 secret at the given mount and path.
// Returns nil (not error) if the secret doesn't exist.
func (c *Client) ReadKVv2(ctx context.Context, mount, path string) (*Secret, error) {
	secret, err := c.raw.KVv2(mount).Get(ctx, path)
	if err != nil {
		// Check for 404 — secret doesn't exist
		if isNotFound(err) || errors.Is(err, vaultapi.ErrSecretNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("read kv %s/%s: %w", mount, path, err)
	}
	if secret == nil {
		return nil, nil
	}

	version := 0
	if secret.VersionMetadata != nil {
		version = secret.VersionMetadata.Version
	}

	return &Secret{
		Data:    secret.Data,
		Version: version,
	}, nil
}

// ListKVv2 lists keys under the given path in a KVv2 mount.
func (c *Client) ListKVv2(ctx context.Context, mount, path string) ([]string, error) {
	secret, err := c.raw.Logical().ListWithContext(ctx, fmt.Sprintf("%s/metadata/%s", mount, path))
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list kv %s/%s: %w", mount, path, err)
	}
	if secret == nil {
		return nil, nil
	}

	keysRaw, ok := secret.Data["keys"]
	if !ok {
		return nil, nil
	}

	keysSlice, ok := keysRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected keys type: %T", keysRaw)
	}

	keys := make([]string, len(keysSlice))
	for i, k := range keysSlice {
		keys[i] = fmt.Sprintf("%v", k)
	}
	return keys, nil
}

// EnableKVv2 enables a KVv2 secrets engine at the given path.
// Used for testing. Returns an error if it already exists (non-fatal).
func (c *Client) EnableKVv2(ctx context.Context, path string) error {
	err := c.raw.Sys().MountWithContext(ctx, path, &vaultapi.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	})
	if err != nil {
		return fmt.Errorf("enable kv-v2 at %s: %w", path, err)
	}
	return nil
}

// WriteKVv2 writes data to a KVv2 secret. Used for testing/seeding.
func (c *Client) WriteKVv2(ctx context.Context, mount, path string, data map[string]any) error {
	_, err := c.raw.KVv2(mount).Put(ctx, path, data)
	if err != nil {
		return fmt.Errorf("write kv %s/%s: %w", mount, path, err)
	}
	return nil
}

// LookupSelf returns the current token's metadata, or an error if invalid.
func (c *Client) LookupSelf(ctx context.Context) (*vaultapi.Secret, error) {
	secret, err := c.raw.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("token lookup-self: %w", err)
	}
	return secret, nil
}

// RenewSelf renews the current token.
func (c *Client) RenewSelf(ctx context.Context, increment int) (*vaultapi.Secret, error) {
	secret, err := c.raw.Auth().Token().RenewSelfWithContext(ctx, increment)
	if err != nil {
		return nil, fmt.Errorf("token renew-self: %w", err)
	}
	return secret, nil
}

func isNotFound(err error) bool {
	if respErr, ok := err.(*vaultapi.ResponseError); ok {
		return respErr.StatusCode == 404
	}
	return false
}
