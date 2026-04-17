package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"

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

// DeleteKVv2 deletes all versions of a KVv2 secret (the full metadata
// record, not just a soft-delete of the latest version). Used by the
// refresh manager when the upstream credential has been permanently
// revoked and the local state needs to be wiped so the user can re-enrol.
func (c *Client) DeleteKVv2(ctx context.Context, mount, path string) error {
	if err := c.raw.KVv2(mount).DeleteMetadata(ctx, path); err != nil {
		// A not-found metadata entry is fine (race with another cleanup).
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("delete kv %s/%s: %w", mount, path, err)
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

// ServerHealth returns the Vault server health status.
func (c *Client) ServerHealth(ctx context.Context) (*HealthResponse, error) {
	resp, err := c.raw.Sys().HealthWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("vault health check: %w", err)
	}
	return &HealthResponse{
		Version:    resp.Version,
		Enterprise: resp.Enterprise,
		ClusterName: resp.ClusterName,
	}, nil
}

// HealthResponse contains selected fields from the Vault health endpoint.
type HealthResponse struct {
	Version     string
	Enterprise  bool
	ClusterName string
}

// MFAMethod describes an MFA method required for authentication.
type MFAMethod struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	UsesPasscode bool   `json:"uses_passcode"`
}

// LoginResult holds the outcome of an LDAP login attempt.
type LoginResult struct {
	Token        string
	MFARequired  bool
	MFARequestID string
	MFAMethods   []MFAMethod
}

// LoginLDAP authenticates via LDAP and detects if MFA is required.
func (c *Client) LoginLDAP(ctx context.Context, mount, username, password string) (*LoginResult, error) {
	data := map[string]interface{}{
		"password": password,
	}
	secret, err := c.raw.Logical().WriteWithContext(ctx,
		fmt.Sprintf("auth/%s/login/%s", mount, username), data)
	if err != nil {
		return nil, fmt.Errorf("LDAP login: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return nil, fmt.Errorf("no auth data in LDAP response")
	}

	// If we got a token directly, no MFA needed.
	if secret.Auth.ClientToken != "" {
		return &LoginResult{Token: secret.Auth.ClientToken}, nil
	}

	// MFA required — extract methods from constraints.
	mfaReq := secret.Auth.MFARequirement
	if mfaReq == nil {
		return nil, fmt.Errorf("no token and no MFA requirement in LDAP response")
	}

	var methods []MFAMethod
	for _, constraint := range mfaReq.MFAConstraints {
		for _, m := range constraint.Any {
			methods = append(methods, MFAMethod{
				ID:           m.ID,
				Type:         m.Type,
				UsesPasscode: m.UsesPasscode,
			})
		}
	}

	// Sort methods so passcode-capable (TOTP) come first, then by ID for
	// determinism. This ensures MFAMethods[0] is the preferred method.
	sort.Slice(methods, func(i, j int) bool {
		if methods[i].UsesPasscode != methods[j].UsesPasscode {
			return methods[i].UsesPasscode
		}
		return methods[i].ID < methods[j].ID
	})

	return &LoginResult{
		MFARequired:  true,
		MFARequestID: mfaReq.MFARequestID,
		MFAMethods:   methods,
	}, nil
}

// ValidateMFA validates an MFA challenge. For push methods (Duo), pass an
// empty passcode — the call blocks until the user approves or the context
// is cancelled. For TOTP, pass the user-provided code. Returns the
// authenticated client token on success.
func (c *Client) ValidateMFA(ctx context.Context, mfaRequestID, methodID, passcode string) (string, error) {
	payload := map[string]interface{}{
		methodID: []string{passcode},
	}
	secret, err := c.raw.Sys().MFAValidateWithContext(ctx, mfaRequestID, payload)
	if err != nil {
		return "", fmt.Errorf("MFA validate: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return "", fmt.Errorf("no token in MFA validate response")
	}
	return secret.Auth.ClientToken, nil
}

func isNotFound(err error) bool {
	if respErr, ok := err.(*vaultapi.ResponseError); ok {
		return respErr.StatusCode == 404
	}
	return false
}

// IsForbidden returns true if the error is a Vault 403 response, indicating
// the token is invalid, revoked, or lacks permissions.
func IsForbidden(err error) bool {
	var respErr *vaultapi.ResponseError
	if errors.As(err, &respErr) {
		return respErr.StatusCode == http.StatusForbidden
	}
	return false
}
