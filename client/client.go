// Package client is dotvault's public, importable Go API. It exposes
// dotvault's connectivity, token-resolution, login, and user-path conventions
// so other tools (e.g. an agent runner that reads identity tokens out of
// Vault) can talk to the same Vault, authenticate the same way, and read from
// the exact path dotvault writes to — without re-implementing any of it and
// risking silent divergence.
//
// dotvault remains the single source of truth for:
//
//   - connectivity (Vault address, TLS, CA),
//   - token-resolution order (VAULT_TOKEN env → token file → interactive
//     login),
//   - the login flow itself (OIDC browser, LDAP with MFA),
//   - the convention mapping an authenticated user to a
//     kv/users/<user>/... path.
//
// # Identity / path convention
//
// IMPORTANT: dotvault derives the <user> path segment from the OS user (the
// current account's username with any DOMAIN\ prefix stripped), NOT from the
// Vault token. A user logged in via OIDC as alice@corp whose OS account is
// "alice" has secrets at kv/users/alice/.... IdentityName returns this
// OS-derived name, and ReadUserSecret composes paths with it, so a consumer
// reads from exactly where dotvault's sync/enrolment writes. A consumer must
// therefore run as the same OS user as the dotvault that populated the
// secrets — typically true, since dotvault runs in the user's own context.
//
// # Typical use
//
//	cfg, err := client.LoadConfig(client.DefaultConfigPath())
//	cli, err := client.New(cfg)
//	if err := cli.Authenticate(ctx); err != nil {
//	    // errors.Is(err, client.ErrLoginRequired | ErrUnreachable | ErrAuthFailed)
//	}
//	gh,  _, err := cli.ReadUserSecret(ctx, "gh",      "oauth_token")
//	ll,  _, err := cli.ReadUserSecret(ctx, "litellm", "token")
package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/vault"
)

// Client wraps a Vault client with dotvault's auth and KV-read conventions.
// Construct one with New. A Client is not safe for concurrent Authenticate /
// Login calls, but concurrent reads after authentication are fine.
type Client struct {
	cfg Config
	vc  *vault.Client
}

// New constructs a Client from cfg. It builds the underlying Vault client
// (applying TLS/CA settings) but performs no network calls and does not
// authenticate — call Authenticate (or Login) before reading secrets.
//
// Empty optional fields in cfg are filled with dotvault's defaults (KVMount
// "kv", UserPrefix "users/", TokenFile ~/.vault-token), so a directly
// constructed Config behaves the same as one returned by LoadConfig.
func New(cfg *Config) (*Client, error) {
	if cfg == nil {
		return nil, errors.New("dotvault: nil config")
	}
	if cfg.Vault.Address == "" {
		return nil, errors.New("dotvault: vault address is required")
	}
	resolved := cfg.withDefaults()

	vc, err := vault.NewClient(vault.Config{
		Address:       resolved.Vault.Address,
		CACert:        resolved.Vault.CACert,
		TLSSkipVerify: resolved.Vault.TLSSkipVerify,
	})
	if err != nil {
		return nil, fmt.Errorf("dotvault: create vault client: %w", err)
	}
	return &Client{cfg: resolved, vc: vc}, nil
}

// Authenticate makes the Client hold a usable Vault token, following
// dotvault's precedence:
//
//  1. VAULT_TOKEN environment variable,
//  2. the configured token file,
//  3. if neither yields a token Vault accepts, the configured fresh-auth flow
//     (OIDC browser / LDAP terminal prompt — the same path as `dotvault
//     login`).
//
// If Vault is unreachable, it returns an error wrapping ErrUnreachable
// without attempting an interactive login (no point prompting when the server
// is down). If a fresh login is required but fails, the error wraps
// ErrAuthFailed.
//
// Use AuthenticateCached when interactive login must not happen (e.g. a
// side-effect-free health check).
func (c *Client) Authenticate(ctx context.Context) error {
	err := c.AuthenticateCached(ctx)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrUnreachable):
		// Vault is down — surface it rather than dropping the user into a
		// login flow that cannot succeed.
		return err
	case errors.Is(err, ErrLoginRequired):
		// Fall through to the interactive flow below.
	default:
		return err
	}
	return c.Login(ctx)
}

// AuthenticateCached resolves a token from VAULT_TOKEN then the token file and
// validates it with a LookupSelf, but never initiates an interactive login.
// It returns nil if a cached token is usable, an error wrapping
// ErrLoginRequired if no usable token is present (missing, expired, or
// revoked), or an error wrapping ErrUnreachable if Vault cannot be reached to
// validate the token.
//
// This is the entry point for callers that must remain side-effect-free — no
// browser pop, no password prompt — such as a `doctor`/preflight check.
func (c *Client) AuthenticateCached(ctx context.Context) error {
	token := auth.ResolveToken(c.cfg.TokenFile)
	if token == "" {
		return fmt.Errorf("%w: no VAULT_TOKEN and no token at %s",
			ErrLoginRequired, c.cfg.TokenFile)
	}
	c.vc.SetToken(token)
	if _, err := c.vc.LookupSelf(ctx); err != nil {
		c.vc.SetToken("")
		// An unreachable Vault is a transient/infra problem, distinct from a
		// genuinely invalid token. Preserve that distinction for callers.
		if cat := classify(err); errors.Is(cat, ErrUnreachable) {
			return fmt.Errorf("%w: %v", ErrUnreachable, err)
		}
		// Reachable Vault rejected the token (403) or it has no TTL left:
		// from the caller's perspective a fresh login is required.
		return fmt.Errorf("%w: cached token rejected: %v", ErrLoginRequired, err)
	}
	return nil
}

// Login runs the configured fresh-auth flow unconditionally, ignoring any
// cached token — the equivalent of `dotvault login`. OIDC opens a browser;
// LDAP prompts for a password (and MFA) on the terminal. On success the new
// token is written to the configured token file (matching dotvault) and held
// on the Client. A login that runs but fails to yield a token returns an
// error wrapping ErrAuthFailed.
//
// Login requires an interactive context for LDAP (a terminal on stdin); it
// will not prompt when stdin is not a TTY and instead returns an error
// wrapping ErrAuthFailed. Headless callers (including the Windows GUI-subsystem
// binary, which has no console) should drive auth through OIDC, or stick to
// AuthenticateCached and surface ErrLoginRequired to the operator.
func (c *Client) Login(ctx context.Context) error {
	mgr, err := c.manager()
	if err != nil {
		return err
	}
	if err := mgr.Login(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrAuthFailed, err)
	}
	return nil
}

// manager builds an auth.Manager wired to this Client's Vault client and
// config. The Username is the OS-derived identity (used for the LDAP prompt
// and consistent with the path convention).
func (c *Client) manager() (*auth.Manager, error) {
	username, err := paths.Username()
	if err != nil {
		return nil, fmt.Errorf("dotvault: resolve username: %w", err)
	}
	return &auth.Manager{
		VaultClient:   c.vc,
		TokenFilePath: c.cfg.TokenFile,
		AuthMethod:    c.cfg.Vault.AuthMethod,
		AuthMount:     c.cfg.Vault.AuthMount,
		AuthRole:      c.cfg.Vault.AuthRole,
		Username:      username,
	}, nil
}

// IdentityName returns the <user> path segment dotvault uses to lay out
// kv/users/<user>/.... This is the OS username with any DOMAIN\ prefix
// stripped — NOT a value derived from the Vault token (display_name, entity
// name, or token metadata). Consumers reading per-user secrets MUST use this
// so they hit the same path dotvault writes to.
//
// It performs no Vault call and takes no context: the value comes from the OS
// account the process runs as. Callers that need secrets written by a given
// dotvault instance must run as the same OS user.
func (c *Client) IdentityName() (string, error) {
	name, err := paths.Username()
	if err != nil {
		return "", fmt.Errorf("dotvault: resolve identity: %w", err)
	}
	return name, nil
}

// Token returns the Vault token the Client currently holds, or "" if none.
// Exposed so a caller can pass the same token to other Vault-aware tooling.
func (c *Client) Token() string {
	return c.vc.Token()
}

// ReadKVField reads a single field from a KV v2 secret at the given mount and
// path. It returns:
//
//   - (value, true, nil)  when the secret exists and the field is present;
//   - ("", false, nil)    when the secret exists but the field is absent, OR
//     the secret path does not exist (both are "the field you asked for isn't
//     there", which callers map to a missing_field outcome);
//   - ("", false, err)    for transport/auth failures, wrapping ErrUnreachable
//     or ErrDenied.
//
// Non-string field values are stringified via fmt's %v: numbers and bools
// render as you'd expect; a nested object or array renders as its Go-syntax
// form (map[...]/[...]). dotvault stores credential material as strings, so in
// practice the fields a consumer reads are already strings.
func (c *Client) ReadKVField(ctx context.Context, mount, path, field string) (string, bool, error) {
	secret, err := c.vc.ReadKVv2(ctx, mount, path)
	if err != nil {
		return "", false, fmt.Errorf("%w: read %s/%s: %v", classify(err), mount, path, err)
	}
	if secret == nil {
		// Path does not exist — treat as missing field, not an error, so the
		// caller distinguishes "no secret" from "couldn't reach Vault".
		return "", false, nil
	}
	raw, ok := secret.Data[field]
	if !ok {
		return "", false, nil
	}
	if s, isString := raw.(string); isString {
		return s, true, nil
	}
	return fmt.Sprintf("%v", raw), true, nil
}

// ReadUserSecret reads a single field from kv/users/<IdentityName>/<service>,
// using the configured KV mount and user prefix. It is IdentityName +
// ReadKVField composed, with dotvault owning the path layout end-to-end:
// {KVMount}/{UserPrefix}{identity}/{service}, field {field}.
//
// Example: ReadUserSecret(ctx, "gh", "oauth_token") reads the oauth_token
// field of kv/users/<user>/gh. Return semantics match ReadKVField.
func (c *Client) ReadUserSecret(ctx context.Context, service, field string) (string, bool, error) {
	identity, err := c.IdentityName()
	if err != nil {
		return "", false, err
	}
	path := c.cfg.Vault.UserPrefix + identity + "/" + service
	return c.ReadKVField(ctx, c.cfg.Vault.KVMount, path, field)
}
