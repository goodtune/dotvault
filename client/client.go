// Package client is dotvault's public, importable Go API. It exposes
// dotvault's connectivity, token-resolution, login, and user-path conventions
// so any Go module can talk to the same Vault, authenticate the same way, and
// read from the exact path dotvault writes to — without re-implementing any of
// it and risking silent divergence.
//
// dotvault remains the single source of truth for:
//
//   - connectivity (Vault address, TLS, CA),
//   - token-resolution order (DOTVAULT_TOKEN env → token file → interactive
//     login; VAULT_TOKEN is deliberately ignored — it belongs to the `vault`
//     CLI and must not leak into dotvault's session),
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
//	cli, err := client.New(cfg) // optionally: client.New(cfg, client.WithIdentity("alice"))
//	if err := cli.Authenticate(ctx); err != nil {
//	    // categorise with errors.Is, one sentinel at a time. Authenticate
//	    // yields ErrUnreachable or ErrAuthFailed (it consumes the no-token
//	    // case and logs in); AuthenticateCached is what surfaces
//	    // ErrLoginRequired.
//	    //   errors.Is(err, client.ErrUnreachable)
//	    //   errors.Is(err, client.ErrAuthFailed)
//	    return err
//	}
//	tok, found, err := cli.ReadUserSecret(ctx, "gh", "oauth_token")
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
	cfg      Config
	vc       *vault.Client
	identity string // overrides the OS-user identity when non-empty (see WithIdentity)
}

// Option configures a Client at construction time. Options are the
// forward-compatible extension point for New: new behaviour can be added as
// an Option without changing New's signature, so existing callers keep
// compiling. See WithIdentity.
//
// Options are applied to the already-built Client after the underlying Vault
// client is constructed, so they tune the Client's own behaviour. An option
// that needs to influence Vault-client construction itself (a custom HTTP
// transport, say) would require New to grow a separate build step first; the
// current options do not.
type Option func(*Client)

// WithIdentity overrides the identity segment used to lay out
// kv/users/<identity>/... paths. By default the Client derives it from the OS
// user (see IdentityName), which assumes the consumer runs as the same OS
// account as the dotvault that wrote the secrets. A consumer that runs under a
// different account (a service, a container) — or a test that needs a
// deterministic identity — sets this explicitly. It does not change the
// username used for an interactive LDAP login prompt, only the KV path.
//
// The value is interpolated verbatim into the Vault KV path and is not
// sanitised — it is a caller-controlled value used by the caller's own token,
// and what that token can read is bounded by its Vault policy regardless of
// the path composed, so this grants no authority the token didn't already
// have. An empty string is ignored (the OS user is used).
func WithIdentity(name string) Option {
	return func(c *Client) { c.identity = name }
}

// New constructs a Client from cfg, applying any options. It builds the
// underlying Vault client (applying TLS/CA settings) but performs no network
// calls and does not authenticate — call Authenticate (or Login) before
// reading secrets.
//
// Empty optional fields in cfg are filled with dotvault's defaults (KVMount
// "kv", UserPrefix "users/", TokenFile ~/.dotvault-token), so a directly
// constructed Config behaves the same as one returned by LoadConfig.
func New(cfg *Config, opts ...Option) (*Client, error) {
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
	c := &Client{cfg: resolved, vc: vc}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c, nil
}

// Authenticate makes the Client hold a usable Vault token, following
// dotvault's precedence:
//
//  1. DOTVAULT_TOKEN environment variable,
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
		// No usable cached token. Before dropping into the interactive flow
		// — which for LDAP prompts for a password on the terminal *before*
		// it ever contacts Vault — confirm the server is actually reachable,
		// so the documented "short-circuit ErrUnreachable without prompting"
		// contract holds even on the no-token path. sys/health needs no auth,
		// and the Vault SDK sends uninitcode/sealedcode/standbycode=299 on the
		// health request so an uninitialised, sealed, or standby node returns
		// a non-error 2xx — meaning ServerHealth errors only on a genuine
		// transport failure (DNS, refused, TLS, timeout), which is exactly the
		// reachability signal we want.
		if _, herr := c.vc.ServerHealth(ctx); herr != nil {
			return fmt.Errorf("%w: %w", ErrUnreachable, herr)
		}
		// Reachable — fall through to the interactive flow below.
	default:
		return err
	}
	return c.Login(ctx)
}

// AuthenticateCached resolves a usable Vault token, trying each source in turn
// and validating it with a LookupSelf: DOTVAULT_TOKEN, then the token file,
// then — if a peer socket is configured — by borrowing a live token from the
// peer dotvault over that socket. It never initiates an interactive login. It
// returns nil once a candidate validates, an error wrapping ErrLoginRequired
// if no source yields a usable token (missing, expired, or revoked), or an
// error wrapping ErrUnreachable if Vault cannot be reached to validate.
//
// A cached token that a *reachable* Vault rejects does not end the search: the
// peer socket is tried next, so a remote host with a stale local token file
// but a live peer still recovers — mirroring the daemon's startup path, which
// clears a rejected token and then borrows. An ErrUnreachable from validating
// any candidate short-circuits immediately: when Vault is down a borrowed
// token could not be validated either, so there is nothing to gain by trying.
//
// The socket borrow stays within the side-effect-free contract: it is a plain
// HTTP GET over a Unix socket (the equivalent of
// `curl --unix-socket <path> http://localhost/api/v1/token`) — no browser, no
// password prompt — so a consumer that runs on a host with no usable local
// token but a live peer socket (the SSH RemoteForward topology) authenticates
// without an interactive Login. Best-effort: a missing/stale socket simply
// yields no candidate.
//
// This is the entry point for callers that must remain side-effect-free — no
// browser pop, no password prompt — such as a `doctor`/preflight check.
func (c *Client) AuthenticateCached(ctx context.Context) error {
	// tryCandidate validates tok against Vault. ok reports a usable token (the
	// client is left holding it). When not ok, the token is cleared; unreachable
	// is non-nil iff the failure was an unreachable Vault (the caller must stop
	// and surface it rather than trying further candidates).
	tryCandidate := func(tok string) (ok bool, unreachable error) {
		if tok == "" {
			return false, nil
		}
		c.vc.SetToken(tok)
		if _, err := c.vc.LookupSelf(ctx); err != nil {
			c.vc.SetToken("")
			// An unreachable Vault is a transient/infra problem distinct from a
			// genuinely invalid token. Wrap the cause too (multiple %w) so callers
			// can errors.As it.
			if errors.Is(classify(err), ErrUnreachable) {
				return false, fmt.Errorf("%w: %w", ErrUnreachable, err)
			}
			// Reachable Vault rejected the token (403) or it has no TTL left.
			return false, nil
		}
		return true, nil
	}

	// Candidates 1 & 2: DOTVAULT_TOKEN, then the token file — validated
	// separately and in that order. ResolveToken is deliberately NOT used here:
	// it collapses env and file into a single env-first candidate, so a stale
	// DOTVAULT_TOKEN would mask a valid token file (Vault rejects the env token
	// and the file is never tried). Reading them apart lets a fresh token file
	// recover even when the env var is stale. A file read error (file present
	// but unreadable) is treated as no candidate, matching ResolveToken's own
	// best-effort handling.
	cachedRejected := false
	fileToken, _ := auth.ReadTokenFile(c.cfg.TokenFile)
	seen := map[string]bool{}
	for _, cand := range []string{auth.ReadTokenEnv(), fileToken} {
		if cand == "" || seen[cand] {
			continue
		}
		seen[cand] = true
		if ok, unreachable := tryCandidate(cand); ok {
			return nil
		} else if unreachable != nil {
			return unreachable
		}
		// A token was present but a reachable Vault rejected it. Keep trying the
		// remaining candidates (the other source, then the peer socket) before
		// declaring login required.
		cachedRejected = true
	}

	// Candidate 3: borrow from the peer socket. Best-effort — a missing/stale
	// socket or an unauthenticated peer yields "" and falls through.
	if c.cfg.Vault.TokenSocket != "" {
		borrowed, _ := auth.FetchTokenFromSocket(ctx, c.cfg.Vault.TokenSocket)
		if borrowed != "" && !seen[borrowed] {
			if ok, unreachable := tryCandidate(borrowed); ok {
				return nil
			} else if unreachable != nil {
				return unreachable
			}
			cachedRejected = true
		}
	}

	if cachedRejected {
		// At least one source produced a token the reachable Vault rejected.
		return fmt.Errorf("%w: cached token rejected and no usable replacement from DOTVAULT_TOKEN, token file, or peer socket",
			ErrLoginRequired)
	}
	// No source produced a token at all.
	switch {
	case c.cfg.TokenFile == "" && c.cfg.Vault.TokenSocket == "":
		return fmt.Errorf("%w: no DOTVAULT_TOKEN set and no token file configured",
			ErrLoginRequired)
	case c.cfg.TokenFile == "":
		return fmt.Errorf("%w: no DOTVAULT_TOKEN set, no token file configured, and no token borrowable from peer socket %s",
			ErrLoginRequired, c.cfg.Vault.TokenSocket)
	case c.cfg.Vault.TokenSocket == "":
		return fmt.Errorf("%w: no DOTVAULT_TOKEN and no token at %s",
			ErrLoginRequired, c.cfg.TokenFile)
	default:
		return fmt.Errorf("%w: no DOTVAULT_TOKEN, no token at %s, and no token borrowable from peer socket %s",
			ErrLoginRequired, c.cfg.TokenFile, c.cfg.Vault.TokenSocket)
	}
}

// Login runs the configured fresh-auth flow unconditionally, ignoring any
// cached token — the equivalent of `dotvault login`. OIDC opens a browser;
// LDAP prompts for a password (and MFA) on the terminal. On success the new
// token is written to the configured token file (matching dotvault) and held
// on the Client. Any failure to produce a token — a genuine auth failure or a
// misconfigured auth method (unsupported AuthMethod, or "token" with nothing
// on disk) — returns an error wrapping ErrAuthFailed.
//
// Login requires an interactive context for LDAP (a terminal on stdin); it
// will not prompt when stdin is not a TTY and instead returns an error
// wrapping ErrAuthFailed. Headless callers (including the Windows GUI-subsystem
// binary, which has no console) should drive auth through OIDC, or stick to
// AuthenticateCached and surface ErrLoginRequired to the operator.
func (c *Client) Login(ctx context.Context) error {
	if err := c.manager().Login(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}
	return nil
}

// manager builds an auth.Manager wired to this Client's Vault client and
// config. Username is the OS-derived name and is only used as the default for
// the LDAP password prompt; it is deliberately independent of WithIdentity
// (which overrides only the kv/users/<identity>/... path segment, not the
// login credential). Resolution is best-effort: OIDC and token auth don't need
// a username, so a failure to resolve it (e.g. user.Current erroring in a
// minimal container) must not break those flows — it's left empty and only an
// LDAP login would notice.
func (c *Client) manager() *auth.Manager {
	username, _ := paths.Username()
	return &auth.Manager{
		VaultClient:      c.vc,
		TokenFilePath:    c.cfg.TokenFile,
		AuthMethod:       c.cfg.Vault.AuthMethod,
		AuthMount:        c.cfg.Vault.AuthMount,
		AuthRole:         c.cfg.Vault.AuthRole,
		OIDCCallbackPort: c.cfg.Vault.OIDCCallbackPort,
		TokenSocket:      c.cfg.Vault.TokenSocket,
		Policy: auth.PolicyConstraint{
			Policies:        c.cfg.Vault.Policies,
			NoDefaultPolicy: c.cfg.Vault.NoDefaultPolicy,
		},
		Username: username,
	}
}

// IdentityName returns the <user> path segment dotvault uses to lay out
// kv/users/<user>/.... This is the OS username with any DOMAIN\ prefix
// stripped — NOT a value derived from the Vault token (display_name, entity
// name, or token metadata). Consumers reading per-user secrets MUST use this
// so they hit the same path dotvault writes to.
//
// It performs no Vault call and takes no context: the value comes from the OS
// account the process runs as, unless overridden with WithIdentity. Callers
// that need secrets written by a given dotvault instance must either run as
// the same OS user or set WithIdentity to that user's name.
func (c *Client) IdentityName() (string, error) {
	if c.identity != "" {
		return c.identity, nil
	}
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
// Caveat: Vault answers a read against a missing or disabled KV mount with a
// 404, which is indistinguishable here from a not-yet-written secret — both
// yield ("", false, nil). So a wrong mount (a mis-set kv_mount) reads as
// "not enrolled" rather than an error. A caller that wants to tell a
// misconfigured deployment apart from an un-enrolled user should verify the
// mount independently (e.g. a known-present sentinel path) rather than infer
// it from found == false.
//
// Non-string field values are stringified via fmt's %v: numbers and bools
// render as you'd expect; a nested object or array renders as its Go-syntax
// form (map[...]/[...]). dotvault stores credential material as strings, so in
// practice the fields a consumer reads are already strings.
func (c *Client) ReadKVField(ctx context.Context, mount, path, field string) (string, bool, error) {
	secret, err := c.vc.ReadKVv2(ctx, mount, path)
	if err != nil {
		return "", false, fmt.Errorf("%w: read %s/%s: %w", classify(err), mount, path, err)
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

// Reader is the read-side contract a consumer depends on after a Client is
// authenticated. It exists so downstream code can accept this narrow
// interface and substitute a fake in tests without standing up a Vault — the
// shape is owned here so every consumer fakes the same thing and the methods
// can't drift between them. *Client satisfies it.
//
// Authentication (Authenticate/Login) is intentionally excluded: it has side
// effects (token file writes, browser/terminal interaction) that belong to
// process wiring, not to the unit under test. Construct and authenticate a
// real *Client in main; depend on Reader everywhere a secret is consumed.
type Reader interface {
	// IdentityName returns the kv/users/<identity>/... path segment.
	IdentityName() (string, error)
	// ReadKVField reads one field of a KV v2 secret. See Client.ReadKVField.
	ReadKVField(ctx context.Context, mount, path, field string) (string, bool, error)
	// ReadUserSecret reads kv/users/<identity>/<service> field <field>.
	ReadUserSecret(ctx context.Context, service, field string) (string, bool, error)
}

// Compile-time assertion that *Client satisfies Reader.
var _ Reader = (*Client)(nil)
