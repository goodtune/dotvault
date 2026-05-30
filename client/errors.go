package client

import (
	"errors"
	"net/http"

	vaultapi "github.com/hashicorp/vault/api"
)

// Sentinel errors expose a small, stable set of failure categories so callers
// can map outcomes onto metrics without string-matching. Every error returned
// by this package that fits one of these categories wraps the corresponding
// sentinel, so callers use errors.Is rather than comparing values directly.
//
// The categories line up with the outcomes a consumer tracks:
//
//	success         → nil error
//	missing_token   → ErrLoginRequired
//	denied          → ErrDenied, ErrAuthFailed
//	unreachable     → ErrUnreachable
//	missing_field   → (value, false, nil) from ReadKVField/ReadUserSecret
//
// ErrAuthFailed covers an interactive login that started but did not yield a
// usable token (bad password, declined MFA, OIDC callback error). It is
// distinct from ErrLoginRequired, which means "no usable token was found and
// no interactive login was attempted"; a consumer that buckets outcomes for
// metrics can fold it into the same "denied" label as ErrDenied, but it is a
// separate sentinel so callers that want to distinguish "wrong creds" from
// "no creds offered" can.
//
// Every categorised error that has an underlying cause wraps both the sentinel
// and that cause with %w, so a caller can errors.Is the sentinel and errors.As
// the cause (a *vaultapi.ResponseError) from the same value. (A few errors have
// no Vault cause to wrap — e.g. the no-token branch of AuthenticateCached or a
// construction failure in New — and wrap only the sentinel.) The wrapped text
// comes from Vault's API error (which echoes the server response body, never
// the request token) plus the mount/path being read — none of it carries token
// material, so callers may log these errors verbatim.
var (
	// ErrLoginRequired indicates no usable cached token was found (neither
	// VAULT_TOKEN nor the token file yielded a token that LookupSelf
	// accepts) and no interactive login was performed. Returned by
	// AuthenticateCached, and by Authenticate when the caller has opted out
	// of interactive login.
	ErrLoginRequired = errors.New("dotvault: login required (no valid cached token)")

	// ErrAuthFailed indicates the configured fresh-auth flow (Login, or the
	// login fallback inside Authenticate) ran but did not yield a usable
	// token. This covers a genuine auth failure (bad password, declined MFA,
	// OIDC callback error, no TTY for an LDAP prompt) as well as a
	// misconfigured auth method (an unsupported AuthMethod, or AuthMethod
	// "token" with no token on disk — for which Login has nothing to do).
	// It is distinct from ErrLoginRequired, which means a fresh login was
	// not attempted at all.
	ErrAuthFailed = errors.New("dotvault: authentication failed")

	// ErrDenied indicates Vault rejected the request with 401/403 — the
	// token is missing the required policy, or was revoked between the
	// LookupSelf check and the read (see TestReadKVField_Denied).
	ErrDenied = errors.New("dotvault: vault denied the request")

	// ErrUnreachable indicates the Vault server could not be reached
	// (DNS, connection refused, TLS handshake, timeout) or returned a 5xx.
	ErrUnreachable = errors.New("dotvault: vault unreachable")
)

// classify maps a raw Vault API error onto one of the sentinel categories.
// It is used to wrap transport/auth failures from LookupSelf and KV reads so
// the public surface stays errors.Is-able. A nil error returns nil.
func classify(err error) error {
	if err == nil {
		return nil
	}
	var respErr *vaultapi.ResponseError
	if errors.As(err, &respErr) {
		switch {
		case respErr.StatusCode == http.StatusUnauthorized,
			respErr.StatusCode == http.StatusForbidden:
			return ErrDenied
		case respErr.StatusCode >= 500:
			return ErrUnreachable
		default:
			// 4xx other than 401/403 (e.g. 400). A KV-read 404 never
			// reaches here — ReadKVv2 intercepts it and ReadKVField returns
			// found == false — so this bucket is for genuine client errors
			// on other endpoints. Treat as denied-ish; the caller still gets
			// the wrapped detail.
			return ErrDenied
		}
	}
	// No HTTP response at all — DNS failure, connection refused, TLS error,
	// context deadline. Everything in this bucket is "couldn't talk to Vault".
	return ErrUnreachable
}
