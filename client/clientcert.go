package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/clientcert"
	"github.com/goodtune/dotvault/internal/paths"
)

// handshakeTimeout bounds one certificate lookup made from a TLS handshake,
// where crypto/tls offers no context. It matches the sign timeout inside
// internal/clientcert, so a handshake that has to wait on a sign outlasts
// nothing but that sign.
const handshakeTimeout = 30 * time.Second

// certReplaceInterval is the shortest gap between two attempts to replace a
// token Vault rejected while signing. Each attempt costs a lookup-self (and,
// when the token really is dead, an AuthenticateCached), and a consumer may
// ask for the certificate on every handshake; without a floor, a token that
// stays rejected would turn each handshake into Vault round trips. It matches
// the signing source's own floor between sign attempts.
const certReplaceInterval = 10 * time.Second

// ClientCertificate is a mutual-TLS client certificate and its private key, in
// the forms a consumer needs. It is the same certificate the daemon serves
// through the filesystem mount and Docker volumes.
//
// The PEM slices are copies; modifying them affects no other caller. They hold
// a private key, so keep them out of logs and error messages.
type ClientCertificate struct {
	// CertPEM is the leaf certificate followed by its CA chain.
	CertPEM []byte
	// KeyPEM is the private key, PKCS#8 PEM.
	KeyPEM []byte
	// CombinedPEM is CertPEM followed by KeyPEM, the single file some tools
	// (curl --cert) accept.
	CombinedPEM []byte
	// NotAfter is when the leaf expires. A certificate is replaced well before
	// that; call ClientCertificate again (or use TLSConfig) rather than
	// holding this one.
	NotAfter time.Time
	// Certificate is the same pair assembled for crypto/tls.
	Certificate tls.Certificate
}

// ClientCertificate returns the client certificate this Config describes: the
// certificate this host already logs in to Vault with (plain "mtls"), else a
// short-lived one signed on demand by Vault's PKI engine with the Client's
// token and held only in memory. The same value comes back until it is due
// for replacement, so calling it for every request is cheap.
//
// It never prompts. A held certificate needs no token and is served without
// one. Signing needs one, so when none is held the call first tries
// AuthenticateCached (cached token, peer socket, enrolled certificate) and
// retries once; if that finds nothing the error wraps ErrLoginRequired.
//
// The token is re-resolved when Vault rejects it, so a long-lived Client
// follows the daemon's re-login, a peer's re-borrow, or a token reaching its
// max TTL without any action from the caller. That happens when the call that
// notices is due to replace the certificate anyway: while the current
// certificate is still valid it keeps being served and the replacement token
// signs the next one; when nothing valid is left the call fails transiently
// (signing is paced, at most one attempt per ten seconds) and a later one
// succeeds.
//
// Errors are categorised for errors.Is: ErrNotConfigured (section disabled, or
// no PKI role and no usable held certificate), ErrLoginRequired, ErrDenied (a
// 401/403 from Vault, typically a policy without pki/sign), ErrUnreachable
// (transport failure or a 5xx). A signing attempt made too soon after the last
// one, with no failure on record, wraps ErrSignPaced; it is transient and a
// later call succeeds. While a failed signing is backing off, the call returns
// that signing's error again rather than ErrSignPaced.
func (c *Client) ClientCertificate(ctx context.Context) (*ClientCertificate, error) {
	src, err := c.clientCertSource()
	if err != nil {
		return nil, err
	}
	used := c.vc.Token()
	pair, err := src.Current(ctx)
	if errors.Is(err, clientcert.ErrNoToken) {
		// Only a sign needs a token, so authenticate only now: a held
		// certificate, or an unexpired cached one, must not be refused for
		// want of a token it never needed.
		if aerr := c.authenticateForCert(ctx); aerr != nil {
			return nil, aerr
		}
		used = c.vc.Token()
		pair, err = src.Current(ctx)
	}
	if rejected := c.signRejection(src, pair, err); rejected != nil {
		replaced, rerr := c.replaceRejectedToken(ctx, used)
		switch {
		case replaced && err != nil:
			pair, err = src.Current(ctx)
		case rerr != nil && err != nil:
			// The token is dead and nothing replaced it: say so, rather
			// than reporting the sign's 403 as a policy problem.
			return nil, rerr
		}
	}
	if err != nil {
		return nil, mapClientCertErr(ctx, err)
	}
	tc, err := pair.TLSCertificate()
	if err != nil {
		// tls.X509KeyPair's errors name the problem, never the bytes.
		return nil, fmt.Errorf("dotvault: assemble client certificate: %w", err)
	}
	return &ClientCertificate{
		CertPEM:     append([]byte(nil), pair.CertPEM...),
		KeyPEM:      append([]byte(nil), pair.KeyPEM...),
		CombinedPEM: pair.Combined(),
		NotAfter:    pair.NotAfter,
		Certificate: tc,
	}, nil
}

// TLSConfig returns a copy of base (nil is fine) whose GetClientCertificate
// presents the current client certificate, looked up on every handshake so a
// rotation needs no action from the caller. base is not modified.
//
// It reports ErrNotConfigured immediately when the Config cannot produce a
// certificate at all, rather than leaving that to fail every handshake. Later
// errors, from the lookup at handshake time, fail the handshake and are the
// ones ClientCertificate returns.
//
// crypto/tls gives the callback no context, so each lookup runs under a
// bounded one (30 seconds). A handshake can therefore block while a
// certificate is signed; this happens at most once per certificate lifetime,
// since concurrent handshakes share one signing and later ones are answered
// from memory.
func (c *Client) TLSConfig(base *tls.Config) (*tls.Config, error) {
	if _, err := c.clientCertSource(); err != nil {
		return nil, err
	}
	var cfg *tls.Config
	if base != nil {
		cfg = base.Clone()
	} else {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
		defer cancel()
		cc, err := c.ClientCertificate(ctx)
		if err != nil {
			return nil, err
		}
		return &cc.Certificate, nil
	}
	return cfg, nil
}

// clientCertSource builds the certificate source once, using this Client's own
// Vault client to sign. A construction failure is a configuration problem and
// is reported as ErrNotConfigured with the cause attached.
func (c *Client) clientCertSource() (clientcert.Source, error) {
	c.certOnce.Do(func() {
		cc := c.cfg.ClientCert
		if !cc.Enabled {
			c.certErr = fmt.Errorf("%w: the client_cert section is not enabled", ErrNotConfigured)
			return
		}
		// The OS account, not IdentityName: WithIdentity names the KV path
		// segment, while the held envelope's identity check and
		// {{.os_user}} are about who this process runs as — the same value
		// the daemon and the facade's own certificate login use.
		user, err := paths.Username()
		if err != nil {
			c.certErr = fmt.Errorf("dotvault: resolve OS user for the client certificate: %w", err)
			return
		}
		src, err := clientcert.NewFromParams(clientcert.Params{
			Enabled:       true,
			Held:          c.cfg.clientCertHeld(),
			Method:        c.cfg.Vault.AuthMethod,
			StorageDir:    c.cfg.Vault.MTLS.StorageDir,
			ReissueBefore: c.cfg.Vault.ReissueBefore,
			Ephemeral: clientcert.EphemeralOptions{
				PKIMount:   cc.PKIMount,
				PKIRole:    cc.PKIRole,
				CommonName: cc.CommonName,
				TTL:        cc.TTL,
				KeyType:    cc.KeyType,
				KeyBits:    cc.KeyBits,
				OSUser:     user,
				Now:        c.now,
			},
		}, c.vc)
		if err != nil {
			c.certErr = fmt.Errorf("%w: %w", ErrNotConfigured, err)
			return
		}
		if src == nil {
			c.certErr = fmt.Errorf("%w: no certificate source", ErrNotConfigured)
			return
		}
		c.certSrc = src
	})
	return c.certSrc, c.certErr
}

// authenticateForCert makes the Client hold a token without prompting, for a
// signing that needs one. Serialised because AuthenticateCached is not safe
// for concurrent calls and concurrent TLS handshakes can arrive together; a
// caller that finds a token already adopted by another skips the work.
func (c *Client) authenticateForCert(ctx context.Context) error {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	if c.vc.Token() != "" {
		return nil
	}
	return c.AuthenticateCached(ctx)
}

// lastReporter is implemented by every clientcert source: the most recent pair
// served and the most recent error, read without signing.
type lastReporter interface {
	Last() (*clientcert.Pair, error)
}

// signRejection returns the token rejection behind a Current answer, or nil.
// A failed refresh does not always surface as err: while the cached
// certificate is still valid the source keeps serving it, so a token that died
// is only visible as a pair already past its RefreshAt together with the
// source's last error.
func (c *Client) signRejection(src clientcert.Source, pair *clientcert.Pair, err error) error {
	if err != nil {
		if auth.IsTokenRejected(err) {
			return err
		}
		return nil
	}
	if pair == nil || pair.Source != clientcert.SourceEphemeral || c.clock().Before(pair.RefreshAt) {
		return nil
	}
	lr, ok := src.(lastReporter)
	if !ok {
		return nil
	}
	if _, last := lr.Last(); last != nil && auth.IsTokenRejected(last) {
		return last
	}
	return nil
}

// replaceRejectedToken re-resolves the Client's token after Vault rejected
// rejected while signing. It reports whether the Client now holds a different
// token. A 403 from pki/sign is also what a policy without that path answers,
// so the token is first checked with lookup-self and kept when Vault still
// accepts it; only a token Vault refuses there is dropped and replaced through
// AuthenticateCached, whose error is returned when nothing replaces it.
// Attempts are at least certReplaceInterval apart.
func (c *Client) replaceRejectedToken(ctx context.Context, rejected string) (bool, error) {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	if cur := c.vc.Token(); cur != rejected {
		// Another caller replaced it already.
		return cur != "", nil
	}
	now := c.clock()
	if !c.certReplacedAt.IsZero() && now.Sub(c.certReplacedAt) < certReplaceInterval {
		return false, nil
	}
	c.certReplacedAt = now
	if rejected != "" {
		if _, err := c.vc.LookupSelf(ctx); err == nil || !auth.IsTokenRejected(err) {
			// Still accepted (the denial is the role or policy), or Vault
			// could not answer: either way this token is not known dead.
			return false, nil
		}
	}
	c.vc.SetToken("")
	if err := c.AuthenticateCached(ctx); err != nil {
		return false, err
	}
	return c.vc.Token() != rejected, nil
}

// clock is the time the certificate path reads.
func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// mapClientCertErr maps an error from a clientcert.Source onto this package's
// sentinels. It never adds PEM or key bytes: the messages it wraps are Vault's
// API errors and this package's own descriptions.
func mapClientCertErr(ctx context.Context, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, clientcert.ErrNoToken):
		return fmt.Errorf("%w: no token to sign a client certificate with: %w", ErrLoginRequired, err)
	case errors.Is(err, clientcert.ErrSignPaced), errors.Is(err, clientcert.ErrNoUsername):
		// Kept reachable but not categorised: pacing is transient and says
		// nothing about Vault, and a missing username is a deployment fault
		// no existing sentinel names.
		return fmt.Errorf("dotvault: client certificate: %w", err)
	case errors.Is(err, auth.ErrNoCertCredential), errors.Is(err, auth.ErrHeldNotExportable):
		// Held certificate unusable and no role to sign one instead.
		return fmt.Errorf("%w: no usable held certificate and no PKI role to sign one: %w", ErrNotConfigured, err)
	case ctx.Err() != nil:
		return fmt.Errorf("dotvault: client certificate: %w", err)
	}
	var respErr *vaultapi.ResponseError
	var urlErr *url.Error
	var netErr net.Error
	if errors.As(err, &respErr) {
		return fmt.Errorf("%w: client certificate: %w", classify(err), err)
	}
	if errors.As(err, &urlErr) || errors.As(err, &netErr) {
		return fmt.Errorf("%w: client certificate: %w", ErrUnreachable, err)
	}
	// A local failure (key generation, template, a response that does not
	// match the key): not a Vault verdict, so left uncategorised rather than
	// reported as an outage.
	return fmt.Errorf("dotvault: client certificate: %w", err)
}
