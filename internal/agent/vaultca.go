package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// defaultCertTTL is the vault-ca certificate lifetime applied when a source
// omits `ttl`.
const defaultCertTTL = 15 * time.Minute

// certSigner mints an SSH certificate from a Vault SSH-CA role. Abstracted so
// the source is unit-testable without a live Vault SSH secrets engine.
type certSigner interface {
	SignSSHCert(ctx context.Context, mount, role string, pub ssh.PublicKey, principals []string, ttl time.Duration) (*ssh.Certificate, error)
}

// vaultCASource presents a short-lived certificate minted by a Vault SSH CA.
// In ephemeral mode it generates an in-memory Ed25519 keypair at startup; the
// private key never lands on disk. The certificate is cached until shortly
// before expiry and transparently re-minted on the next List/Sign — which is
// what keeps long-lived forwarded session chains working without manual
// re-issue.
type vaultCASource struct {
	name       string
	signer     certSigner
	mount      string
	role       string
	principals []string
	username   string
	ttl        time.Duration
	now        func() time.Time

	base ssh.Signer // ephemeral key

	mu         sync.Mutex
	cert       *ssh.Certificate
	certSigner ssh.Signer
}

func newVaultCASource(name string, signer certSigner, mount, role string, principals []string, username string, ttl time.Duration, ephemeral bool) (Source, error) {
	if !ephemeral {
		// Non-ephemeral CA keys (a persisted private key trusted by the CA)
		// are a separate work item; only ephemeral mode is wired today.
		return newErrSource(name, "vault-ca", fmt.Errorf("vault-ca requires ephemeral_key: true")), nil
	}
	if ttl <= 0 {
		ttl = defaultCertTTL
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	base, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return nil, fmt.Errorf("ephemeral signer: %w", err)
	}
	return &vaultCASource{
		name:       name,
		signer:     signer,
		mount:      mount,
		role:       role,
		principals: principals,
		username:   username,
		ttl:        ttl,
		now:        time.Now,
		base:       base,
	}, nil
}

func (s *vaultCASource) Name() string { return s.name }
func (s *vaultCASource) Type() string { return "vault-ca" }

// ensureCert returns a currently-valid certificate signer, minting a fresh
// certificate when none is cached or the cached one is within its renew window.
func (s *vaultCASource) ensureCert(ctx context.Context) (*ssh.Certificate, ssh.Signer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cert != nil && !s.needsRenew(s.cert) {
		return s.cert, s.certSigner, nil
	}

	principals, err := renderPrincipals(s.principals, s.username)
	if err != nil {
		return nil, nil, err
	}
	cert, err := s.signer.SignSSHCert(ctx, s.mount, s.role, s.base.PublicKey(), principals, s.ttl)
	if err != nil {
		return nil, nil, fmt.Errorf("mint certificate: %w", err)
	}
	cs, err := ssh.NewCertSigner(cert, s.base)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate signer: %w", err)
	}
	s.cert, s.certSigner = cert, cs
	return cert, cs, nil
}

// needsRenew reports whether cert is close enough to expiry to re-mint. A
// certificate with no expiry (CertTimeInfinity) is never renewed.
func (s *vaultCASource) needsRenew(cert *ssh.Certificate) bool {
	if cert.ValidBefore == ssh.CertTimeInfinity {
		return false
	}
	expiry := time.Unix(int64(cert.ValidBefore), 0)
	skew := s.ttl / 10
	if skew < 30*time.Second {
		skew = 30 * time.Second
	}
	return s.now().Add(skew).After(expiry)
}

func certExpiry(cert *ssh.Certificate) time.Time {
	if cert.ValidBefore == ssh.CertTimeInfinity {
		return time.Time{}
	}
	return time.Unix(int64(cert.ValidBefore), 0)
}

func (s *vaultCASource) Identities(ctx context.Context) ([]Identity, error) {
	cert, _, err := s.ensureCert(ctx)
	if err != nil {
		return nil, err
	}
	return []Identity{{
		PubKey:  cert,
		Comment: s.name,
		Expiry:  certExpiry(cert),
	}}, nil
}

func (s *vaultCASource) Sign(ctx context.Context, key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, bool, error) {
	if !s.mayOwn(key) {
		return nil, false, nil
	}
	cert, cs, err := s.ensureCert(ctx)
	if err != nil {
		return nil, false, err
	}
	if !keyEqual(key, cert) && !keyEqual(key, s.base.PublicKey()) {
		return nil, false, nil
	}
	sig, err := signData(cs, data, flags)
	if err != nil {
		return nil, false, fmt.Errorf("sign: %w", err)
	}
	return sig, true, nil
}

// mayOwn reports whether key could plausibly belong to this source without
// minting a certificate: true when it matches the stable ephemeral base key
// or the currently cached certificate (if any). It can't rule out a key on a
// cold cache (no certificate minted yet), so callers still fall through to
// ensureCert in that case — the List-parity skip in Backend.SignWithFlags is
// what actually prevents a source that can't mint from blocking signing for
// keys owned by other sources.
func (s *vaultCASource) mayOwn(key ssh.PublicKey) bool {
	if keyEqual(key, s.base.PublicKey()) {
		return true
	}
	s.mu.Lock()
	cert := s.cert
	s.mu.Unlock()
	if cert == nil {
		return true
	}
	return keyEqual(key, cert)
}

// renderPrincipals expands each principal template against {vault_username}.
func renderPrincipals(tmpls []string, username string) ([]string, error) {
	out := make([]string, 0, len(tmpls))
	data := map[string]string{"vault_username": username}
	for _, t := range tmpls {
		tt, err := template.New("principal").Parse(t)
		if err != nil {
			return nil, fmt.Errorf("principal %q: %w", t, err)
		}
		var b strings.Builder
		if err := tt.Execute(&b, data); err != nil {
			return nil, fmt.Errorf("principal %q: %w", t, err)
		}
		out = append(out, b.String())
	}
	return out, nil
}

// vaultCertSigner is the production certSigner: it calls the Vault SSH CA's
// sign/<role> endpoint and parses the returned certificate.
type vaultCertSigner struct {
	client *vault.Client
}

func (v vaultCertSigner) SignSSHCert(ctx context.Context, mount, role string, pub ssh.PublicKey, principals []string, ttl time.Duration) (*ssh.Certificate, error) {
	data := map[string]any{
		"public_key": string(ssh.MarshalAuthorizedKey(pub)),
		"cert_type":  "user",
	}
	if len(principals) > 0 {
		data["valid_principals"] = strings.Join(principals, ",")
	}
	if ttl > 0 {
		data["ttl"] = fmt.Sprintf("%ds", int(ttl.Seconds()))
	}
	sec, err := v.client.Raw().Logical().WriteWithContext(ctx, mount+"/sign/"+role, data)
	if err != nil {
		return nil, fmt.Errorf("vault sign %s/sign/%s: %w", mount, role, err)
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("vault sign %s/sign/%s: empty response", mount, role)
	}
	signed, ok := sec.Data["signed_key"].(string)
	if !ok || strings.TrimSpace(signed) == "" {
		return nil, fmt.Errorf("vault sign %s/sign/%s: no signed_key in response", mount, role)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signed))
	if err != nil {
		return nil, fmt.Errorf("parse signed certificate: %w", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("vault returned a key, not a certificate")
	}
	return cert, nil
}
