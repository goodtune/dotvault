package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/goodtune/dotvault/internal/securestore"
	"github.com/goodtune/dotvault/internal/tmpl"
	"github.com/goodtune/dotvault/internal/vault"
)

// MTLSParams carries everything the cert-auth flow needs. It is populated by
// the daemon (cmd/dotvault) from the validated vault.mtls config and attached
// to a Manager whose AuthMethod is "mtls" or "mtls+tpm".
type MTLSParams struct {
	// Connectivity for building a cert-presenting login client.
	VaultAddress  string
	CACert        string
	TLSSkipVerify bool

	Method          string // "mtls" | "mtls+tpm"
	BootstrapMethod string
	BootstrapMount  string
	CertMount       string
	CertRole        string
	PKIMount        string
	PKIRole         string
	KeyType         string
	CommonName      string // template over {{.user}}
	TTL             string
	ReissueBefore   time.Duration
	SealToPCRs      bool
	StorageDir      string
	BYOCert         string
	BYOKey          string
}

// authenticateMTLS runs the certificate-auth flow: reuse an in-window
// credential where possible, otherwise seed one (BYO or LDAP/OIDC bootstrap →
// PKI), then log in against Vault's cert auth method and adopt the operational
// token onto the Manager's client.
func (m *Manager) authenticateMTLS(ctx context.Context) error {
	p := m.MTLS
	if p == nil {
		return fmt.Errorf("auth method %q selected but vault.mtls is not configured", m.AuthMethod)
	}

	store, err := securestore.Open(securestore.ModeForMethod(p.Method))
	if err != nil {
		if p.Method == "mtls+tpm" {
			return fmt.Errorf("mtls+tpm requested but no hardware backend is available on this host (%w); re-run with auth_method: mtls to store the key on disk, or provision a TPM", err)
		}
		return fmt.Errorf("open secure store: %w", err)
	}
	defer store.Close()

	// 1. Try an existing credential.
	cred, err := loadCredential(p.StorageDir)
	if err != nil {
		slog.Warn("existing mtls credential unusable, will re-seed", "error", err)
		cred = nil
	}
	if cred != nil {
		if reused, err := m.tryExistingCredential(ctx, store, cred); err != nil {
			slog.Warn("existing mtls credential failed, re-seeding", "error", err)
		} else if reused {
			return nil
		}
	}

	// 2. Seed a fresh credential (BYO or bootstrap), then cert-login.
	newCred, signer, err := m.seedCredential(ctx, store)
	if err != nil {
		return err
	}
	if err := saveCredential(p.StorageDir, newCred); err != nil {
		return fmt.Errorf("persist mtls credential: %w", err)
	}
	return m.certLogin(ctx, newCred, signer)
}

// tryExistingCredential loads the stored signer, optionally rotates a cert
// inside the re-issue window, and logs in. Returns (true, nil) when the
// Manager's client now holds an operational token.
func (m *Manager) tryExistingCredential(ctx context.Context, store securestore.Storage, cred *sealedCredential) (bool, error) {
	if cred.Identity != "" && m.Username != "" && cred.Identity != m.Username {
		return false, fmt.Errorf("credential belongs to %q, not the current user %q", cred.Identity, m.Username)
	}
	if !cred.NotAfter.IsZero() && time.Now().After(cred.NotAfter) {
		return false, fmt.Errorf("certificate expired at %s", cred.NotAfter.Format(time.RFC3339))
	}
	signer, err := store.Load(cred.Handle)
	if err != nil {
		return false, fmt.Errorf("load key from secure store: %w", err)
	}
	if err := m.certLogin(ctx, cred, signer); err != nil {
		return false, err
	}

	// Proactively rotate if we are inside the re-issue window. A failure here
	// is non-fatal: we already hold an operational token on the valid cert.
	if m.MTLS.ReissueBefore > 0 && !cred.NotAfter.IsZero() &&
		time.Now().After(cred.NotAfter.Add(-m.MTLS.ReissueBefore)) {
		if err := m.reissue(ctx, store, cred); err != nil {
			slog.Warn("certificate re-issuance failed; continuing on the current certificate",
				"not_after", cred.NotAfter.Format(time.RFC3339), "error", err)
		}
	}
	return true, nil
}

// ReissueIfDue rotates the certificate when it is inside the re-issue window,
// using the current operational Vault token (no human). It is a no-op for
// non-cert methods, when no credential exists, or when the cert is not yet due
// for rotation. The daemon calls this periodically so a long-running process
// whose token keeps renewing still rotates its certificate before expiry —
// without this, a warm daemon never re-enters the cert flow and the cert could
// expire unrotated. Safe to call repeatedly: after one successful rotation the
// fresh NotAfter moves out of the window and subsequent calls return nil.
func (m *Manager) ReissueIfDue(ctx context.Context) error {
	if m.MTLS == nil || (m.AuthMethod != "mtls" && m.AuthMethod != "mtls+tpm") || m.MTLS.ReissueBefore <= 0 {
		return nil
	}
	cred, err := loadCredential(m.MTLS.StorageDir)
	if err != nil || cred == nil {
		return err
	}
	if cred.NotAfter.IsZero() || time.Now().Before(cred.NotAfter.Add(-m.MTLS.ReissueBefore)) {
		return nil // not due
	}
	store, err := securestore.Open(securestore.ModeForMethod(m.MTLS.Method))
	if err != nil {
		return fmt.Errorf("open secure store: %w", err)
	}
	defer store.Close()
	return m.reissue(ctx, store, cred)
}

// reissue mints a fresh certificate using the current (still-valid) Vault
// token, writes a new envelope, and adopts the new operational token.
func (m *Manager) reissue(ctx context.Context, store securestore.Storage, old *sealedCredential) error {
	slog.Info("rotating mtls certificate before expiry", "not_after", old.NotAfter.Format(time.RFC3339))
	cn, err := m.renderCommonName()
	if err != nil {
		return err
	}
	signer, handle, err := store.Generate(securestore.KeyType(m.MTLS.KeyType), m.MTLS.SealToPCRs)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	issued, err := m.signOrIssue(ctx, m.VaultClient, signer, cn)
	if err != nil {
		return err
	}
	newCred, err := m.buildCredential(store, issued, handle)
	if err != nil {
		return err
	}
	if err := saveCredential(m.MTLS.StorageDir, newCred); err != nil {
		return fmt.Errorf("persist rotated credential: %w", err)
	}
	return m.certLogin(ctx, newCred, signer)
}

// seedCredential produces a fresh credential via BYO or LDAP/OIDC bootstrap.
func (m *Manager) seedCredential(ctx context.Context, store securestore.Storage) (*sealedCredential, crypto.Signer, error) {
	p := m.MTLS
	cn, err := m.renderCommonName()
	if err != nil {
		return nil, nil, err
	}

	// BYO: import an existing cert+key, skipping bootstrap.
	if p.BYOCert != "" {
		signer, handle, certPEM, notAfter, serial, err := m.importBYO(store)
		if err != nil {
			return nil, nil, err
		}
		cred := &sealedCredential{
			Method:   p.Method,
			Backend:  store.Capabilities().Name,
			CertPEM:  certPEM,
			Handle:   handle,
			Serial:   serial,
			NotAfter: notAfter,
			Identity: m.Username,
			IssuedAt: time.Now(),
		}
		return cred, signer, nil
	}

	// Bootstrap: human login → PKI sign/issue.
	slog.Info("no usable mtls certificate; bootstrapping via human login", "method", p.BootstrapMethod)
	bootClient, err := m.runBootstrap(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("bootstrap login: %w", err)
	}
	signer, handle, err := store.Generate(securestore.KeyType(p.KeyType), p.SealToPCRs)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	// PKI sign runs on the bootstrap client, not m.VaultClient: the broad,
	// PKI-capable bootstrap token must never be installed on the shared client
	// (which the web server exposes via /api/v1/token before the final cert
	// login). Only certLogin adopts the final, downscoped cert-auth token.
	issued, err := m.signOrIssue(ctx, bootClient, signer, cn)
	if err != nil {
		return nil, nil, err
	}
	cred, err := m.buildCredential(store, issued, handle)
	if err != nil {
		return nil, nil, err
	}
	return cred, signer, nil
}

// runBootstrap runs the configured human-credential method to obtain a
// short-lived token authorised for PKI issuance, returning the isolated client
// that holds it. The bootstrap login runs on a *sibling* of m.VaultClient
// (same connection, separate token), never on m.VaultClient itself: the broad,
// PKI-capable bootstrap token must not be installed on the shared client, which
// the web server starts before auth and exposes via /api/v1/token — otherwise
// that broad token would be retrievable during bootstrap and would linger if a
// later step (PKI sign, cert login, downscope) failed. The caller uses the
// returned client for PKI signing; only certLogin adopts the final, downscoped
// cert-auth token onto m.VaultClient.
//
// The bootstrap Manager carries no TokenFilePath, so the broad token is never
// written to the on-disk cache either (WriteTokenFile treats "" as a no-op).
func (m *Manager) runBootstrap(ctx context.Context) (*vault.Client, error) {
	bootClient, err := m.VaultClient.NewSibling("")
	if err != nil {
		return nil, fmt.Errorf("build bootstrap client: %w", err)
	}
	boot := &Manager{
		VaultClient: bootClient,
		AuthMethod:  m.MTLS.BootstrapMethod,
		AuthMount:   m.MTLS.BootstrapMount,
		AuthRole:    m.AuthRole,
		Username:    m.Username,
	}
	if err := boot.Login(ctx); err != nil {
		return nil, err
	}
	return bootClient, nil
}

// signOrIssue mints a certificate for the signer's public key. It prefers the
// PKI sign endpoint (the private key never leaves the host); if the role
// forbids signing it can be retried via issue, but issue would discard our
// hardware key, so it is only attempted when no PKI role offers sign — left as
// the sign path for v1.
func (m *Manager) signOrIssue(ctx context.Context, vc *vault.Client, signer crypto.Signer, commonName string) (*vault.IssuedCert, error) {
	csrPEM, err := buildCSR(signer, commonName)
	if err != nil {
		return nil, err
	}
	issued, err := vc.SignCSR(ctx, m.MTLS.PKIMount, m.MTLS.PKIRole, csrPEM, commonName, m.MTLS.TTL)
	if err != nil {
		return nil, fmt.Errorf("PKI sign: %w", err)
	}
	return issued, nil
}

// buildCredential assembles an envelope from a freshly signed certificate.
func (m *Manager) buildCredential(store securestore.Storage, issued *vault.IssuedCert, handle []byte) (*sealedCredential, error) {
	leaf, err := leafCert(issued.CertPEM)
	if err != nil {
		return nil, err
	}
	return &sealedCredential{
		Method:   m.MTLS.Method,
		Backend:  store.Capabilities().Name,
		CertPEM:  issued.CertPEM,
		Handle:   handle,
		Serial:   issued.Serial,
		NotAfter: leaf.NotAfter,
		Identity: m.Username,
		IssuedAt: time.Now(),
	}, nil
}

// importBYO loads, validates, and seals a bring-your-own certificate and key.
func (m *Manager) importBYO(store securestore.Storage) (crypto.Signer, []byte, string, time.Time, string, error) {
	certPEM, err := os.ReadFile(m.MTLS.BYOCert)
	if err != nil {
		return nil, nil, "", time.Time{}, "", fmt.Errorf("read byo cert: %w", err)
	}
	keyPEM, err := os.ReadFile(m.MTLS.BYOKey)
	if err != nil {
		return nil, nil, "", time.Time{}, "", fmt.Errorf("read byo key: %w", err)
	}
	leaf, err := leafCert(string(certPEM))
	if err != nil {
		return nil, nil, "", time.Time{}, "", err
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, nil, "", time.Time{}, "", fmt.Errorf("byo certificate is not currently valid (%s – %s)",
			leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, nil, "", time.Time{}, "", fmt.Errorf("parse byo key: %w", err)
	}
	signer, handle, err := store.Import(key, m.MTLS.SealToPCRs)
	if err != nil {
		return nil, nil, "", time.Time{}, "", fmt.Errorf("import byo key into secure store: %w", err)
	}
	serial := ""
	if leaf.SerialNumber != nil {
		serial = leaf.SerialNumber.String()
	}
	return signer, handle, string(certPEM), leaf.NotAfter, serial, nil
}

// certLogin assembles a tls.Certificate from the stored cert and signer, dials
// Vault's cert auth method on a dedicated cert-presenting client, and adopts
// the operational token onto the Manager's main client and token file.
func (m *Manager) certLogin(ctx context.Context, cred *sealedCredential, signer crypto.Signer) error {
	tlsCert, err := buildTLSCertificate(cred.CertPEM, signer)
	if err != nil {
		return err
	}
	certClient, err := vault.NewClient(vault.Config{
		Address:       m.MTLS.VaultAddress,
		CACert:        m.MTLS.CACert,
		TLSSkipVerify: m.MTLS.TLSSkipVerify,
		ClientCert:    &tlsCert,
	})
	if err != nil {
		return fmt.Errorf("build cert-auth client: %w", err)
	}
	if err := certClient.LoginCert(ctx, m.MTLS.CertMount, m.MTLS.CertRole); err != nil {
		return err
	}
	// Downscope through certClient (which presents the client certificate), not
	// m.VaultClient: on a Vault listener that requires a client cert on every
	// request, the auth/token/create call must present it too. certClient's
	// sibling inherits the cert via NewSibling. m.VaultClient adopts only the
	// resulting downscoped token.
	token, err := Downscope(ctx, certClient, certClient.Token(), m.Policy)
	if err != nil {
		return err
	}
	m.VaultClient.SetToken(token)
	if err := WriteTokenFile(m.TokenFilePath, token, SealTokenAtRest(m.AuthMethod)); err != nil {
		slog.Warn("failed to write token file", "error", err)
	}
	slog.Info("mtls authentication successful", "method", m.MTLS.Method, "serial", cred.Serial,
		"not_after", cred.NotAfter.Format(time.RFC3339))
	return nil
}

func (m *Manager) renderCommonName() (string, error) {
	cn := m.MTLS.CommonName
	if cn == "" {
		return m.Username, nil
	}
	rendered, err := tmpl.Render("mtls-common-name", cn, map[string]any{"user": m.Username})
	if err != nil {
		return "", fmt.Errorf("render common_name template: %w", err)
	}
	return rendered, nil
}

// buildCSR creates a PEM-encoded CSR over the given signer.
func buildCSR(signer crypto.Signer, commonName string) (string, error) {
	tmplCSR := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmplCSR, signer)
	if err != nil {
		return "", fmt.Errorf("create CSR: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// buildTLSCertificate assembles a tls.Certificate from a PEM chain and a
// crypto.Signer (which may be hardware-backed).
func buildTLSCertificate(certPEM string, signer crypto.Signer) (tls.Certificate, error) {
	var der [][]byte
	rest := []byte(certPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			der = append(der, block.Bytes)
		}
	}
	if len(der) == 0 {
		return tls.Certificate{}, fmt.Errorf("no CERTIFICATE block in credential")
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse leaf certificate: %w", err)
	}
	return tls.Certificate{Certificate: der, PrivateKey: signer, Leaf: leaf}, nil
}

// leafCert parses the first CERTIFICATE block from a PEM chain.
func leafCert(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE block in PEM input")
	}
	return x509.ParseCertificate(block.Bytes)
}

// parsePrivateKey decodes a PEM private key in PKCS#8, EC, or PKCS#1 form.
func parsePrivateKey(keyPEM []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in key")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unsupported private key format")
}
