package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
)

// testCA is a minimal in-test certificate authority that signs CSRs, standing
// in for Vault's PKI engine.
type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pem  string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dotvault-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{key: key, cert: cert, pem: pemCert(der)}
}

// signLeaf signs a client certificate for pub with the given CN and lifetime.
func (ca *testCA) signLeaf(t *testing.T, pub any, cn string, notAfter time.Time) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pemCert(der)
}

func pemCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// fakeVault serves the two endpoints the cert-auth flow touches: PKI sign and
// cert-auth login. loginCount/signCount let tests assert what happened.
type fakeVault struct {
	ca                 *testCA
	loginCount         int
	signCount          int
	leafTTL            time.Duration
	failLogin          bool // when set, /v1/auth/cert/login returns 500
	tokenCreateCount   int
	tokenCreateSawCert bool
	// signTokens records the X-Vault-Token presented on each PKI sign call, so
	// tests can assert which client (and therefore which token) did the signing.
	signTokens []string
}

func (f *fakeVault) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/cert/login", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client certificate", http.StatusBadRequest)
			return
		}
		if f.failLogin {
			http.Error(w, "cert auth rejected", http.StatusInternalServerError)
			return
		}
		f.loginCount++
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "s.operational-token"},
		})
	})
	mux.HandleFunc("/v1/auth/token/create", func(w http.ResponseWriter, r *http.Request) {
		// Record whether the downscope call presented the client certificate.
		// The server requests (not requires) the cert, so a sibling that drops
		// it would arrive here with no peer certificate.
		f.tokenCreateCount++
		f.tokenCreateSawCert = r.TLS != nil && len(r.TLS.PeerCertificates) > 0
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "s.child-token"},
		})
	})
	mux.HandleFunc("/v1/pki/sign/dotvault", func(w http.ResponseWriter, r *http.Request) {
		f.signTokens = append(f.signTokens, r.Header.Get("X-Vault-Token"))
		var body struct {
			CSR        string `json:"csr"`
			CommonName string `json:"common_name"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		block, _ := pem.Decode([]byte(body.CSR))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.signCount++
		ttl := f.leafTTL
		if ttl == 0 {
			ttl = 24 * time.Hour
		}
		leaf := f.ca.signLeaf(&testing.T{}, csr.PublicKey, body.CommonName, time.Now().Add(ttl))
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate":   leaf,
				"ca_chain":      []string{f.ca.pem},
				"serial_number": "aa:bb:cc",
			},
		})
	})
	return mux
}

func newFakeVaultServer(t *testing.T, f *fakeVault) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(f.handler())
	// Request (not require) the client cert: Vault asks for it during the
	// handshake so the cert auth method can match it, but token-authenticated
	// calls like PKI sign present no cert over the same listener.
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func newPEMKey(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func mtlsManager(t *testing.T, srv *httptest.Server, storageDir string) *Manager {
	t.Helper()
	vc, err := vault.NewClient(vault.Config{Address: srv.URL, TLSSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	return &Manager{
		VaultClient:   vc,
		TokenFilePath: filepath.Join(storageDir, "token"),
		AuthMethod:    "mtls",
		Username:      "alice",
		MTLS: &MTLSParams{
			VaultAddress:  srv.URL,
			TLSSkipVerify: true,
			Method:        "mtls",
			CertMount:     "cert",
			CertRole:      "dotvault",
			PKIMount:      "pki",
			PKIRole:       "dotvault",
			KeyType:       "ec",
			CommonName:    "{{.user}}",
			ReissueBefore: 7 * 24 * time.Hour,
			StorageDir:    storageDir,
		},
	}
}

// TestMTLSByoSeedAndLogin exercises the bring-your-own path: import an existing
// cert+key, persist the envelope, and log in against the cert auth method.
func TestMTLSByoSeedAndLogin(t *testing.T) {
	ca := newTestCA(t)
	f := &fakeVault{ca: ca}
	srv := newFakeVaultServer(t, f)
	dir := t.TempDir()

	// Produce a BYO cert+key on disk.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := ca.signLeaf(t, &key.PublicKey, "alice", time.Now().Add(24*time.Hour))
	certPath := filepath.Join(dir, "byo.crt")
	keyPath := filepath.Join(dir, "byo.key")
	os.WriteFile(certPath, []byte(leaf), 0o600)
	os.WriteFile(keyPath, []byte(newPEMKey(t, key)), 0o600)

	m := mtlsManager(t, srv, dir)
	m.MTLS.BYOCert = certPath
	m.MTLS.BYOKey = keyPath

	buf := captureSlog(t)
	if err := m.authenticateMTLS(t.Context()); err != nil {
		t.Fatalf("authenticateMTLS: %v", err)
	}
	if got := m.VaultClient.Token(); got != "s.operational-token" {
		t.Errorf("token = %q, want operational token", got)
	}
	// No policy configured → the operational login warns exactly once.
	if n := strings.Count(buf.String(), "set vault.policies"); n != 1 {
		t.Errorf("transition warning emitted %d times, want exactly 1", n)
	}
	if f.loginCount != 1 {
		t.Errorf("login count = %d, want 1", f.loginCount)
	}
	if f.signCount != 0 {
		t.Errorf("BYO must not call PKI sign; got %d", f.signCount)
	}
	// Envelope persisted.
	cred, err := loadCredential(dir)
	if err != nil || cred == nil {
		t.Fatalf("credential not saved: %v", err)
	}
	if cred.Identity != "alice" || cred.Backend != "file" {
		t.Errorf("unexpected credential: %+v", cred)
	}
}

// writeBYO produces a valid BYO cert+key on disk and returns their paths.
func writeBYO(t *testing.T, ca *testCA, dir string) (certPath, keyPath string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := ca.signLeaf(t, &key.PublicKey, "alice", time.Now().Add(24*time.Hour))
	certPath = filepath.Join(dir, "byo.crt")
	keyPath = filepath.Join(dir, "byo.key")
	os.WriteFile(certPath, []byte(leaf), 0o600)
	os.WriteFile(keyPath, []byte(newPEMKey(t, key)), 0o600)
	return certPath, keyPath
}

// TestMTLSSeedLoginFailureDoesNotClobberEnvelope pins the P1 fix: the new
// credential must not become authoritative until the replacement cert login
// succeeds. Before the fix, saveCredential overwrote credential.json before the
// login was known to work, so a failed login left the on-disk envelope pointing
// at a credential the store had just rolled back — stranding the next restart or
// unattended recovery. Reload credential.json on the failure path and assert it
// still reflects the previous state.
func TestMTLSSeedLoginFailureDoesNotClobberEnvelope(t *testing.T) {
	ca := newTestCA(t)

	t.Run("first enrolment leaves no envelope", func(t *testing.T) {
		f := &fakeVault{ca: ca, failLogin: true}
		srv := newFakeVaultServer(t, f)
		dir := t.TempDir()
		certPath, keyPath := writeBYO(t, ca, dir)

		m := mtlsManager(t, srv, dir)
		m.MTLS.BYOCert = certPath
		m.MTLS.BYOKey = keyPath

		if err := m.authenticateMTLS(t.Context()); err == nil {
			t.Fatal("expected authenticateMTLS to fail when the cert login is rejected")
		}
		// No prior credential existed, so a failed login must not write one.
		if _, err := os.Stat(filepath.Join(dir, "credential.json")); !os.IsNotExist(err) {
			cred, _ := loadCredential(dir)
			t.Fatalf("credential.json must not exist after a failed first enrolment; got %+v (stat err %v)", cred, err)
		}
	})

	t.Run("re-seed keeps the previous envelope", func(t *testing.T) {
		f := &fakeVault{ca: ca, failLogin: true}
		srv := newFakeVaultServer(t, f)
		dir := t.TempDir()
		// An expired credential is present: startup reuse fails (expiry check,
		// no login attempt), so the flow falls through to a BYO re-seed whose
		// cert login then fails.
		seedCredentialFile(t, ca, dir, time.Now().Add(-time.Hour))
		certPath, keyPath := writeBYO(t, ca, dir)

		m := mtlsManager(t, srv, dir)
		m.MTLS.BYOCert = certPath
		m.MTLS.BYOKey = keyPath

		if err := m.authenticateMTLS(t.Context()); err == nil {
			t.Fatal("expected authenticateMTLS to fail when the re-seed cert login is rejected")
		}
		// The envelope must still be the previous one, not the abandoned BYO
		// re-seed. seedCredentialFile stamps serial "old-serial".
		cred, err := loadCredential(dir)
		if err != nil || cred == nil {
			t.Fatalf("previous credential must survive a failed re-seed: %v", err)
		}
		if cred.Serial != "old-serial" {
			t.Errorf("envelope serial = %q, want the preserved old-serial (a failed re-seed must not clobber it)", cred.Serial)
		}
	})
}

// TestCertLoginFromStore_EmptyStorageDirIgnoresCwd pins that an empty
// StorageDir is treated as "no credential" and never probes a cwd-relative
// "credential.json". The client facade yields an empty StorageDir on a
// home-less host (defaultMTLSStorageDir → ""); without the guard, loadCredential
// would read whatever ./credential.json sits in the working directory and
// authenticate as it — the same cwd-relative hazard DefaultTokenFile avoids.
// Chdir into a temp dir holding a valid envelope and assert the login is
// refused, not performed.
func TestCertLoginFromStore_EmptyStorageDirIgnoresCwd(t *testing.T) {
	ca := newTestCA(t)
	f := &fakeVault{ca: ca}
	srv := newFakeVaultServer(t, f)
	dir := t.TempDir()
	seedCredentialFile(t, ca, dir, time.Now().Add(60*24*time.Hour)) // writes dir/credential.json
	t.Chdir(dir)                                                    // so "" would resolve to ./credential.json

	m := mtlsManager(t, srv, dir)
	m.MTLS.StorageDir = "" // the home-less-host case

	err := m.CertLoginFromStore(t.Context())
	if !errors.Is(err, ErrNoCertCredential) {
		t.Fatalf("err = %v, want ErrNoCertCredential (an empty StorageDir must not probe cwd)", err)
	}
	if f.loginCount != 0 {
		t.Errorf("login attempted %d times; an empty StorageDir must not read ./credential.json and log in", f.loginCount)
	}
}

// TestMTLSDownscopePresentsClientCert covers the cert-auth downscope path: when
// vault.policies is set, the auth/token/create call that mints the downscoped
// child must present the client certificate (some Vault listeners require a
// client cert on every request). It also confirms the downscoped child token is
// the one adopted onto the shared client.
func TestMTLSDownscopePresentsClientCert(t *testing.T) {
	ca := newTestCA(t)
	f := &fakeVault{ca: ca}
	srv := newFakeVaultServer(t, f)
	dir := t.TempDir()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := ca.signLeaf(t, &key.PublicKey, "alice", time.Now().Add(24*time.Hour))
	certPath := filepath.Join(dir, "byo.crt")
	keyPath := filepath.Join(dir, "byo.key")
	os.WriteFile(certPath, []byte(leaf), 0o600)
	os.WriteFile(keyPath, []byte(newPEMKey(t, key)), 0o600)

	m := mtlsManager(t, srv, dir)
	m.MTLS.BYOCert = certPath
	m.MTLS.BYOKey = keyPath
	m.Policy = PolicyConstraint{Policies: []string{"dotvault"}}

	buf := captureSlog(t)
	if err := m.authenticateMTLS(t.Context()); err != nil {
		t.Fatalf("authenticateMTLS: %v", err)
	}
	// Policy configured → no transition warning.
	if strings.Contains(buf.String(), "set vault.policies") {
		t.Errorf("transition warning must not fire when policies are set: %q", buf.String())
	}
	if f.tokenCreateCount != 1 {
		t.Fatalf("auth/token/create called %d times, want 1 (downscope must run)", f.tokenCreateCount)
	}
	if !f.tokenCreateSawCert {
		t.Error("downscope auth/token/create did not present the client certificate")
	}
	if got := m.VaultClient.Token(); got != "s.child-token" {
		t.Errorf("token = %q, want the downscoped child token", got)
	}
}

// TestMTLSReuseExisting confirms a valid stored credential logs in without
// re-seeding, and that a credential inside the re-issue window is rotated via
// PKI sign.
func TestMTLSReuseAndReissue(t *testing.T) {
	ca := newTestCA(t)

	t.Run("reuse in-window cert without re-issue", func(t *testing.T) {
		f := &fakeVault{ca: ca}
		srv := newFakeVaultServer(t, f)
		dir := t.TempDir()
		seedCredentialFile(t, ca, dir, time.Now().Add(60*24*time.Hour)) // far from expiry

		m := mtlsManager(t, srv, dir)
		if err := m.authenticateMTLS(t.Context()); err != nil {
			t.Fatalf("authenticateMTLS: %v", err)
		}
		if f.loginCount != 1 {
			t.Errorf("login count = %d, want 1", f.loginCount)
		}
		if f.signCount != 0 {
			t.Errorf("a healthy cert must not be re-issued; signs=%d", f.signCount)
		}
	})

	t.Run("rotate cert inside re-issue window", func(t *testing.T) {
		f := &fakeVault{ca: ca}
		srv := newFakeVaultServer(t, f)
		dir := t.TempDir()
		// Expires in 3 days; reissue window is 7 days, so it must rotate.
		seedCredentialFile(t, ca, dir, time.Now().Add(3*24*time.Hour))

		m := mtlsManager(t, srv, dir)
		if err := m.authenticateMTLS(t.Context()); err != nil {
			t.Fatalf("authenticateMTLS: %v", err)
		}
		if f.signCount != 1 {
			t.Errorf("expected one re-issue, got signs=%d", f.signCount)
		}
		// The rotated credential carries the freshly-signed cert: the fake
		// stamps serial "aa:bb:cc", replacing the seeded "old-serial".
		cred, _ := loadCredential(dir)
		if cred.Serial != "aa:bb:cc" {
			t.Errorf("credential not rotated; serial=%q", cred.Serial)
		}
	})
}

// TestReissueIfDue covers the periodic check the daemon runs: a healthy cert is
// left alone, a cert inside the window is rotated using the operational token.
func TestReissueIfDue(t *testing.T) {
	ca := newTestCA(t)

	t.Run("not due is a no-op", func(t *testing.T) {
		f := &fakeVault{ca: ca}
		srv := newFakeVaultServer(t, f)
		dir := t.TempDir()
		seedCredentialFile(t, ca, dir, time.Now().Add(60*24*time.Hour))

		m := mtlsManager(t, srv, dir)
		if err := m.ReissueIfDue(t.Context()); err != nil {
			t.Fatalf("ReissueIfDue: %v", err)
		}
		if f.signCount != 0 || f.loginCount != 0 {
			t.Errorf("healthy cert should not rotate: signs=%d logins=%d", f.signCount, f.loginCount)
		}
	})

	t.Run("due rotates", func(t *testing.T) {
		f := &fakeVault{ca: ca}
		srv := newFakeVaultServer(t, f)
		dir := t.TempDir()
		seedCredentialFile(t, ca, dir, time.Now().Add(3*24*time.Hour))

		m := mtlsManager(t, srv, dir)
		m.VaultClient.SetToken("s.operational-token") // as if already authenticated
		if err := m.ReissueIfDue(t.Context()); err != nil {
			t.Fatalf("ReissueIfDue: %v", err)
		}
		if f.signCount != 1 {
			t.Errorf("expected one re-issue, got signs=%d", f.signCount)
		}
		cred, _ := loadCredential(dir)
		if cred.Serial != "aa:bb:cc" {
			t.Errorf("credential not rotated; serial=%q", cred.Serial)
		}
	})

	t.Run("non-cert method is a no-op", func(t *testing.T) {
		m := &Manager{AuthMethod: "oidc"}
		if err := m.ReissueIfDue(t.Context()); err != nil {
			t.Errorf("non-cert method should be a no-op: %v", err)
		}
	})
}

// seedCredentialFile writes a file-backend credential envelope (key + CA-signed
// cert) into dir, as if a previous run had seeded it.
func seedCredentialFile(t *testing.T, ca *testCA, dir string, notAfter time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := ca.signLeaf(t, &key.PublicKey, "alice", notAfter)
	cred := &sealedCredential{
		Method:   "mtls",
		Backend:  "file",
		CertPEM:  leaf,
		Handle:   []byte(newPEMKey(t, key)),
		Serial:   "old-serial",
		NotAfter: notAfter,
		Identity: "alice",
		IssuedAt: time.Now(),
	}
	if err := saveCredential(dir, cred); err != nil {
		t.Fatal(err)
	}
}
