package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/clientcert"
)

// certVault is a fake Vault that answers token lookup and signs CSRs at
// <mount>/sign/<role> with an in-test CA.
type certVault struct {
	srv    *httptest.Server
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte

	signs atomic.Int32
	// signStatus, when non-zero, makes pki/sign answer that status.
	signStatus atomic.Int32
	// lastPath is the most recent signing path.
	lastPath atomic.Value
}

func newCertVault(t *testing.T) *certVault {
	t.Helper()
	t.Setenv("VAULT_MAX_RETRIES", "0")
	t.Setenv("DOTVAULT_TOKEN", "")

	cv := &certVault{}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cv.caCert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cv.caKey = key
	cv.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "good" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"id": "good", "ttl": 3600, "creation_ttl": 7200,
			"meta": map[string]any{"username": "gary"},
		}})
	})
	mux.HandleFunc("/v1/pki/sign/", func(w http.ResponseWriter, r *http.Request) {
		cv.signs.Add(1)
		cv.lastPath.Store(r.URL.Path)
		if st := int(cv.signStatus.Load()); st != 0 {
			w.WriteHeader(st)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"nope"}})
			return
		}
		var body struct {
			CSR        string `json:"csr"`
			CommonName string `json:"common_name"`
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(body.CSR))
		if block == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(0x2a),
			Subject:      pkix.Name{CommonName: body.CommonName},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(10 * time.Minute),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, cv.caCert, csr.PublicKey, cv.caKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"certificate":   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			"ca_chain":      []string{string(cv.caPEM)},
			"serial_number": "2a",
		}})
	})
	cv.srv = httptest.NewServer(mux)
	t.Cleanup(cv.srv.Close)
	return cv
}

// ephemeralConfig is a Config that signs against cv under a non-cert auth
// method, with an empty token file so only the DOTVAULT_TOKEN a test sets can
// authenticate.
func (cv *certVault) ephemeralConfig(t *testing.T) *Config {
	t.Helper()
	return &Config{
		Vault:     VaultConfig{Address: cv.srv.URL, AuthMethod: "token"},
		TokenFile: filepath.Join(t.TempDir(), ".vault-token"),
		ClientCert: ClientCertConfig{
			Enabled:    true,
			PKIRole:    "client",
			CommonName: "{{.os_user}}",
		},
	}
}

func newClient(t *testing.T, cfg *Config) *Client {
	t.Helper()
	c, err := New(cfg, WithIdentity("gary"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestClientCertificateEphemeral(t *testing.T) {
	cv := newCertVault(t)
	t.Setenv("DOTVAULT_TOKEN", "good")
	c := newClient(t, cv.ephemeralConfig(t))

	cc, err := c.ClientCertificate(context.Background())
	if err != nil {
		t.Fatalf("ClientCertificate: %v", err)
	}
	if got := cv.lastPath.Load(); got != "/v1/pki/sign/client" {
		t.Errorf("sign path = %v, want /v1/pki/sign/client", got)
	}
	if len(cc.CertPEM) == 0 || len(cc.KeyPEM) == 0 {
		t.Fatalf("empty PEM: cert %d key %d bytes", len(cc.CertPEM), len(cc.KeyPEM))
	}
	if !bytes.HasPrefix(cc.CombinedPEM, cc.CertPEM) || !bytes.HasSuffix(cc.CombinedPEM, cc.KeyPEM) {
		t.Error("CombinedPEM is not the certificate followed by the key")
	}
	if !cc.NotAfter.After(time.Now()) {
		t.Errorf("NotAfter %v is not in the future", cc.NotAfter)
	}
	if len(cc.Certificate.Certificate) == 0 || cc.Certificate.PrivateKey == nil {
		t.Error("tls.Certificate is not populated")
	}
	leaf, err := x509.ParseCertificate(cc.Certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "gary" {
		t.Errorf("CN = %q, want gary", leaf.Subject.CommonName)
	}

	// A second call is served from the cache: no new sign.
	if _, err := c.ClientCertificate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := cv.signs.Load(); n != 1 {
		t.Errorf("signs = %d, want 1", n)
	}
}

func TestClientCertificateDefaultCommonNameUsesTokenUsername(t *testing.T) {
	cv := newCertVault(t)
	t.Setenv("DOTVAULT_TOKEN", "good")
	cfg := cv.ephemeralConfig(t)
	cfg.ClientCert.CommonName = "" // New applies {{.token_username}}
	c := newClient(t, cfg)

	cc, err := c.ClientCertificate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(cc.Certificate.Certificate[0])
	if leaf.Subject.CommonName != "gary" {
		t.Errorf("CN = %q, want the token's username gary", leaf.Subject.CommonName)
	}
}

func TestClientCertificateNotConfigured(t *testing.T) {
	cv := newCertVault(t)
	t.Setenv("DOTVAULT_TOKEN", "good")

	t.Run("disabled", func(t *testing.T) {
		cfg := cv.ephemeralConfig(t)
		cfg.ClientCert.Enabled = false
		_, err := newClient(t, cfg).ClientCertificate(context.Background())
		if !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("err = %v, want ErrNotConfigured", err)
		}
	})
	t.Run("no role", func(t *testing.T) {
		cfg := cv.ephemeralConfig(t)
		cfg.ClientCert.PKIRole = ""
		_, err := newClient(t, cfg).ClientCertificate(context.Background())
		if !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("err = %v, want ErrNotConfigured", err)
		}
	})
	t.Run("held with nothing enrolled and no role", func(t *testing.T) {
		cfg := cv.ephemeralConfig(t)
		cfg.Vault.AuthMethod = "mtls"
		cfg.Vault.MTLS.StorageDir = t.TempDir()
		cfg.ClientCert.PKIRole = ""
		_, err := newClient(t, cfg).ClientCertificate(context.Background())
		if !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("err = %v, want ErrNotConfigured", err)
		}
		if !errors.Is(err, auth.ErrNoCertCredential) {
			t.Errorf("err = %v, want the cause kept reachable", err)
		}
	})
	t.Run("TLSConfig reports it eagerly", func(t *testing.T) {
		cfg := cv.ephemeralConfig(t)
		cfg.ClientCert.Enabled = false
		if _, err := newClient(t, cfg).TLSConfig(nil); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("err = %v, want ErrNotConfigured", err)
		}
	})
}

func TestClientCertificateDeniedIs403(t *testing.T) {
	cv := newCertVault(t)
	t.Setenv("DOTVAULT_TOKEN", "good")
	cv.signStatus.Store(http.StatusForbidden)
	_, err := newClient(t, cv.ephemeralConfig(t)).ClientCertificate(context.Background())
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
}

func TestClientCertificateUnreachableIs5xx(t *testing.T) {
	cv := newCertVault(t)
	t.Setenv("DOTVAULT_TOKEN", "good")
	cv.signStatus.Store(http.StatusBadGateway)
	_, err := newClient(t, cv.ephemeralConfig(t)).ClientCertificate(context.Background())
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
}

func TestClientCertificateHeld(t *testing.T) {
	cv := newCertVault(t) // no token anywhere: a held certificate needs none
	dir := t.TempDir()
	writeHeldEnvelope(t, dir, "gary")

	cfg := cv.ephemeralConfig(t)
	cfg.Vault.AuthMethod = "mtls"
	cfg.Vault.MTLS = MTLSConfig{StorageDir: dir}
	cfg.ClientCert.PKIRole = "" // held alone
	c := newClient(t, cfg)

	cc, err := c.ClientCertificate(context.Background())
	if err != nil {
		t.Fatalf("ClientCertificate: %v", err)
	}
	if n := cv.signs.Load(); n != 0 {
		t.Errorf("pki/sign called %d times, want 0 for a held certificate", n)
	}
	leaf, _ := x509.ParseCertificate(cc.Certificate.Certificate[0])
	if leaf.Subject.CommonName != "gary" {
		t.Errorf("CN = %q, want gary", leaf.Subject.CommonName)
	}
	if c.Token() != "" {
		t.Error("a held certificate must not require or acquire a token")
	}
}

func TestClientCertificateHeldForOtherUserIsNotServed(t *testing.T) {
	cv := newCertVault(t)
	dir := t.TempDir()
	writeHeldEnvelope(t, dir, "someone-else")
	cfg := cv.ephemeralConfig(t)
	cfg.Vault.AuthMethod = "mtls"
	cfg.Vault.MTLS = MTLSConfig{StorageDir: dir}
	cfg.ClientCert.PKIRole = ""
	_, err := newClient(t, cfg).ClientCertificate(context.Background())
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestClientCertificateNeverPrompts(t *testing.T) {
	cv := newCertVault(t) // no DOTVAULT_TOKEN, empty token file, no sockets
	_, err := newClient(t, cv.ephemeralConfig(t)).ClientCertificate(context.Background())
	if !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("err = %v, want ErrLoginRequired", err)
	}
	if n := cv.signs.Load(); n != 0 {
		t.Errorf("signed %d times with no token", n)
	}
}

func TestClientCertificateAuthenticatesCachedWhenTokenMissing(t *testing.T) {
	cv := newCertVault(t)
	cfg := cv.ephemeralConfig(t)
	// The token arrives from the token file, so AuthenticateCached finds it.
	if err := os.WriteFile(cfg.TokenFile, []byte("good\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, cfg)
	if _, err := c.ClientCertificate(context.Background()); err != nil {
		t.Fatalf("ClientCertificate: %v", err)
	}
	if c.Token() != "good" {
		t.Errorf("token = %q, want the cached token adopted", c.Token())
	}
}

func TestClientCertificateHeldIsDerivedForHandBuiltConfig(t *testing.T) {
	cfg := &Config{
		Vault:      VaultConfig{Address: "http://127.0.0.1:1", AuthMethod: "mtls"},
		ClientCert: ClientCertConfig{Enabled: true},
	}
	if got := cfg.withDefaults().ClientCert; !got.Held || got.PKIMount != "pki" || got.CommonName != "{{.token_username}}" || got.TTL != 5*time.Minute {
		t.Errorf("defaults = %+v", got)
	}
	cfg.Vault.BorrowOnly = true
	if cfg.withDefaults().ClientCert.Held {
		t.Error("borrow_only must not be held")
	}
}

func TestMapClientCertErr(t *testing.T) {
	ctx := context.Background()
	paced := fmt.Errorf("outer: %w", clientcert.ErrSignPaced)
	got := mapClientCertErr(ctx, paced)
	if !errors.Is(got, clientcert.ErrSignPaced) {
		t.Errorf("ErrSignPaced lost: %v", got)
	}
	for _, c := range []error{ErrDenied, ErrUnreachable, ErrLoginRequired, ErrNotConfigured} {
		if errors.Is(got, c) {
			t.Errorf("pacing must not be categorised as %v", c)
		}
	}
	if got := mapClientCertErr(ctx, clientcert.ErrNoToken); !errors.Is(got, ErrLoginRequired) {
		t.Errorf("ErrNoToken -> %v, want ErrLoginRequired", got)
	}
	if got := mapClientCertErr(ctx, errors.New("clientcert: generate key: boom")); errors.Is(got, ErrUnreachable) {
		t.Errorf("a local failure must not read as unreachable: %v", got)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if got := mapClientCertErr(cctx, context.Canceled); !errors.Is(got, context.Canceled) || errors.Is(got, ErrUnreachable) {
		t.Errorf("cancellation -> %v", got)
	}
}

func TestClientCertificateErrorsCarryNoKeyMaterial(t *testing.T) {
	cv := newCertVault(t)
	t.Setenv("DOTVAULT_TOKEN", "good")
	cv.signStatus.Store(http.StatusForbidden)
	_, err := newClient(t, cv.ephemeralConfig(t)).ClientCertificate(context.Background())
	if err == nil {
		t.Fatal("want error")
	}
	if s := err.Error(); strings.Contains(s, "PRIVATE KEY") || strings.Contains(s, "BEGIN") {
		t.Errorf("error carries PEM: %q", s)
	}
}

func TestTLSConfigPresentsCurrentCert(t *testing.T) {
	cv := newCertVault(t)
	t.Setenv("DOTVAULT_TOKEN", "good")

	pool := x509.NewCertPool()
	pool.AddCert(cv.caCert)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	serverPool := x509.NewCertPool()
	serverPool.AddCert(srv.Certificate())
	base := &tls.Config{RootCAs: serverPool, MinVersion: tls.VersionTLS12}

	c := newClient(t, cv.ephemeralConfig(t))
	cfg, err := c.TLSConfig(base)
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if cfg == base {
		t.Error("TLSConfig must clone base, not mutate it")
	}
	if base.GetClientCertificate != nil {
		t.Error("base was modified")
	}
	if cfg.RootCAs != serverPool || cfg.MinVersion != tls.VersionTLS12 {
		t.Error("base settings were not carried over")
	}

	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	t.Cleanup(hc.CloseIdleConnections)
	resp, err := hc.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "gary" {
		t.Errorf("server saw CN %q, want gary", body)
	}
}

func TestTLSConfigNilBase(t *testing.T) {
	cv := newCertVault(t)
	cfg, err := newClient(t, cv.ephemeralConfig(t)).TLSConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GetClientCertificate == nil {
		t.Fatal("GetClientCertificate not set")
	}
}

func TestTLSConfigHandshakeFailsWhenCertUnavailable(t *testing.T) {
	cv := newCertVault(t) // no token: the handshake cannot get a certificate
	cfg, err := newClient(t, cv.ephemeralConfig(t)).TLSConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{}); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("err = %v, want ErrLoginRequired", err)
	}
}

// writeHeldEnvelope writes a credential.json in auth's on-disk format (schema
// 1, file backend, PKCS#8 handle) holding a fresh self-signed certificate
// issued to identity.
func writeHeldEnvelope(t *testing.T, dir, identity string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	notAfter := notBefore.Add(10 * 24 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x1001),
		Subject:      pkix.Name{CommonName: identity},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{
		"schema":    1,
		"method":    "mtls",
		"backend":   "file",
		"cert_pem":  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"handle":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		"serial":    "ignored",
		"not_after": notAfter,
		"identity":  identity,
		"issued_at": notBefore,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "credential.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
