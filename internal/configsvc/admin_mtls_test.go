package configsvc

import (
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
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/configsvc/groups"
	"github.com/goodtune/dotvault/internal/configsvc/store"
)

// testCA is a throwaway issuing CA standing in for the dedicated Vault PKI
// intermediate.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// issueClient mints a client certificate with the given CN, mirroring what
// a Vault PKI role with client_flag=true would produce.
func (ca *testCA) issueClient(t *testing.T, cn string, ekus []x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(30 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  ekus,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newMTLSServer stands up the admin handler behind a RequireAndVerifyClientCert
// listener trusting only ca, with a registered "ci" service account.
func newMTLSServer(t *testing.T, ca *testCA) (store.Store, *httptest.Server) {
	t.Helper()
	st := newTestStore(t)
	if err := st.PutServiceAccount(context.Background(), &store.ServiceAccount{Name: "ci"}); err != nil {
		t.Fatal(err)
	}

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := MTLSServerConfig(AdminMTLSConfig{Listen: "x", CACert: caPath, CertFile: "x", KeyFile: "x"})
	if err != nil {
		t.Fatalf("MTLSServerConfig: %v", err)
	}

	svc := NewServer(st, groups.NewStatic(st))
	svc.EnableAdmin(AdminConfig{Group: adminGroup, SessionTTL: time.Hour}, nil)
	ts := httptest.NewUnstartedServer(svc.Handler())
	ts.TLS = tlsCfg
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return st, ts
}

// clientWith returns ts's TLS-trusting client with the given client cert
// attached (or none).
func clientWith(ts *httptest.Server, cert *tls.Certificate) *http.Client {
	client := ts.Client()
	tr := client.Transport.(*http.Transport).Clone()
	if cert != nil {
		tr.TLSClientConfig.Certificates = []tls.Certificate{*cert}
	}
	client.Transport = tr
	return client
}

func TestMTLSServiceAccountAuth(t *testing.T) {
	ca := newTestCA(t, "dotvault-config svc CA")
	st, ts := newMTLSServer(t, ca)

	cert := ca.issueClient(t, "ci", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	client := clientWith(ts, &cert)

	resp, err := client.Get(ts.URL + "/v1/admin/whoami")
	if err != nil {
		t.Fatalf("whoami over mTLS: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("whoami = %d, want 200", resp.StatusCode)
	}
	var identity Identity
	json.NewDecoder(resp.Body).Decode(&identity)
	if identity.Name != "ci" || identity.Kind != identityKindServiceAccount {
		t.Fatalf("identity = %+v", identity)
	}

	// Certificate-authenticated mutations need no CSRF token (no ambient
	// browser credential to forge) — the exact path a Terraform provider
	// uses.
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/v1/admin/layers/global",
		strings.NewReader("sync:\n  interval: 9m\n"))
	put, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	put.Body.Close()
	if put.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT over mTLS = %d, want 204", put.StatusCode)
	}
	if _, ok, _ := st.GetLayer(context.Background(), "global"); !ok {
		t.Fatal("layer not written")
	}
}

func TestMTLSRejectsUnregisteredAndDisabledAccounts(t *testing.T) {
	ca := newTestCA(t, "svc CA")
	st, ts := newMTLSServer(t, ca)

	// A valid certificate whose CN is not a registered account: the chain
	// verifies, the binding fails.
	stranger := ca.issueClient(t, "stranger", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	resp, err := clientWith(ts, &stranger).Get(ts.URL + "/v1/admin/whoami")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unregistered CN = %d, want 403", resp.StatusCode)
	}

	// Disabling the account revokes access while the certificate is still
	// valid — the immediate-revocation property.
	if err := st.PutServiceAccount(context.Background(), &store.ServiceAccount{Name: "ci", Disabled: true}); err != nil {
		t.Fatal(err)
	}
	cert := ca.issueClient(t, "ci", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	resp, err = clientWith(ts, &cert).Get(ts.URL + "/v1/admin/whoami")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("disabled account = %d, want 403", resp.StatusCode)
	}
}

func TestMTLSRejectsAtHandshake(t *testing.T) {
	ca := newTestCA(t, "svc CA")
	_, ts := newMTLSServer(t, ca)

	// No client certificate at all.
	if _, err := clientWith(ts, nil).Get(ts.URL + "/v1/admin/whoami"); err == nil {
		t.Fatal("request without client certificate succeeded, want handshake failure")
	}

	// A certificate from a different CA — even with the right CN.
	other := newTestCA(t, "imposter CA")
	cert := other.issueClient(t, "ci", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if _, err := clientWith(ts, &cert).Get(ts.URL + "/v1/admin/whoami"); err == nil {
		t.Fatal("certificate from untrusted CA succeeded, want handshake failure")
	}

	// A certificate without the clientAuth EKU — Go's verifier enforces
	// extended key usage during the handshake.
	server := ca.issueClient(t, "ci", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if _, err := clientWith(ts, &server).Get(ts.URL + "/v1/admin/whoami"); err == nil {
		t.Fatal("certificate without clientAuth EKU succeeded, want handshake failure")
	}
}

// brokenSAStore fails service-account lookups, simulating a storage outage
// during certificate authentication.
type brokenSAStore struct {
	store.Store
}

func (brokenSAStore) GetServiceAccount(context.Context, string) (*store.ServiceAccount, bool, error) {
	return nil, false, errors.New("backend down")
}

func TestMTLSStoreOutageIs503NotForbidden(t *testing.T) {
	ca := newTestCA(t, "svc CA")
	st := newTestStore(t)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := MTLSServerConfig(AdminMTLSConfig{CACert: caPath})
	if err != nil {
		t.Fatal(err)
	}
	svc := NewServer(brokenSAStore{st}, groups.NewStatic(st))
	svc.EnableAdmin(AdminConfig{Group: adminGroup, SessionTTL: time.Hour}, nil)
	ts := httptest.NewUnstartedServer(svc.Handler())
	ts.TLS = tlsCfg
	ts.StartTLS()
	t.Cleanup(ts.Close)

	cert := ca.issueClient(t, "ci", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	resp, err := clientWith(ts, &cert).Get(ts.URL + "/v1/admin/whoami")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// A storage outage must not read as "credential revoked" to an
	// automation client — 503, never 403.
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("whoami during store outage = %d, want 503", resp.StatusCode)
	}
}

func TestMTLSServerConfigErrors(t *testing.T) {
	if _, err := MTLSServerConfig(AdminMTLSConfig{CACert: "/nonexistent.pem"}); err == nil {
		t.Fatal("missing CA file accepted")
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	os.WriteFile(empty, []byte("not a cert"), 0o600)
	if _, err := MTLSServerConfig(AdminMTLSConfig{CACert: empty}); err == nil {
		t.Fatal("CA file without certificates accepted")
	}
}
