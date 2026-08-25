package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/securestore"
)

// TestReissueRevokesSupersededCertificate pins the half of rotation that the
// OS-store sweep alone does not cover: removing the superseded leaf from
// CurrentUser\My stops *this host* presenting it, but the certificate stays
// valid at Vault until its own NotAfter. A copy taken before the rotation —
// or a key the OS store never held exclusively — therefore keeps authenticating
// for the rest of the old certificate's life. Revoking by serial closes that
// window at the CA, which is the only place that can close it.
func TestReissueRevokesSupersededCertificate(t *testing.T) {
	ca := newTestCA(t)
	f := &fakeVault{ca: ca}
	srv := newFakeVaultServer(t, f)
	dir := t.TempDir()
	// Expires in 3 days against a 7-day window, so it is due for rotation.
	seedCredentialFile(t, ca, dir, time.Now().Add(3*24*time.Hour))

	m := mtlsManager(t, srv, dir)
	// A distinctive pre-rotation value, so the revoke's token proves which
	// credential made the call rather than merely being non-empty.
	m.VaultClient.SetToken("s.pre-rotation-token")
	if err := m.ReissueIfDue(t.Context()); err != nil {
		t.Fatalf("ReissueIfDue: %v", err)
	}
	if f.signCount != 1 {
		t.Fatalf("expected one re-issue, got signs=%d", f.signCount)
	}
	if len(f.revokedSerials) != 1 {
		t.Fatalf("revoked serials = %v, want exactly the superseded one", f.revokedSerials)
	}
	if f.revokedSerials[0] != "old-serial" {
		t.Errorf("revoked %q, want the superseded certificate's serial %q", f.revokedSerials[0], "old-serial")
	}
	// The revocation must ride the credential that is now current, not the one
	// being retired: by this point certLogin has adopted the replacement's
	// token onto the shared client, and that is the token whose policies an
	// operator grants pki/revoke to.
	if got := f.revokeTokens[0]; got != m.VaultClient.Token() {
		t.Errorf("revoke presented token %q, want the rotated credential's token %q", got, m.VaultClient.Token())
	}
	if f.revokeTokens[0] == "s.pre-rotation-token" {
		t.Error("revoke presented the pre-rotation token")
	}
}

// recordingLifecycle is a CertStorer+CertLifecycle backend over a real file
// store, so Generate/Load work while the store's transactional calls are
// recorded into a shared event log. The genuine OS backend is Windows-only
// CNG; what is asserted here — the order internal/auth drives the flow in — is
// platform-neutral.
type recordingLifecycle struct {
	securestore.Storage
	record func(string)
}

func (r *recordingLifecycle) StoreCert(handle []byte, _ string) ([]byte, error) {
	r.record("store-cert")
	return handle, nil
}

func (r *recordingLifecycle) CommitCert(_, _ []byte) error {
	r.record("commit")
	return nil
}

func (r *recordingLifecycle) RollbackCert(_ []byte) error {
	r.record("rollback")
	return nil
}

// TestReissueRevokesOnlyAfterOSStoreRemoval pins the ordering the OS-native
// backend needs. Revoking first would leave a revoked certificate installed in
// CurrentUser\My for as long as the sweep takes — and permanently if the sweep
// fails — so every browser and client that picked it up would offer a
// certificate the CA now rejects, turning a successful rotation into broken
// mTLS on this host. Removal first means the worst case is a certificate that
// is gone locally but still valid at Vault, which the next attempt can fix.
func TestReissueRevokesOnlyAfterOSStoreRemoval(t *testing.T) {
	ca := newTestCA(t)
	var events []string
	record := func(op string) { events = append(events, op) }

	f := &fakeVault{ca: ca, record: record}
	srv := newFakeVaultServer(t, f)
	dir := t.TempDir()
	seedCredentialFile(t, ca, dir, time.Now().Add(3*24*time.Hour))

	base, err := securestore.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	store := &recordingLifecycle{Storage: base, record: record}

	m := mtlsManager(t, srv, dir)
	m.VaultClient.SetToken("s.operational-token")
	old, err := loadCredential(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.reissue(t.Context(), store, old); err != nil {
		t.Fatalf("reissue: %v", err)
	}

	commit := indexOf(events, "commit")
	revoke := indexOf(events, "revoke")
	if commit < 0 {
		t.Fatalf("the superseded credential was never removed from the store; events=%v", events)
	}
	if revoke < 0 {
		t.Fatalf("the superseded certificate was never revoked; events=%v", events)
	}
	if revoke < commit {
		t.Errorf("revoked before removing from the store; events=%v", events)
	}
	if indexOf(events, "rollback") >= 0 {
		t.Errorf("a successful rotation must not roll back; events=%v", events)
	}
}

func indexOf(events []string, want string) int {
	for i, e := range events {
		if e == want {
			return i
		}
	}
	return -1
}

// TestReissueRevocationFailureIsAdvisory pins that a rotation which cannot
// revoke still succeeds. By the time revocation runs the replacement is
// persisted, operational, and the superseded artefacts are gone; failing the
// rotation there would leave the daemon reporting an error for a credential it
// is already using — and, worse, invite a retry loop that re-issues a
// certificate on every attempt. A deployment whose token policy omits
// pki/revoke keeps working, loudly.
func TestReissueRevocationFailureIsAdvisory(t *testing.T) {
	ca := newTestCA(t)
	f := &fakeVault{ca: ca, failRevoke: true}
	srv := newFakeVaultServer(t, f)
	dir := t.TempDir()
	seedCredentialFile(t, ca, dir, time.Now().Add(3*24*time.Hour))

	m := mtlsManager(t, srv, dir)
	m.VaultClient.SetToken("s.operational-token")
	buf := captureSlog(t)
	if err := m.ReissueIfDue(t.Context()); err != nil {
		t.Fatalf("a failed revocation must not fail the rotation: %v", err)
	}
	cred, err := loadCredential(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Serial != "aa:bb:cc" {
		t.Errorf("credential not rotated; serial=%q", cred.Serial)
	}
	if !strings.Contains(buf.String(), "revoke") {
		t.Errorf("a failed revocation must be logged; log=%q", buf.String())
	}
}

// TestReissueWithoutSupersededSerialSkipsRevocation covers an envelope written
// before serials were recorded (and any credential whose issuer returned none).
// There is nothing to name in a revoke call, so the rotation must simply not
// make one rather than sending an empty serial Vault would reject.
func TestReissueWithoutSupersededSerialSkipsRevocation(t *testing.T) {
	ca := newTestCA(t)
	f := &fakeVault{ca: ca}
	srv := newFakeVaultServer(t, f)
	dir := t.TempDir()
	seedCredentialFile(t, ca, dir, time.Now().Add(3*24*time.Hour))

	cred, err := loadCredential(dir)
	if err != nil {
		t.Fatal(err)
	}
	cred.Serial = ""
	if err := saveCredential(dir, cred); err != nil {
		t.Fatal(err)
	}

	m := mtlsManager(t, srv, dir)
	// A distinctive pre-rotation value, so the revoke's token proves which
	// credential made the call rather than merely being non-empty.
	m.VaultClient.SetToken("s.pre-rotation-token")
	if err := m.ReissueIfDue(t.Context()); err != nil {
		t.Fatalf("ReissueIfDue: %v", err)
	}
	if f.signCount != 1 {
		t.Fatalf("expected one re-issue, got signs=%d", f.signCount)
	}
	if len(f.revokedSerials) != 0 {
		t.Errorf("revoked %v, want no revocation for a credential with no serial", f.revokedSerials)
	}
}

// TestSeedRecordsRevocableSerial pins that the serial an envelope records is
// the one pki/revoke understands. Vault's sign response already returns its
// colon-hex form, but a BYO import used big.Int.String() — a decimal string
// Vault has never heard of — so the first rotation after a BYO seed would send
// a serial that could not match anything and quietly revoke nothing.
func TestSeedRecordsRevocableSerial(t *testing.T) {
	tests := []struct {
		name   string
		serial *big.Int
		want   string
	}{
		{"single byte pads to a pair", big.NewInt(0x0a), "0a"},
		{"multi-byte is colon-separated", big.NewInt(0xaabbcc), "aa:bb:cc"},
		{"leading zero byte is preserved", big.NewInt(0x00ff), "ff"},
		{"zero", big.NewInt(0), "00"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatSerial(tc.serial); got != tc.want {
				t.Errorf("formatSerial(%v) = %q, want %q", tc.serial, got, tc.want)
			}
		})
	}

	t.Run("byo import records colon-hex", func(t *testing.T) {
		ca := newTestCA(t)
		dir := t.TempDir()
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leaf := ca.signLeaf(t, &key.PublicKey, "alice", time.Now().Add(24*time.Hour))
		certPath := writeFile(t, dir, "byo.crt", leaf)
		keyPath := writeFile(t, dir, "byo.key", newPEMKey(t, key))

		m := &Manager{MTLS: &MTLSParams{
			Method: "mtls", KeyType: "ec", StorageDir: dir,
			BYOCert: certPath, BYOKey: keyPath,
		}}
		store, err := securestore.Open("file")
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, _, serial, err := m.importBYO(store)
		if err != nil {
			t.Fatalf("importBYO: %v", err)
		}
		if !strings.Contains(serial, ":") {
			t.Errorf("BYO serial = %q, want Vault's colon-hex form", serial)
		}
		want := formatSerial(mustLeaf(t, leaf).SerialNumber)
		if serial != want {
			t.Errorf("BYO serial = %q, want %q", serial, want)
		}
	})
}

// TestRevokeSupersededCertificateToleratesNoLifecycleBackend covers file and
// tpm, where the handle IS the key material so there is no store to sweep. The
// certificate is just as superseded, so it must still be revoked.
func TestRevokeSupersededCertificateToleratesNoLifecycleBackend(t *testing.T) {
	ca := newTestCA(t)
	f := &fakeVault{ca: ca}
	srv := newFakeVaultServer(t, f)
	dir := t.TempDir()
	seedCredentialFile(t, ca, dir, time.Now().Add(3*24*time.Hour))

	base, err := securestore.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := base.(securestore.CertLifecycle); ok {
		t.Fatal("the file backend must not implement CertLifecycle")
	}

	m := mtlsManager(t, srv, dir)
	m.VaultClient.SetToken("s.operational-token")
	old, err := loadCredential(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.reissue(t.Context(), base, old); err != nil {
		t.Fatalf("reissue: %v", err)
	}
	if len(f.revokedSerials) != 1 || f.revokedSerials[0] != "old-serial" {
		t.Errorf("revoked %v, want [old-serial]", f.revokedSerials)
	}
}

// writeFile drops content into dir at 0600 and returns its path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustLeaf(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	leaf, err := leafCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}
