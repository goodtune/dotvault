package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/securestore"
	"github.com/goodtune/dotvault/internal/vault"
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
	wantSerial := seedCredentialFile(t, ca, dir, time.Now().Add(3*24*time.Hour))

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
	if f.revokedSerials[0] != wantSerial {
		t.Errorf("revoked %q, want the superseded certificate's serial %q", f.revokedSerials[0], wantSerial)
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

// failingLifecycle is a CertStorer+CertLifecycle backend whose sweep fails —
// the OS backend unable to delete the superseded CNG container or its
// CurrentUser\My leaf.
type failingLifecycle struct {
	securestore.Storage
	record func(string)
}

func (f *failingLifecycle) StoreCert(handle []byte, _ string) ([]byte, error) { return handle, nil }

func (f *failingLifecycle) CommitCert(_, _ []byte) error {
	f.record("commit-failed")
	return errors.New("delete key container: access denied")
}

func (f *failingLifecycle) RollbackCert(_ []byte) error { return nil }

// TestReissueDoesNotRevokeWhenTheStoreSweepFails is the other half of the
// ordering rule, and the half ordering alone does not buy.
//
// Running the sweep first only helps if its outcome is consulted. The sweep's
// errors are advisory — a stale artefact must not fail a live rotation — so
// revoking regardless would produce exactly the state the ordering exists to
// prevent, and produce it permanently: a certificate revoked at the CA while
// still sitting in CurrentUser\My, which browsers go on offering until an
// operator removes it by hand. Leaving it unrevoked is the strictly better
// failure: the certificate still works, and the next rotation can retry both
// halves.
func TestReissueDoesNotRevokeWhenTheStoreSweepFails(t *testing.T) {
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
	store := &failingLifecycle{Storage: base, record: record}

	m := mtlsManager(t, srv, dir)
	m.VaultClient.SetToken("s.operational-token")
	old, err := loadCredential(dir)
	if err != nil {
		t.Fatal(err)
	}

	buf := captureSlog(t)
	// The rotation itself must still succeed: the replacement is issued,
	// persisted and operational, and a stale artefact is not worth failing it.
	if err := m.reissue(t.Context(), store, old); err != nil {
		t.Fatalf("a failed sweep must not fail the rotation: %v", err)
	}
	cred, err := loadCredential(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Serial != "aa:bb:cc" {
		t.Errorf("credential not rotated; serial=%q", cred.Serial)
	}

	if len(f.revokedSerials) != 0 {
		t.Errorf("revoked %v while the certificate was still installed in the store; events=%v",
			f.revokedSerials, events)
	}
	if !strings.Contains(buf.String(), "still installed") {
		t.Errorf("a skipped revocation must say why; log=%q", buf.String())
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
	// Assert on the failure line specifically. Matching a bare "revoke" would
	// also match the success line ("revoked a superseded mtls certificate"),
	// so the assertion would pass just as happily against a revocation that
	// worked — pinning nothing about the failure path it exists to cover.
	logged := buf.String()
	if len(f.revokedSerials) != 0 {
		t.Fatalf("the fake accepted a revocation it was configured to refuse: %v", f.revokedSerials)
	}
	if !strings.Contains(logged, "level=WARN") || !strings.Contains(logged, "stays valid at Vault") {
		t.Errorf("a failed revocation must WARN that the certificate is still valid; log=%q", logged)
	}
	if !strings.Contains(logged, "/revoke serial_number=") {
		t.Errorf("the WARN must name the manual remedy; log=%q", logged)
	}
}

// TestFailedRevocationIsRetriedOnTheNextRotation pins the durability half.
//
// A revocation failure is advisory, which alone would make it disappear: the
// envelope has just been overwritten with the replacement, so the serial
// survives nowhere but one WARN line. The commonest cause — a Vault policy
// without pki/revoke — is persistent, so every rotation would leave one more
// valid certificate behind, which is precisely the accumulation revocation
// exists to prevent. Carrying the serial forward means the backlog drains as
// soon as the cause clears.
func TestFailedRevocationIsRetriedOnTheNextRotation(t *testing.T) {
	ca := newTestCA(t)
	f := &fakeVault{ca: ca, failRevoke: true}
	srv := newFakeVaultServer(t, f)
	dir := t.TempDir()
	firstSerial := seedCredentialFile(t, ca, dir, time.Now().Add(3*24*time.Hour))

	m := mtlsManager(t, srv, dir)
	m.VaultClient.SetToken("s.operational-token")

	// Rotation one: revocation is refused, so the serial must be recorded.
	if err := m.ReissueIfDue(t.Context()); err != nil {
		t.Fatalf("first ReissueIfDue: %v", err)
	}
	cred, err := loadCredential(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cred.PendingRevocations) != 1 || cred.PendingRevocations[0] != firstSerial {
		t.Fatalf("pending revocations = %v, want [%s]", cred.PendingRevocations, firstSerial)
	}

	// Age the replacement into the re-issue window and let the policy be fixed.
	cred.NotAfter = time.Now().Add(3 * 24 * time.Hour)
	secondSerial := vaultSerialOf(t, cred)
	if err := saveCredential(dir, cred); err != nil {
		t.Fatal(err)
	}
	f.failRevoke = false

	// Rotation two: the backlog drains alongside the newly superseded cert.
	if err := m.ReissueIfDue(t.Context()); err != nil {
		t.Fatalf("second ReissueIfDue: %v", err)
	}
	if len(f.revokedSerials) != 2 {
		t.Fatalf("revoked %v, want both the backlog and the newly superseded certificate", f.revokedSerials)
	}
	if indexOf(f.revokedSerials, firstSerial) < 0 {
		t.Errorf("revoked %v, want it to include the retried %s", f.revokedSerials, firstSerial)
	}
	if indexOf(f.revokedSerials, secondSerial) < 0 {
		t.Errorf("revoked %v, want it to include the newly superseded %s", f.revokedSerials, secondSerial)
	}
	after, err := loadCredential(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.PendingRevocations) != 0 {
		t.Errorf("pending revocations = %v, want the backlog cleared", after.PendingRevocations)
	}
}

// TestSweptButUnrevokedIsNotQueuedWhenTheSweepFailed keeps the two halves of
// retirement from contradicting each other. A certificate the sweep could not
// remove is still installed, so it must not be queued for a later revocation
// either — that would just defer the revoked-yet-installed state rather than
// avoid it.
func TestSweptButUnrevokedIsNotQueuedWhenTheSweepFailed(t *testing.T) {
	ca := newTestCA(t)
	f := &fakeVault{ca: ca}
	srv := newFakeVaultServer(t, f)
	dir := t.TempDir()
	seedCredentialFile(t, ca, dir, time.Now().Add(3*24*time.Hour))

	base, err := securestore.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	store := &failingLifecycle{Storage: base, record: func(string) {}}

	m := mtlsManager(t, srv, dir)
	m.VaultClient.SetToken("s.operational-token")
	old, err := loadCredential(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.reissue(t.Context(), store, old); err != nil {
		t.Fatalf("reissue: %v", err)
	}
	cred, err := loadCredential(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cred.PendingRevocations) != 0 {
		t.Errorf("pending revocations = %v, want none: an unswept certificate must not be queued for revocation",
			cred.PendingRevocations)
	}
}

// vaultSerialOf reports the colon-hex serial of a credential's certificate.
func vaultSerialOf(t *testing.T, cred *sealedCredential) string {
	t.Helper()
	return vault.FormatSerial(mustLeaf(t, cred.CertPEM).SerialNumber)
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

	// Strip both sources of a serial. Clearing the recorded field alone no
	// longer suffices — revocation derives the serial from the certificate —
	// so the envelope is edited in memory and handed straight to reissue.
	cred, err := loadCredential(dir)
	if err != nil {
		t.Fatal(err)
	}
	cred.Serial = ""
	cred.CertPEM = ""

	base, err := securestore.Open("file")
	if err != nil {
		t.Fatal(err)
	}

	m := mtlsManager(t, srv, dir)
	m.VaultClient.SetToken("s.operational-token")
	if err := m.reissue(t.Context(), base, cred); err != nil {
		t.Fatalf("reissue: %v", err)
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
// a serial that could not match anything and quietly revoke nothing. The
// encoding itself is pinned in internal/vault, which owns the wire format.
func TestSeedRecordsRevocableSerial(t *testing.T) {
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
	if want := vault.FormatSerial(mustLeaf(t, leaf).SerialNumber); serial != want {
		t.Errorf("BYO serial = %q, want %q", serial, want)
	}
}

// TestSupersededSerialPrefersTheCertificate pins that revocation derives the
// serial from the credential's own certificate rather than trusting the
// recorded field.
//
// Normalising at write time fixes envelopes written from now on. It does
// nothing for the ones already on disk — a BYO host upgraded from an earlier
// build still carries a decimal serial, and that host's first rotation is
// exactly the one that would try to use it. The certificate is present in every
// envelope and is unambiguous, so it is the authority.
func TestSupersededSerialPrefersTheCertificate(t *testing.T) {
	ca := newTestCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := ca.signLeaf(t, &key.PublicKey, "alice", time.Now().Add(24*time.Hour))
	want := vault.FormatSerial(mustLeaf(t, leaf).SerialNumber)

	t.Run("stale decimal serial is overridden", func(t *testing.T) {
		// What an envelope written by an earlier build actually looks like.
		cred := &sealedCredential{
			CertPEM: leaf,
			Serial:  mustLeaf(t, leaf).SerialNumber.String(), // decimal
		}
		if got := supersededSerial(cred); got != want {
			t.Errorf("supersededSerial = %q, want the certificate's %q", got, want)
		}
	})

	t.Run("falls back to the field when the PEM will not parse", func(t *testing.T) {
		cred := &sealedCredential{CertPEM: "not a certificate", Serial: "aa:bb:cc"}
		if got := supersededSerial(cred); got != "aa:bb:cc" {
			t.Errorf("supersededSerial = %q, want the recorded aa:bb:cc", got)
		}
	})

	t.Run("no certificate and no field yields nothing to revoke", func(t *testing.T) {
		if got := supersededSerial(&sealedCredential{}); got != "" {
			t.Errorf("supersededSerial = %q, want empty", got)
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
	wantSerial := seedCredentialFile(t, ca, dir, time.Now().Add(3*24*time.Hour))

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
	if len(f.revokedSerials) != 1 || f.revokedSerials[0] != wantSerial {
		t.Errorf("revoked %v, want [%s]", f.revokedSerials, wantSerial)
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
