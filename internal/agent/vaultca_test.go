package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type fakeCA struct {
	caSigner  ssh.Signer
	calls     int
	lastPrinc []string
	err       error // when set, SignSSHCert fails instead of minting
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromSigner(sk)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeCA{caSigner: s}
}

func (f *fakeCA) SignSSHCert(_ context.Context, _, _ string, pub ssh.PublicKey, principals []string, ttl time.Duration) (*ssh.Certificate, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	f.lastPrinc = principals
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		ValidPrincipals: principals,
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(ttl).Unix()),
	}
	if err := cert.SignCert(rand.Reader, f.caSigner); err != nil {
		return nil, err
	}
	return cert, nil
}

func TestVaultCASourceIdentities(t *testing.T) {
	ca := newFakeCA(t)
	src, err := newVaultCASource("ca", ca, "ssh", "role", []string{"{{.vault_username}}"}, "alice", 15*time.Minute, true)
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	ids, err := src.Identities(context.Background())
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("want 1 identity, got %d", len(ids))
	}
	if _, ok := ids[0].PubKey.(*ssh.Certificate); !ok {
		t.Errorf("identity is not a certificate")
	}
	if ids[0].Expiry.IsZero() {
		t.Errorf("certificate expiry not set")
	}
	if ca.lastPrinc[0] != "alice" {
		t.Errorf("principal template not expanded: %v", ca.lastPrinc)
	}
}

func TestVaultCASourceSign(t *testing.T) {
	ca := newFakeCA(t)
	src, err := newVaultCASource("ca", ca, "ssh", "role", nil, "alice", 15*time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cert := ids[0].PubKey
	data := []byte("challenge")
	sig, matched, err := src.Sign(context.Background(), cert, data, 0)
	if err != nil || !matched {
		t.Fatalf("Sign: matched=%v err=%v", matched, err)
	}
	if err := cert.Verify(data, sig); err != nil {
		t.Errorf("signature does not verify against cert: %v", err)
	}
}

func TestVaultCASourceCachesCert(t *testing.T) {
	ca := newFakeCA(t)
	src, err := newVaultCASource("ca", ca, "ssh", "role", nil, "alice", 15*time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := src.Identities(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if ca.calls != 1 {
		t.Errorf("want 1 mint (cached), got %d", ca.calls)
	}
}

func TestVaultCASourceReMintsNearExpiry(t *testing.T) {
	ca := newFakeCA(t)
	s, err := newVaultCASource("ca", ca, "ssh", "role", nil, "alice", 15*time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	vca := s.(*vaultCASource)
	if _, err := vca.Identities(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Jump the clock to within the renew skew of expiry.
	vca.now = func() time.Time { return time.Now().Add(15 * time.Minute) }
	if _, err := vca.Identities(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ca.calls != 2 {
		t.Errorf("want 2 mints (re-mint near expiry), got %d", ca.calls)
	}
}

func TestVaultCASourceNonEphemeralIsErrSource(t *testing.T) {
	ca := newFakeCA(t)
	src, err := newVaultCASource("ca", ca, "ssh", "role", nil, "alice", 15*time.Minute, false)
	if err != nil {
		t.Fatalf("constructor should not hard-fail: %v", err)
	}
	_, err = src.Identities(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ephemeral") {
		t.Errorf("want ephemeral error, got %v", err)
	}
}

// TestVaultCASourceSignSkipsMintForForeignKeyOnceCached is the secondary
// hardening from the bug report: once a certificate is cached, Sign for a key
// this source plainly doesn't own must short-circuit via mayOwn and never
// attempt a mint, even when the CA is currently unable to mint (e.g. its role
// can't currently sign for the active auth identity).
func TestVaultCASourceSignSkipsMintForForeignKeyOnceCached(t *testing.T) {
	ca := newFakeCA(t)
	src, err := newVaultCASource("ca", ca, "ssh", "role", nil, "alice", 15*time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Identities(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ca.calls != 1 {
		t.Fatalf("want 1 mint to seed the cache, got %d", ca.calls)
	}

	// Now the CA can no longer mint (mirrors a role that stopped resolving
	// under the active Vault identity).
	ca.err = errors.New("permission denied")

	_, _, foreignPub, _ := genEd25519(t, "foreign")
	sig, matched, err := src.Sign(context.Background(), foreignPub, []byte("x"), 0)
	if err != nil || matched || sig != nil {
		t.Fatalf("Sign: want (nil, false, nil) for a foreign key, got (%v, %v, %v)", sig, matched, err)
	}
	if ca.calls != 1 {
		t.Errorf("want no mint attempt for a foreign key once cached, got %d calls", ca.calls)
	}
}

// TestVaultCASourceSignColdCacheForeignKeyStillErrors documents the residual
// gap mayOwn's comment calls out: on a cold cache (no certificate minted
// yet), ownership can't be ruled out cheaply, so Sign falls through to
// ensureCert. If the CA can't mint, Sign surfaces that error rather than
// silently returning (nil, false, nil) — Backend.SignWithFlags (the
// List-parity skip) is what keeps this from blocking other sources, not this
// method pretending the key isn't foreign.
func TestVaultCASourceSignColdCacheForeignKeyStillErrors(t *testing.T) {
	ca := newFakeCA(t)
	ca.err = errors.New("permission denied")
	src, err := newVaultCASource("ca", ca, "ssh", "role", nil, "alice", 15*time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}

	_, _, foreignPub, _ := genEd25519(t, "foreign")
	sig, matched, err := src.Sign(context.Background(), foreignPub, []byte("x"), 0)
	if err == nil || matched || sig != nil {
		t.Fatalf("Sign: want (nil, false, err) on a cold cache with a failing CA, got (%v, %v, %v)", sig, matched, err)
	}
	if ca.calls != 1 {
		t.Errorf("want exactly 1 mint attempt on a cold cache, got %d", ca.calls)
	}
}

func TestRenderPrincipals(t *testing.T) {
	out, err := renderPrincipals([]string{"{{.vault_username}}", "ops-{{.vault_username}}"}, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if out[0] != "bob" || out[1] != "ops-bob" {
		t.Errorf("got %v", out)
	}
}
