package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// seedHeld writes an envelope with the given method/backend/identity/expiry and
// returns the key the certificate was issued for.
func seedHeld(t *testing.T, dir, method, backend, identity string, notAfter time.Time, handle func(*ecdsa.PrivateKey) []byte) *ecdsa.PrivateKey {
	t.Helper()
	ca := newTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := ca.signLeaf(t, &key.PublicKey, "alice", notAfter)
	cred := &sealedCredential{
		Method:   method,
		Backend:  backend,
		CertPEM:  leaf + ca.pem,
		Handle:   handle(key),
		Serial:   "aa:bb",
		NotAfter: notAfter,
		Identity: identity,
		IssuedAt: time.Now(),
	}
	if err := saveCredential(dir, cred); err != nil {
		t.Fatal(err)
	}
	return key
}

func pkcs8Handle(t *testing.T) func(*ecdsa.PrivateKey) []byte {
	return func(k *ecdsa.PrivateKey) []byte { return []byte(newPEMKey(t, k)) }
}

func TestExportHeldCertificate(t *testing.T) {
	dir := t.TempDir()
	notAfter := time.Now().Add(time.Hour).Truncate(time.Second)
	key := seedHeld(t, dir, "mtls", "file", "alice", notAfter, pkcs8Handle(t))

	held, err := ExportHeldCertificate(dir, "mtls", "alice")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(held.KeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("KeyPEM is not a PRIVATE KEY block: %v", block)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("KeyPEM is not PKCS#8: %v", err)
	}
	if !parsed.(*ecdsa.PrivateKey).Equal(key) {
		t.Fatal("exported key does not match the issued key")
	}
	cb, rest := pem.Decode(held.CertPEM)
	if cb == nil {
		t.Fatal("no certificate in CertPEM")
	}
	leaf, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("certificate public key does not match the exported key")
	}
	if len(rest) == 0 {
		t.Fatal("chain was not carried through verbatim")
	}
	if !held.NotAfter.Equal(notAfter) {
		t.Fatalf("NotAfter = %v, want %v", held.NotAfter, notAfter)
	}
	if held.Serial != "aa:bb" {
		t.Fatalf("Serial = %q", held.Serial)
	}
	if held.ModTime.IsZero() {
		t.Fatal("ModTime not set")
	}
}

// A legacy SEC1 handle must come out as PKCS#8 rather than being passed through.
func TestExportHeldNormalisesLegacyHandle(t *testing.T) {
	dir := t.TempDir()
	key := seedHeld(t, dir, "mtls", "file", "alice", time.Now().Add(time.Hour), func(k *ecdsa.PrivateKey) []byte {
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	})
	held, err := ExportHeldCertificate(dir, "mtls", "alice")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(held.KeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("want PRIVATE KEY block, got %v", block)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.(*ecdsa.PrivateKey).Equal(key) {
		t.Fatal("key mismatch")
	}
}

func TestExportHeldRefusesTPMAndOS(t *testing.T) {
	cases := []struct{ method, backend string }{
		{"mtls+tpm", "tpm"},
		{"mtls+os", "os"},
		// The envelope says file but the configured method is hardware: refuse
		// on the configured method alone.
		{"mtls+tpm", "file"},
		// The configured method is plain mtls but the envelope records a
		// hardware backend: refuse on the envelope alone.
		{"mtls", "tpm"},
		{"mtls", "os"},
		{"oidc", "file"},
	}
	for _, tc := range cases {
		t.Run(tc.method+"/"+tc.backend, func(t *testing.T) {
			dir := t.TempDir()
			seedHeld(t, dir, tc.method, tc.backend, "alice", time.Now().Add(time.Hour), pkcs8Handle(t))
			held, err := ExportHeldCertificate(dir, tc.method, "alice")
			if !errors.Is(err, ErrHeldNotExportable) {
				t.Fatalf("err = %v, want ErrHeldNotExportable", err)
			}
			if held != nil {
				t.Fatal("returned a certificate alongside the refusal")
			}
		})
	}
}

func TestExportHeldExpired(t *testing.T) {
	dir := t.TempDir()
	seedHeld(t, dir, "mtls", "file", "alice", time.Now().Add(-time.Minute), pkcs8Handle(t))
	if _, err := ExportHeldCertificate(dir, "mtls", "alice"); !errors.Is(err, ErrNoCertCredential) {
		t.Fatalf("err = %v, want ErrNoCertCredential", err)
	}
}

func TestExportHeldWrongIdentity(t *testing.T) {
	dir := t.TempDir()
	seedHeld(t, dir, "mtls", "file", "bob", time.Now().Add(time.Hour), pkcs8Handle(t))
	if _, err := ExportHeldCertificate(dir, "mtls", "alice"); !errors.Is(err, ErrNoCertCredential) {
		t.Fatalf("err = %v, want ErrNoCertCredential", err)
	}
}

func TestExportHeldAbsentAndEmptyDir(t *testing.T) {
	if _, err := ExportHeldCertificate(t.TempDir(), "mtls", "alice"); !errors.Is(err, ErrNoCertCredential) {
		t.Fatalf("absent envelope: err = %v, want ErrNoCertCredential", err)
	}
	if _, err := ExportHeldCertificate("", "mtls", "alice"); !errors.Is(err, ErrNoCertCredential) {
		t.Fatalf("empty dir: err = %v, want ErrNoCertCredential", err)
	}
}

// A rotation that lands between the stat and the read must leave the older
// mtime paired with the newer content, so the caller reloads once more rather
// than missing the rotation.
func TestExportHeldStatsBeforeRead(t *testing.T) {
	dir := t.TempDir()
	seedHeld(t, dir, "mtls", "file", "alice", time.Now().Add(time.Hour), pkcs8Handle(t))
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(credentialPath(dir), old, old); err != nil {
		t.Fatal(err)
	}

	heldAfterStat = func() {
		seedHeld(t, dir, "mtls", "file", "alice", time.Now().Add(2*time.Hour), pkcs8Handle(t))
		cred, err := loadCredential(dir)
		if err != nil {
			t.Fatal(err)
		}
		cred.Serial = "cc:dd"
		if err := saveCredential(dir, cred); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { heldAfterStat = nil })

	held, err := ExportHeldCertificate(dir, "mtls", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if held.Serial != "cc:dd" {
		t.Fatalf("Serial = %q, want the rotated content", held.Serial)
	}
	if !held.ModTime.Equal(old) {
		t.Fatalf("ModTime = %v, want the pre-read mtime %v", held.ModTime, old)
	}
}

// A key that is not the certificate's key is an unusable credential, and the
// error must not carry key material.
func TestExportHeldKeyCertMismatch(t *testing.T) {
	dir := t.TempDir()
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPEM := newPEMKey(t, other)
	seedHeld(t, dir, "mtls", "file", "alice", time.Now().Add(time.Hour), func(*ecdsa.PrivateKey) []byte {
		return []byte(otherPEM)
	})
	held, err := ExportHeldCertificate(dir, "mtls", "alice")
	if !errors.Is(err, ErrNoCertCredential) {
		t.Fatalf("err = %v, want ErrNoCertCredential", err)
	}
	if held != nil {
		t.Fatal("returned a certificate alongside the mismatch")
	}
	if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), otherPEM[40:80]) {
		t.Fatal("error carries key material")
	}
}
