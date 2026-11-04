package clientcert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
)

// envelopeSpec describes a credential.json to write.
type envelopeSpec struct {
	serial    int64
	cn        string
	identity  string
	method    string
	backend   string
	notBefore time.Time
	notAfter  time.Time
}

func (s envelopeSpec) withDefaults() envelopeSpec {
	if s.serial == 0 {
		s.serial = 0x1001
	}
	if s.cn == "" {
		s.cn = "gary"
	}
	if s.identity == "" {
		s.identity = "gary"
	}
	if s.method == "" {
		s.method = "mtls"
	}
	if s.backend == "" {
		s.backend = "file"
	}
	if s.notBefore.IsZero() {
		s.notBefore = time.Now().Add(-time.Hour).Truncate(time.Second)
	}
	if s.notAfter.IsZero() {
		s.notAfter = s.notBefore.Add(10 * 24 * time.Hour)
	}
	return s
}

// writeEnvelope writes a credential.json under dir in auth's on-disk format
// (schema 1, file backend, PKCS#8 PEM handle) with a fresh key and a
// certificate for it, and returns the file's path.
func writeEnvelope(t *testing.T, dir string, spec envelopeSpec) string {
	t.Helper()
	spec = spec.withDefaults()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(spec.serial),
		Subject:      pkix.Name{CommonName: spec.cn},
		NotBefore:    spec.notBefore,
		NotAfter:     spec.notAfter,
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
	env := map[string]any{
		"schema":    1,
		"method":    spec.method,
		"backend":   spec.backend,
		"cert_pem":  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"handle":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		"serial":    "ignored",
		"not_after": spec.notAfter,
		"identity":  spec.identity,
		"issued_at": spec.notBefore,
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credential.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHeldServesEnvelope(t *testing.T) {
	dir := t.TempDir()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	notAfter := notBefore.Add(10 * 24 * time.Hour)
	writeEnvelope(t, dir, envelopeSpec{serial: 0xABCD, cn: "gary", notBefore: notBefore, notAfter: notAfter})

	src := NewHeld(dir, "mtls", "gary", 24*time.Hour)
	p, err := src.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.Source != SourceHeld {
		t.Errorf("Source = %q", p.Source)
	}
	if p.CommonName != "gary" {
		t.Errorf("CommonName = %q", p.CommonName)
	}
	if p.Serial != "ab:cd" {
		t.Errorf("Serial = %q, want ab:cd", p.Serial)
	}
	if !p.NotBefore.Equal(notBefore) || !p.NotAfter.Equal(notAfter) {
		t.Errorf("validity = %v..%v", p.NotBefore, p.NotAfter)
	}
	if want := notAfter.Add(-24 * time.Hour); !p.RefreshAt.Equal(want) {
		t.Errorf("RefreshAt = %v, want NotAfter - reissue_before = %v", p.RefreshAt, want)
	}
	if _, err := p.TLSCertificate(); err != nil {
		t.Fatalf("pair does not assemble: %v", err)
	}
	if p.Fingerprint() == "" {
		t.Error("no fingerprint")
	}
}

func TestHeldRefreshAtFallsBackToHalfLife(t *testing.T) {
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	notAfter := notBefore.Add(4 * time.Hour)
	// Zero reissue_before, and one longer than the certificate's life, which
	// would put RefreshAt before NotBefore.
	for _, rb := range []time.Duration{0, 168 * time.Hour} {
		dir := t.TempDir()
		writeEnvelope(t, dir, envelopeSpec{notBefore: notBefore, notAfter: notAfter})
		p, err := NewHeld(dir, "mtls", "gary", rb).Current(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if want := notBefore.Add(2 * time.Hour); !p.RefreshAt.Equal(want) {
			t.Errorf("reissue_before %v: RefreshAt = %v, want half-life %v", rb, p.RefreshAt, want)
		}
	}
}

func TestHeldCachesUntilEnvelopeChanges(t *testing.T) {
	dir := t.TempDir()
	writeEnvelope(t, dir, envelopeSpec{serial: 1})
	src := NewHeld(dir, "mtls", "gary", time.Hour)
	p1, err := src.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p2, err := src.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p1 != p2 {
		t.Fatal("unchanged envelope was re-exported")
	}
}

func TestHeldReloadsAfterRotation(t *testing.T) {
	dir := t.TempDir()
	path := writeEnvelope(t, dir, envelopeSpec{serial: 0x01})
	old := time.Now().Add(-time.Minute).Truncate(time.Second)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	src := NewHeld(dir, "mtls", "gary", time.Hour)
	p1, err := src.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	writeEnvelope(t, dir, envelopeSpec{serial: 0x02})
	bumped := old.Add(time.Minute)
	if err := os.Chtimes(path, bumped, bumped); err != nil {
		t.Fatal(err)
	}
	p2, err := src.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p1.Serial == p2.Serial {
		t.Fatalf("serial unchanged after rotation: %s", p2.Serial)
	}
	if p2.Serial != "02" {
		t.Errorf("Serial = %q, want 02", p2.Serial)
	}
}

// A rewrite inside the same second must still be noticed: the comparison is on
// the full-resolution mtime and the size, not a truncated timestamp.
func TestHeldSeesSameSecondRewrite(t *testing.T) {
	dir := t.TempDir()
	path := writeEnvelope(t, dir, envelopeSpec{serial: 0x01})
	base := time.Now().Add(-time.Minute).Truncate(time.Second)
	if err := os.Chtimes(path, base, base); err != nil {
		t.Fatal(err)
	}
	src := NewHeld(dir, "mtls", "gary", time.Hour)
	p1, err := src.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("sub-second mtime change", func(t *testing.T) {
		writeEnvelope(t, dir, envelopeSpec{serial: 0x02})
		sub := base.Add(500 * time.Millisecond)
		if err := os.Chtimes(path, sub, sub); err != nil {
			t.Fatal(err)
		}
		fi, _ := os.Stat(path)
		if !fi.ModTime().Equal(sub) {
			t.Skip("filesystem does not keep sub-second mtimes")
		}
		p2, err := src.Current(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if p2.Serial == p1.Serial {
			t.Fatal("same-second rewrite with a new mtime was missed")
		}
	})

	t.Run("size change with identical mtime", func(t *testing.T) {
		cur, err := src.Current(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		fi, _ := os.Stat(path)
		same := fi.ModTime()
		// A longer common name makes the envelope a different size.
		writeEnvelope(t, dir, envelopeSpec{serial: 0x03, cn: "gary-with-a-longer-name"})
		if err := os.Chtimes(path, same, same); err != nil {
			t.Fatal(err)
		}
		p3, err := src.Current(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if p3.Serial == cur.Serial {
			t.Fatal("rewrite with the same mtime but a new size was missed")
		}
	})
}

func TestHeldErrors(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		_, err := NewHeld(t.TempDir(), "mtls", "gary", time.Hour).Current(context.Background())
		if !errors.Is(err, auth.ErrNoCertCredential) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		dir := t.TempDir()
		nb := time.Now().Add(-48 * time.Hour)
		writeEnvelope(t, dir, envelopeSpec{notBefore: nb, notAfter: nb.Add(time.Hour)})
		_, err := NewHeld(dir, "mtls", "gary", time.Hour).Current(context.Background())
		if !errors.Is(err, auth.ErrNoCertCredential) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("another user's", func(t *testing.T) {
		dir := t.TempDir()
		writeEnvelope(t, dir, envelopeSpec{identity: "mallory"})
		_, err := NewHeld(dir, "mtls", "gary", time.Hour).Current(context.Background())
		if !errors.Is(err, auth.ErrNoCertCredential) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("not exportable", func(t *testing.T) {
		dir := t.TempDir()
		writeEnvelope(t, dir, envelopeSpec{method: "mtls+tpm", backend: "tpm"})
		_, err := NewHeld(dir, "mtls+tpm", "gary", time.Hour).Current(context.Background())
		if !errors.Is(err, auth.ErrHeldNotExportable) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestHeldNoLongerServesAfterEnvelopeRemoved(t *testing.T) {
	dir := t.TempDir()
	path := writeEnvelope(t, dir, envelopeSpec{})
	src := NewHeld(dir, "mtls", "gary", time.Hour)
	if _, err := src.Current(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Current(context.Background()); !errors.Is(err, auth.ErrNoCertCredential) {
		t.Fatalf("err = %v, want ErrNoCertCredential", err)
	}
}

func TestHeldLast(t *testing.T) {
	dir := t.TempDir()
	path := writeEnvelope(t, dir, envelopeSpec{})
	src := NewHeld(dir, "mtls", "gary", time.Hour)
	r := src.(lastReporter)
	if p, err := r.Last(); p != nil || err != nil {
		t.Fatalf("before any call: %v, %v", p, err)
	}
	p, err := src.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if lp, lerr := r.Last(); lp != p || lerr != nil {
		t.Fatalf("after success: %v, %v", lp, lerr)
	}
	os.Remove(path)
	if _, err := src.Current(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	lp, lerr := r.Last()
	if lp != p {
		t.Error("Last dropped the most recent pair after a failure")
	}
	if !errors.Is(lerr, auth.ErrNoCertCredential) {
		t.Errorf("Last error = %v", lerr)
	}
}

func TestHeldErrorsCarryNoKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	writeEnvelope(t, dir, envelopeSpec{identity: "mallory"})
	_, err := NewHeld(dir, "mtls", "gary", time.Hour).Current(context.Background())
	if err == nil || strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatalf("err = %v", err)
	}
}

func TestHeldLastDoesNotWaitOnCurrent(t *testing.T) {
	h := NewHeld(t.TempDir(), "mtls", "gary", 0).(*held)
	// A Current stuck in file I/O on a hung cache directory holds h.mu.
	h.mu.Lock()
	defer h.mu.Unlock()
	done := make(chan struct{})
	go func() {
		_, _ = h.Last()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Last blocked behind Current")
	}
}
