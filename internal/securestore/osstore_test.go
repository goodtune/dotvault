package securestore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// makeCertPEM builds a self-signed certificate and returns its PEM block, for
// assembling test chains for parseLeafAndIssuer.
func makeCertPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestExportPolicyIsExportable(t *testing.T) {
	cases := map[uint32]bool{
		0x0:       false, // NCRYPT_ALLOW_EXPORT_NONE — the non-exportable default we require
		0x1:       true,  // NCRYPT_ALLOW_EXPORT_FLAG
		0x2:       true,  // NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
		0x3:       true,  // both export flags
		0x4:       false, // NCRYPT_ALLOW_ARCHIVING_FLAG — backup/escrow, not key extraction
		0x1 | 0x4: true,  // export + archiving
	}
	for policy, want := range cases {
		if got := exportPolicyIsExportable(policy); got != want {
			t.Errorf("exportPolicyIsExportable(%#x) = %v, want %v", policy, got, want)
		}
	}
}

func TestParseLeafAndIssuer(t *testing.T) {
	leafPEM := makeCertPEM(t, "leaf")
	caPEM := makeCertPEM(t, "issuer")

	t.Run("leaf plus issuer", func(t *testing.T) {
		leaf, issuer, err := parseLeafAndIssuer(leafPEM + caPEM)
		if err != nil {
			t.Fatalf("parseLeafAndIssuer: %v", err)
		}
		if leaf.Subject.CommonName != "leaf" {
			t.Errorf("leaf CN = %q, want leaf", leaf.Subject.CommonName)
		}
		if issuer.Subject.CommonName != "issuer" {
			t.Errorf("issuer CN = %q, want issuer", issuer.Subject.CommonName)
		}
	})

	t.Run("leaf only rejected", func(t *testing.T) {
		_, _, err := parseLeafAndIssuer(leafPEM)
		if err == nil || !strings.Contains(err.Error(), "issuing CA chain") {
			t.Fatalf("err = %v, want issuing-CA-chain error", err)
		}
	})

	t.Run("empty rejected", func(t *testing.T) {
		if _, _, err := parseLeafAndIssuer(""); err == nil {
			t.Fatal("expected error for empty PEM")
		}
	})

	t.Run("non-certificate PEM rejected", func(t *testing.T) {
		junk := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}))
		if _, _, err := parseLeafAndIssuer(junk); err == nil {
			t.Fatal("expected error when no CERTIFICATE block present")
		}
	})
}
