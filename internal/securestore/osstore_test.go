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
		0x4:       true,  // NCRYPT_ALLOW_ARCHIVING_FLAG — a one-time export is still an extraction
		0x8:       true,  // NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG — one-time plaintext export
		0xC:       true,  // both archiving flags
		0xF:       true,  // everything set
		0x1 | 0x4: true,  // export + archiving
		0x10:      false, // an unrelated future bit must not read as exportable
	}
	for policy, want := range cases {
		if got := exportPolicyIsExportable(policy); got != want {
			t.Errorf("exportPolicyIsExportable(%#x) = %v, want %v", policy, got, want)
		}
	}
}

// TestExportPolicyArchivingFlagsAreLoadBearing pins the fix for the
// archiving-flag gap: the mask previously covered only 0x1|0x2, so a key CNG
// permits a one-time (or one-time plaintext) archival export of read as
// non-exportable, and assertNonExportable waved it through. This asserts the
// archiving bits are *individually* sufficient to fail the check, so the old
// two-flag mask cannot come back without a red test.
func TestExportPolicyArchivingFlagsAreLoadBearing(t *testing.T) {
	oldMask := func(policy uint32) bool {
		return policy&(cngAllowExport|cngAllowPlaintextExport) != 0
	}
	for _, policy := range []uint32{cngAllowArchiving, cngAllowPlaintextArchiving, cngAllowArchiving | cngAllowPlaintextArchiving} {
		if oldMask(policy) {
			t.Fatalf("test is not load-bearing: the old two-flag mask already rejected %#x", policy)
		}
		if !exportPolicyIsExportable(policy) {
			t.Errorf("exportPolicyIsExportable(%#x) = false; an archiving flag permits the private key to be exported and must fail the check", policy)
		}
	}
}

func TestNewOSContainerIsUniqueAndValid(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		name, err := newOSContainer()
		if err != nil {
			t.Fatalf("newOSContainer: %v", err)
		}
		if !strings.HasPrefix(name, osContainerPrefix) {
			t.Fatalf("container %q lacks prefix %q", name, osContainerPrefix)
		}
		if !validOSContainer(name) {
			t.Fatalf("generated container %q fails validOSContainer", name)
		}
		if seen[name] {
			t.Fatalf("duplicate container name %q — rotation would overwrite a live key", name)
		}
		seen[name] = true
	}
}

func TestValidOSContainer(t *testing.T) {
	cases := map[string]bool{
		osLegacyContainer:          true, // pre-rotation envelopes stay loadable
		"dotvault-mtls-0011aabb":   true,
		"dotvault-mtls-":           false, // empty suffix
		"dotvault-mtls-AABB":       false, // uppercase is not what we emit
		"dotvault-mtls-zz":         false, // not hex
		"dotvault-mtls-abc":        false, // odd-length hex
		"":                         false,
		"some-other-app":           false,
		"dotvault-mtls-00/../evil": false,
		"DOTVAULT-MTLS":            false,
	}
	for name, want := range cases {
		if got := validOSContainer(name); got != want {
			t.Errorf("validOSContainer(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestOSHandleRoundTrip(t *testing.T) {
	in := osHandle{Provider: "Microsoft Software Key Storage Provider", Container: "dotvault-mtls-deadbeef", Thumbprint: "ABCD"}
	b, err := encodeOSHandle(in)
	if err != nil {
		t.Fatalf("encodeOSHandle: %v", err)
	}
	out, err := decodeOSHandle(b)
	if err != nil {
		t.Fatalf("decodeOSHandle: %v", err)
	}
	if out != in {
		t.Errorf("round trip = %+v, want %+v", out, in)
	}
}

func TestDecodeOSHandleRejectsForeignContainer(t *testing.T) {
	for _, body := range []string{
		`{"provider":"p"}`, // no container
		`{"provider":"p","container":"someone-else"}`, // not ours: deleting it would be destructive
		`not json`,
	} {
		if _, err := decodeOSHandle([]byte(body)); err == nil {
			t.Errorf("decodeOSHandle(%s) succeeded, want error", body)
		}
	}
}

func TestDecodeOSHandleAcceptsLegacyEnvelope(t *testing.T) {
	// Envelopes written before rotation became two-phase name the single fixed
	// container and carry no thumbprint. They must keep loading, and the first
	// rotation then supersedes them.
	h, err := decodeOSHandle([]byte(`{"provider":"p","container":"dotvault-mtls"}`))
	if err != nil {
		t.Fatalf("decodeOSHandle(legacy): %v", err)
	}
	if h.Container != osLegacyContainer || h.Thumbprint != "" {
		t.Errorf("legacy handle = %+v", h)
	}
}

func TestCertSHA1Thumbprint(t *testing.T) {
	// Known-answer: the thumbprint of the empty DER input, uppercase hex SHA-1.
	if got := certSHA1Thumbprint(nil); got != "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709" {
		t.Errorf("certSHA1Thumbprint(nil) = %q", got)
	}
	block, _ := pem.Decode([]byte(makeCertPEM(t, "leaf")))
	tp := certSHA1Thumbprint(block.Bytes)
	if len(tp) != 40 {
		t.Errorf("thumbprint %q is not 40 hex chars", tp)
	}
	if tp != strings.ToUpper(tp) {
		t.Errorf("thumbprint %q is not uppercase (Windows convention)", tp)
	}
}

func TestSupersededOSArtifacts(t *testing.T) {
	old := osHandle{Container: "dotvault-mtls-1111", Thumbprint: "AAAA"}
	newer := osHandle{Container: "dotvault-mtls-2222", Thumbprint: "BBBB"}

	t.Run("rotation supersedes both", func(t *testing.T) {
		c, tp := supersededOSArtifacts(newer, old)
		if c != "dotvault-mtls-1111" || tp != "AAAA" {
			t.Errorf("got (%q, %q), want the old container and thumbprint", c, tp)
		}
	})

	t.Run("first seed supersedes nothing", func(t *testing.T) {
		if c, tp := supersededOSArtifacts(newer, osHandle{}); c != "" || tp != "" {
			t.Errorf("got (%q, %q), want empty", c, tp)
		}
	})

	t.Run("never deletes an artefact the new credential uses", func(t *testing.T) {
		same := osHandle{Container: newer.Container, Thumbprint: newer.Thumbprint}
		if c, tp := supersededOSArtifacts(newer, same); c != "" || tp != "" {
			t.Errorf("got (%q, %q), want empty — that is the live key/cert", c, tp)
		}
		// Legacy envelope: container superseded, but there is no old leaf
		// recorded, so nothing to delete on the certificate side.
		legacy := osHandle{Container: osLegacyContainer}
		if c, tp := supersededOSArtifacts(newer, legacy); c != osLegacyContainer || tp != "" {
			t.Errorf("got (%q, %q), want (%q, \"\")", c, tp, osLegacyContainer)
		}
	})
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

// TestRSABitsOrDefault covers the modulus-size defaulting shared by both
// key-generating backends.
//
// It lives in the platform-neutral file deliberately: the Windows CNG backend
// cannot be compiled or run off Windows, so without a shared helper its half of
// this logic would be verified by inspection only — and the two backends could
// drift on what an unset key_bits means, giving `mtls` and `mtls+os` different
// key sizes from identical config.
func TestRSABitsOrDefault(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want int
	}{
		{name: "unsetTakesDefault", in: 0, want: defaultRSABits},
		{name: "explicit2048", in: 2048, want: 2048},
		{name: "explicit3072", in: 3072, want: 3072},
		{name: "explicit4096", in: 4096, want: 4096},
		{name: "explicit8192", in: 8192, want: 8192},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rsaBitsOrDefault(tt.in); got != tt.want {
				t.Errorf("rsaBitsOrDefault(%d) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// TestDefaultRSABitsUnchanged pins the pre-key_bits behaviour: an operator who
// never sets key_bits must keep getting exactly what dotvault generated before
// the option existed, so upgrading cannot silently change their key size.
func TestDefaultRSABitsUnchanged(t *testing.T) {
	if defaultRSABits != 2048 {
		t.Errorf("defaultRSABits = %d, want 2048 — changing this alters key size for every operator who has not set key_bits", defaultRSABits)
	}
}
