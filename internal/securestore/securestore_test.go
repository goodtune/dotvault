package securestore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func TestOpenUnknownBackend(t *testing.T) {
	if _, err := Open("nope"); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestModeForMethod(t *testing.T) {
	for method, want := range map[string]string{
		"mtls+tpm": "tpm",
		"mtls+os":  "os",
		"mtls":     "file",
		"oidc":     "file",
		"":         "file",
	} {
		if got := ModeForMethod(method); got != want {
			t.Errorf("ModeForMethod(%q) = %q, want %q", method, got, want)
		}
	}
}

func TestFileBackendCapabilities(t *testing.T) {
	s, err := Open("file")
	if err != nil {
		t.Fatal(err)
	}
	caps := s.Capabilities()
	if caps.Name != "file" || caps.HardwareBound {
		t.Errorf("unexpected caps: %+v", caps)
	}
}

func TestFileBackendGenerateLoadSign(t *testing.T) {
	for _, kt := range []KeyType{KeyEC, KeyRSA} {
		t.Run(string(kt), func(t *testing.T) {
			s, err := Open("file")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			signer, handle, err := s.Generate(kt, 0, false)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if len(handle) == 0 {
				t.Fatal("empty handle")
			}

			// Reload from the handle and confirm it is the same key by
			// signing with the loaded signer and verifying with the original
			// public key.
			loaded, err := s.Load(handle)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}

			digest := sha256.Sum256([]byte("dotvault cert-auth handshake"))
			sig, err := loaded.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			switch pub := signer.Public().(type) {
			case *ecdsa.PublicKey:
				if !ecdsa.VerifyASN1(pub, digest[:], sig) {
					t.Error("ECDSA signature did not verify against original public key")
				}
			case *rsa.PublicKey:
				if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
					t.Errorf("RSA signature did not verify: %v", err)
				}
			default:
				t.Fatalf("unexpected public key type %T", pub)
			}
		})
	}
}

func TestFileBackendImportRoundTrip(t *testing.T) {
	orig, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := Open("file")
	defer s.Close()

	signer, handle, err := s.Import(orig, false)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	loaded, err := s.Load(handle)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := loaded.Public().(*ecdsa.PublicKey)
	want := signer.Public().(*ecdsa.PublicKey)
	if got.X.Cmp(want.X) != 0 || got.Y.Cmp(want.Y) != 0 {
		t.Error("imported key did not round-trip")
	}
}

func TestFileBackendBadHandle(t *testing.T) {
	s, _ := Open("file")
	if _, err := s.Load([]byte("not a pem")); err == nil {
		t.Error("expected error loading garbage handle")
	}
}

// TestFileBackendGenerateKeyBits pins that a requested RSA modulus size is
// actually honoured, not merely accepted.
//
// The motivating failure is silent: a Vault PKI role's key_bits is a MINIMUM
// (SignCert rejects a CSR whose key is smaller than the role requires), so if
// key_bits were plumbed through config and then dropped on the floor, dotvault
// would keep generating 2048-bit keys and issuance against a 4096-bit role
// would keep failing with a Vault-side error that names nothing about dotvault's
// config. Asserting the generated key's real bit length is therefore the whole
// point — a test that only checked the config parsed would not catch it.
func TestFileBackendGenerateKeyBits(t *testing.T) {
	tests := []struct {
		name     string
		kt       KeyType
		bits     int
		wantBits int
	}{
		{name: "rsaDefault", kt: KeyRSA, bits: 0, wantBits: defaultRSABits},
		{name: "rsa2048", kt: KeyRSA, bits: 2048, wantBits: 2048},
		{name: "rsa3072", kt: KeyRSA, bits: 3072, wantBits: 3072},
		{name: "rsa4096", kt: KeyRSA, bits: 4096, wantBits: 4096},
		// 8192 is deliberately NOT generated here. It is valid per Vault, but
		// generating one costs seconds of CPU on every run — and the -short
		// guard that would have skipped it is dead weight, because neither the
		// Makefile nor CI passes -short. Its plumbing is covered without
		// generation by TestKeyBitsReachesGenerate in internal/auth, and
		// rsaBitsOrDefault covers the value itself, so the only thing an 8192
		// generation would add is wall-clock.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Open("file")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			signer, _, err := s.Generate(tt.kt, tt.bits, false)
			if err != nil {
				t.Fatalf("Generate(%v, %d): %v", tt.kt, tt.bits, err)
			}
			pub, ok := signer.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatalf("public key is %T, want *rsa.PublicKey", signer.Public())
			}
			if got := pub.N.BitLen(); got != tt.wantBits {
				t.Errorf("generated modulus = %d bits, want %d — key_bits was not honoured", got, tt.wantBits)
			}
		})
	}
}

// TestFileBackendECIgnoresKeyBits: EC is fixed at P-256, so a stray bits value
// must not change the curve or error. Config rejects the combination before it
// reaches here, but the backend should not depend on that.
func TestFileBackendECIgnoresKeyBits(t *testing.T) {
	s, err := Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	signer, _, err := s.Generate(KeyEC, 4096, false)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *ecdsa.PublicKey", signer.Public())
	}
	if pub.Curve != elliptic.P256() {
		t.Errorf("curve = %v, want P-256", pub.Curve.Params().Name)
	}
}
