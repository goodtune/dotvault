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

			signer, handle, err := s.Generate(kt, false)
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
