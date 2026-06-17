//go:build linux || windows

package securestore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// TestScalarKeyRoundTrip exercises the pure-Go scalar (de)serialisation the TPM
// backend relies on, without needing a TPM: a P-256 key marshalled to its
// 32-byte scalar (as seal does) and reconstructed (as Load does) must yield the
// same key. This guards the FillBytes/scalarToKey path that the sealed handle
// round-trips through, which no live test can cover in CI (no TPM, and the
// simulator requires CGO).
func TestScalarKeyRoundTrip(t *testing.T) {
	for i := 0; i < 50; i++ {
		orig, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		scalar := orig.D.FillBytes(make([]byte, 32))

		signer, err := scalarToKey(scalar)
		if err != nil {
			t.Fatalf("scalarToKey: %v", err)
		}
		got := signer.Public().(*ecdsa.PublicKey)
		if got.X.Cmp(orig.X) != 0 || got.Y.Cmp(orig.Y) != 0 {
			t.Fatalf("reconstructed public key mismatch on iteration %d", i)
		}

		// The reconstructed key must produce verifiable signatures.
		digest := sha256.Sum256([]byte("tpm scalar round-trip"))
		sig, err := signer.Sign(rand.Reader, digest[:], nil)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if !ecdsa.VerifyASN1(&orig.PublicKey, digest[:], sig) {
			t.Fatal("signature from reconstructed key did not verify")
		}
	}
}

func TestScalarKeyRejectsOutOfRange(t *testing.T) {
	// Zero scalar is invalid.
	if _, err := scalarToKey(make([]byte, 32)); err == nil {
		t.Error("expected error for zero scalar")
	}
}
