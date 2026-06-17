//go:build linux || windows

package securestore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
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

// PCR7 (Secure Boot) is claimed by BitLocker on Windows, so the seal_to_pcrs
// binding must drop it there to avoid coupling our credential to BitLocker's
// re-seal cycle; other platforms keep it.
func TestPCRSelectionFor(t *testing.T) {
	cases := map[string][]int{
		"windows": {0, 2, 4},
		"linux":   {0, 2, 4, 7},
		"darwin":  {0, 2, 4, 7},
	}
	for goos, want := range cases {
		got := pcrSelectionFor(goos)
		if got.Hash != tpm2.AlgSHA256 {
			t.Errorf("%s: hash = %v, want SHA256", goos, got.Hash)
		}
		if len(got.PCRs) != len(want) {
			t.Fatalf("%s: PCRs = %v, want %v", goos, got.PCRs, want)
		}
		for i := range want {
			if got.PCRs[i] != want[i] {
				t.Errorf("%s: PCRs = %v, want %v", goos, got.PCRs, want)
				break
			}
		}
		if goos == "windows" {
			for _, p := range got.PCRs {
				if p == 7 {
					t.Errorf("windows PCR selection must exclude PCR7 (BitLocker), got %v", got.PCRs)
				}
			}
		}
	}
}
