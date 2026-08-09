package sshfwd

import (
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

type fakeBackend struct {
	keys     []*sshagent.Key
	signer   ssh.Signer
	signErr  error
	signCall int
}

func (f *fakeBackend) List() ([]*sshagent.Key, error) { return f.keys, nil }

func (f *fakeBackend) SignWithFlags(key ssh.PublicKey, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error) {
	f.signCall++
	if f.signErr != nil {
		return nil, f.signErr
	}
	return f.signer.Sign(rand.Reader, data)
}

func TestSignersWrapsEachBackendIdentity(t *testing.T) {
	s, pub := testKey(t)
	fb := &fakeBackend{
		keys:   []*sshagent.Key{{Format: pub.Type(), Blob: pub.Marshal(), Comment: "dotvault"}},
		signer: s,
	}

	signers, err := Signers(fb)
	if err != nil {
		t.Fatalf("Signers() = %v", err)
	}
	if len(signers) != 1 {
		t.Fatalf("Signers() returned %d, want 1", len(signers))
	}
	if string(signers[0].PublicKey().Marshal()) != string(pub.Marshal()) {
		t.Error("wrapped signer advertises the wrong public key")
	}

	sig, err := signers[0].Sign(rand.Reader, []byte("payload"))
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}
	if fb.signCall != 1 {
		t.Errorf("backend SignWithFlags called %d times, want 1 — signing must delegate, not use a local key", fb.signCall)
	}
	if err := pub.Verify([]byte("payload"), sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}

func TestSignersPropagatesSignError(t *testing.T) {
	s, pub := testKey(t)
	want := errors.New("vault unavailable")
	fb := &fakeBackend{
		keys:    []*sshagent.Key{{Format: pub.Type(), Blob: pub.Marshal()}},
		signer:  s,
		signErr: want,
	}
	signers, err := Signers(fb)
	if err != nil {
		t.Fatalf("Signers() = %v", err)
	}
	if _, err := signers[0].Sign(rand.Reader, []byte("x")); !errors.Is(err, want) {
		t.Fatalf("Sign() err = %v, want %v", err, want)
	}
}

func TestSignersOnEmptyBackend(t *testing.T) {
	signers, err := Signers(&fakeBackend{})
	if err != nil {
		t.Fatalf("Signers() = %v", err)
	}
	if len(signers) != 0 {
		t.Fatalf("Signers() returned %d, want 0", len(signers))
	}
}
