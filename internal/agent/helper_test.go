package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// genEd25519 returns an OpenSSH key pair as the strings the KV schema stores
// (authorized_keys public line, PEM private key) plus the parsed public key and
// a usable signer.
func genEd25519(t *testing.T, comment string) (pubLine, privPEM string, pub ssh.PublicKey, signer ssh.Signer) {
	t.Helper()
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(sk, comment)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privPEM = string(pem.EncodeToMemory(block))
	sshPub, err := ssh.NewPublicKey(pk)
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}
	pubLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " " + comment
	signer, err = ssh.ParsePrivateKey([]byte(privPEM))
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	_ = pk
	return pubLine, privPEM, sshPub, signer
}

// fakeSource is a configurable Source for backend tests.
type fakeSource struct {
	name      string
	typ       string
	ids       []Identity
	signer    ssh.Signer // signs when a requested key matches one of ids
	idErr     error
	listCalls int
}

func (f *fakeSource) Name() string { return f.name }
func (f *fakeSource) Type() string {
	if f.typ == "" {
		return "fake"
	}
	return f.typ
}

func (f *fakeSource) Identities(context.Context) ([]Identity, error) {
	f.listCalls++
	if f.idErr != nil {
		return nil, f.idErr
	}
	return f.ids, nil
}

func (f *fakeSource) Sign(_ context.Context, key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, bool, error) {
	for _, id := range f.ids {
		if keyEqual(id.PubKey, key) {
			sig, err := signData(f.signer, data, flags)
			return sig, true, err
		}
	}
	return nil, false, nil
}
