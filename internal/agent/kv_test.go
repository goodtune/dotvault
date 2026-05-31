package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/vault"
	"golang.org/x/crypto/ssh"
)

type fakeKV struct {
	keys []string
	data map[string]map[string]any // leaf name -> secret data
}

func (f *fakeKV) ListKVv2(_ context.Context, _, _ string) ([]string, error) {
	return f.keys, nil
}

func (f *fakeKV) ReadKVv2(_ context.Context, _, path string) (*vault.Secret, error) {
	name := path[strings.LastIndex(path, "/")+1:]
	d, ok := f.data[name]
	if !ok {
		return nil, nil
	}
	return &vault.Secret{Data: d}, nil
}

func TestKVSourceIdentities(t *testing.T) {
	pubA, privA, _, _ := genEd25519(t, "a")
	pubB, privB, _, _ := genEd25519(t, "b")
	fk := &fakeKV{
		keys: []string{"a", "b", "nested/"},
		data: map[string]map[string]any{
			"a": {"public_key": pubA, "private_key": privA},
			"b": {"public_key": pubB, "private_key": privB},
		},
	}
	src := newKVSource("kv", fk, "kv", "users/me/ssh/")
	ids, err := src.Identities(context.Background())
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("want 2 identities (nested/ skipped), got %d", len(ids))
	}
	if ids[0].Comment != "users/me/ssh/a" {
		t.Errorf("comment = %q, want users/me/ssh/a", ids[0].Comment)
	}
}

func TestKVSourceSign(t *testing.T) {
	pubA, privA, parsedPub, _ := genEd25519(t, "a")
	fk := &fakeKV{
		keys: []string{"a"},
		data: map[string]map[string]any{"a": {"public_key": pubA, "private_key": privA}},
	}
	src := newKVSource("kv", fk, "kv", "users/me/ssh/")

	data := []byte("challenge")
	sig, matched, err := src.Sign(context.Background(), parsedPub, data, 0)
	if err != nil || !matched {
		t.Fatalf("Sign: matched=%v err=%v", matched, err)
	}
	if err := parsedPub.Verify(data, sig); err != nil {
		t.Errorf("verify: %v", err)
	}
}

func TestKVSourceSignUnmatchedReturnsFalse(t *testing.T) {
	pubA, privA, _, _ := genEd25519(t, "a")
	_, _, otherPub, _ := genEd25519(t, "other")
	fk := &fakeKV{
		keys: []string{"a"},
		data: map[string]map[string]any{"a": {"public_key": pubA, "private_key": privA}},
	}
	src := newKVSource("kv", fk, "kv", "users/me/ssh/")
	_, matched, err := src.Sign(context.Background(), otherPub, []byte("x"), 0)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if matched {
		t.Errorf("matched should be false for a key this source does not own")
	}
}

func TestKVSourcePassphraseKeyRejected(t *testing.T) {
	// A passphrase-encrypted private key: the agent cannot use it.
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(sk, "c", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	priv := string(pem.EncodeToMemory(block))
	sshPub, _ := ssh.NewPublicKey(pk)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	fk := &fakeKV{
		keys: []string{"c"},
		data: map[string]map[string]any{"c": {"public_key": pubLine, "private_key": priv}},
	}
	src := newKVSource("kv", fk, "kv", "users/me/ssh/")
	_, _, err = src.Sign(context.Background(), sshPub, []byte("x"), 0)
	if err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("want passphrase error, got %v", err)
	}
}

func TestKVSourceSkipsNonKeySecret(t *testing.T) {
	fk := &fakeKV{
		keys: []string{"notakey"},
		data: map[string]map[string]any{"notakey": {"some": "value"}},
	}
	src := newKVSource("kv", fk, "kv", "users/me/ssh/")
	ids, err := src.Identities(context.Background())
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("want 0 identities, got %d", len(ids))
	}
}
