//go:build !windows

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TestBackendAddForwardsToUpstream is the headline of the pass-through
// contract: `ssh-add` against dotvault's endpoint lands the key in the agent
// dotvault shadows. Without it a user who points SSH_AUTH_SOCK at dotvault
// permanently loses the ability to add a key at all.
func TestBackendAddForwardsToUpstream(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "upstream.sock")
	keyring := serveUpstreamAgentAt(t, sock)
	b := NewBackend([]Source{newUpstreamSource("agent", sock)})

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Add(agent.AddedKey{PrivateKey: sk, Comment: "added-through-dotvault"}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// The key is in the upstream agent, not held by dotvault.
	upstreamKeys, err := keyring.List()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreamKeys) != 1 || !keyEqual(upstreamKeys[0], pub) {
		t.Fatalf("upstream holds %d keys, want the one just added", len(upstreamKeys))
	}

	// And dotvault advertises it immediately: the mutation invalidates the
	// list cache, because `ssh-add` followed by `ssh-add -l` is how a user
	// checks it worked.
	served, err := b.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(served) != 1 || !keyEqual(served[0], pub) {
		t.Errorf("agent lists %d keys after Add, want the added key", len(served))
	}

	// It signs through dotvault too — a key that is listed but unusable would
	// be worse than not forwarding at all.
	data := []byte("challenge")
	sig, err := b.Sign(pub, data)
	if err != nil {
		t.Fatalf("Sign after Add: %v", err)
	}
	if err := pub.Verify(data, sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}

func TestBackendRemoveForwardsToUpstream(t *testing.T) {
	priv, pub := genUpstreamKey(t)
	sock := filepath.Join(t.TempDir(), "upstream.sock")
	keyring := serveUpstreamAgentAt(t, sock, priv)
	b := NewBackend([]Source{newUpstreamSource("agent", sock)})

	if err := b.Remove(pub); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	keys, err := keyring.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Errorf("upstream still holds %d keys after Remove", len(keys))
	}
}

// TestBackendRemoveVaultKeyIsReadOnly draws the line the feature depends on:
// forwarding mutations upstream must not make dotvault's own Vault-backed
// identities removable. They come from Vault and would return regardless, so
// answering read-only is both truthful and more useful than a no-op success.
func TestBackendRemoveVaultKeyIsReadOnly(t *testing.T) {
	upstreamPriv, _ := genUpstreamKey(t)
	sock := filepath.Join(t.TempDir(), "upstream.sock")
	serveUpstreamAgentAt(t, sock, upstreamPriv)

	_, _, vaultPub, vaultSigner := genEd25519(t, "vault-backed")
	b := NewBackend([]Source{
		&fakeSource{name: "kv", ids: []Identity{{PubKey: vaultPub}}, signer: vaultSigner},
		newUpstreamSource("agent", sock),
	})

	if err := b.Remove(vaultPub); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Remove(vault key) = %v, want ErrReadOnly", err)
	}
}

func TestBackendRemoveAllAndLockForwardToUpstream(t *testing.T) {
	priv, _ := genUpstreamKey(t)
	sock := filepath.Join(t.TempDir(), "upstream.sock")
	keyring := serveUpstreamAgentAt(t, sock, priv)
	b := NewBackend([]Source{newUpstreamSource("agent", sock)})

	// Lock/Unlock reach the upstream: a locked keyring reports no keys.
	if err := b.Lock([]byte("secret")); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if keys, _ := keyring.List(); len(keys) != 0 {
		t.Errorf("upstream lists %d keys while locked, want 0", len(keys))
	}
	if err := b.Unlock([]byte("secret")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if keys, _ := keyring.List(); len(keys) != 1 {
		t.Errorf("upstream lists %d keys after Unlock, want 1", len(keys))
	}

	if err := b.RemoveAll(); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if keys, _ := keyring.List(); len(keys) != 0 {
		t.Errorf("upstream still holds %d keys after RemoveAll", len(keys))
	}
}

// TestBackendMutationsReadOnlyWithoutUpstream confirms the default is
// unchanged: a dotvault with only Vault-backed sources is exactly as read-only
// as it was before mutations could be forwarded anywhere.
func TestBackendMutationsReadOnlyWithoutUpstream(t *testing.T) {
	_, _, pub, signer := genEd25519(t, "kv")
	b := NewBackend([]Source{&fakeSource{name: "kv", ids: []Identity{{PubKey: pub}}, signer: signer}})

	if err := b.Add(agent.AddedKey{}); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Add = %v, want ErrReadOnly", err)
	}
	if err := b.Remove(pub); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Remove = %v, want ErrReadOnly", err)
	}
	if err := b.RemoveAll(); !errors.Is(err, ErrReadOnly) {
		t.Errorf("RemoveAll = %v, want ErrReadOnly", err)
	}
	if err := b.Lock(nil); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Lock = %v, want ErrReadOnly", err)
	}
	if err := b.Unlock(nil); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Unlock = %v, want ErrReadOnly", err)
	}
	if _, err := b.Signers(); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Signers = %v, want ErrReadOnly", err)
	}
}

// TestBackendMutationsDoNotRequireVaultToken confirms a forwarded mutation is
// not gated on authentication. `ssh-add` touches no Vault-backed source by
// definition, so making it wait on a token dotvault does not need would strand
// it on an unauthenticated daemon for no benefit.
func TestBackendMutationsDoNotRequireVaultToken(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "upstream.sock")
	keyring := serveUpstreamAgentAt(t, sock)
	b := NewBackend([]Source{newUpstreamSource("agent", sock)},
		WithTokenProbe(func() bool { return false }))

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Add(agent.AddedKey{PrivateKey: sk}); err != nil {
		t.Fatalf("Add on a tokenless daemon: %v", err)
	}
	if keys, _ := keyring.List(); len(keys) != 1 {
		t.Errorf("upstream holds %d keys, want the one added without a token", len(keys))
	}
}

// TestUpstreamAddTargetsFirstEndpointOnly guards the one place a fan-out would
// be actively harmful: a private key must go to the agent the user meant, not
// be copied into every agent on the machine.
func TestUpstreamAddTargetsFirstEndpointOnly(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first.sock")
	second := filepath.Join(t.TempDir(), "second.sock")
	firstRing := serveUpstreamAgentAt(t, first)
	secondRing := serveUpstreamAgentAt(t, second)

	src := newUpstreamSourceFunc("agent", func(context.Context) []string {
		return []string{first, second}
	})
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := src.Add(context.Background(), agent.AddedKey{PrivateKey: sk}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if keys, _ := firstRing.List(); len(keys) != 1 {
		t.Errorf("first upstream holds %d keys, want 1", len(keys))
	}
	if keys, _ := secondRing.List(); len(keys) != 0 {
		t.Errorf("second upstream holds %d keys, want 0 — Add must not fan out", len(keys))
	}
}

// TestUpstreamFansOutAcrossEndpoints covers the auto-detect case where a user
// runs more than one agent: every one is listed, and a signature routes to
// whichever holds the key.
func TestUpstreamFansOutAcrossEndpoints(t *testing.T) {
	privA, pubA := genUpstreamKey(t)
	privB, pubB := genUpstreamKey(t)
	sockA := filepath.Join(t.TempDir(), "a.sock")
	sockB := filepath.Join(t.TempDir(), "b.sock")
	serveUpstreamAgentAt(t, sockA, privA)
	serveUpstreamAgentAt(t, sockB, privB)

	src := newUpstreamSourceFunc("agent", func(context.Context) []string {
		return []string{sockA, sockB}
	})
	ctx := context.Background()
	ids, err := src.Identities(ctx)
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("want 2 identities across the two agents, got %d", len(ids))
	}

	data := []byte("challenge")
	for _, pub := range []ssh.PublicKey{pubA, pubB} {
		sig, matched, err := src.Sign(ctx, pub, data, 0)
		if err != nil || !matched {
			t.Fatalf("Sign: matched=%v err=%v", matched, err)
		}
		if err := pub.Verify(data, sig); err != nil {
			t.Errorf("signature does not verify: %v", err)
		}
	}
}

// TestUpstreamDedupesSharedKey covers the common auto-detect overlap:
// $SSH_AUTH_SOCK usually points at an agent the scan also finds by its
// well-known path. Advertising the same key twice would waste an
// authentication attempt against a server's MaxAuthTries budget.
func TestUpstreamDedupesSharedKey(t *testing.T) {
	priv, _ := genUpstreamKey(t)
	sock := filepath.Join(t.TempDir(), "upstream.sock")
	serveUpstreamAgentAt(t, sock, priv)
	alias := filepath.Join(t.TempDir(), "alias.sock")
	if err := os.Symlink(sock, alias); err != nil {
		t.Fatal(err)
	}

	src := newUpstreamSourceFunc("agent", func(context.Context) []string {
		return []string{sock, alias}
	})
	ids, err := src.Identities(context.Background())
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if len(ids) != 1 {
		t.Errorf("want the shared key listed once, got %d identities", len(ids))
	}
}

// TestUpstreamListSurvivesOneDeadEndpoint is the auto-detect analogue of the
// backend's per-source isolation: the endpoint list is a best guess about what
// is running, so one stale socket in it must not blank the agents that
// answered.
func TestUpstreamListSurvivesOneDeadEndpoint(t *testing.T) {
	priv, pub := genUpstreamKey(t)
	live := filepath.Join(t.TempDir(), "live.sock")
	serveUpstreamAgentAt(t, live, priv)
	dead := filepath.Join(t.TempDir(), "dead.sock")

	src := newUpstreamSourceFunc("agent", func(context.Context) []string {
		return []string{dead, live}
	})
	ids, err := src.Identities(context.Background())
	if err != nil {
		t.Fatalf("Identities should tolerate a dead endpoint: %v", err)
	}
	if len(ids) != 1 || !keyEqual(ids[0].PubKey, pub) {
		t.Errorf("want the live agent's key, got %d identities", len(ids))
	}
}

// TestUpstreamNoEndpointsIsNotAnError covers a host where the user runs no
// other agent. "Nothing to shadow" is a legitimate answer, and reporting it as
// an error would leave the backend refusing to cache its listing — turning
// every `ssh-add -l` into a fresh Vault fan-out.
func TestUpstreamNoEndpointsIsNotAnError(t *testing.T) {
	src := newUpstreamSourceFunc("agent", func(context.Context) []string { return nil })
	ids, err := src.Identities(context.Background())
	if err != nil || len(ids) != 0 {
		t.Errorf("Identities = (%d ids, %v), want (0, nil)", len(ids), err)
	}
	if err := src.Add(context.Background(), agent.AddedKey{}); err == nil {
		t.Errorf("Add with no upstream should error")
	}
}
