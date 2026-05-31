package agent

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestBackendReadOnly(t *testing.T) {
	b := NewBackend(nil)
	if err := b.Add(agent.AddedKey{}); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Add: want ErrReadOnly, got %v", err)
	}
	if err := b.Remove(nil); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Remove: want ErrReadOnly, got %v", err)
	}
	if err := b.RemoveAll(); !errors.Is(err, ErrReadOnly) {
		t.Errorf("RemoveAll: want ErrReadOnly, got %v", err)
	}
	if err := b.Lock(nil); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Lock: want ErrReadOnly, got %v", err)
	}
	if err := b.Unlock(nil); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Unlock: want ErrReadOnly, got %v", err)
	}
	if _, err := b.Signers(); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Signers: want ErrReadOnly, got %v", err)
	}
	if _, err := b.Extension("x", nil); !errors.Is(err, agent.ErrExtensionUnsupported) {
		t.Errorf("Extension: want ErrExtensionUnsupported, got %v", err)
	}
}

func TestBackendListAggregatesAndCaches(t *testing.T) {
	_, _, pubA, _ := genEd25519(t, "a")
	_, _, pubB, _ := genEd25519(t, "b")
	srcA := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA, Comment: "a"}}}
	srcB := &fakeSource{name: "b", ids: []Identity{{PubKey: pubB, Comment: "b"}}}

	b := NewBackend([]Source{srcA, srcB}, WithCacheTTL(time.Minute))
	keys, err := b.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("List: want 2 keys, got %d", len(keys))
	}
	// Second List within the TTL must not re-query the sources.
	if _, err := b.List(); err != nil {
		t.Fatalf("List 2: %v", err)
	}
	if srcA.listCalls != 1 || srcB.listCalls != 1 {
		t.Errorf("cache miss: listCalls a=%d b=%d, want 1/1", srcA.listCalls, srcB.listCalls)
	}
}

func TestBackendListSkipsErroringSource(t *testing.T) {
	_, _, pubA, _ := genEd25519(t, "a")
	good := &fakeSource{name: "good", ids: []Identity{{PubKey: pubA, Comment: "a"}}}
	bad := &fakeSource{name: "bad", idErr: errors.New("boom")}
	b := NewBackend([]Source{bad, good})
	keys, err := b.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("want 1 key (erroring source skipped), got %d", len(keys))
	}
}

func TestBackendSignRoutesToOwningSource(t *testing.T) {
	_, _, pubA, signerA := genEd25519(t, "a")
	_, _, pubB, signerB := genEd25519(t, "b")
	srcA := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}, signer: signerA}
	srcB := &fakeSource{name: "b", ids: []Identity{{PubKey: pubB}}, signer: signerB}
	b := NewBackend([]Source{srcA, srcB})

	data := []byte("challenge")
	sig, err := b.Sign(pubB, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := pubB.Verify(data, sig); err != nil {
		t.Errorf("signature does not verify against pubB: %v", err)
	}
}

func TestBackendSignUnknownKey(t *testing.T) {
	_, _, pubA, signerA := genEd25519(t, "a")
	_, _, pubOther, _ := genEd25519(t, "other")
	srcA := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}, signer: signerA}
	b := NewBackend([]Source{srcA})
	if _, err := b.Sign(pubOther, []byte("x")); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("want ErrKeyNotFound, got %v", err)
	}
}

// stubGate is a controllable ReauthGate.
type stubGate struct{ reauth atomic.Bool }

func (g *stubGate) NeedsReauth() bool { return g.reauth.Load() }

func TestBackendSignWaitsForReauthThenSucceeds(t *testing.T) {
	_, _, pubA, signerA := genEd25519(t, "a")
	srcA := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}, signer: signerA}
	gate := &stubGate{}
	gate.reauth.Store(true)
	b := NewBackend([]Source{srcA}, WithReauthGate(gate), WithReauthTimeout(2*time.Second))

	// Clear the reauth flag shortly after Sign starts waiting.
	go func() {
		time.Sleep(150 * time.Millisecond)
		gate.reauth.Store(false)
	}()

	start := time.Now()
	if _, err := b.Sign(pubA, []byte("x")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Errorf("Sign returned too fast; expected to wait for reauth")
	}
}

func TestBackendSignReauthTimeout(t *testing.T) {
	_, _, pubA, signerA := genEd25519(t, "a")
	srcA := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}, signer: signerA}
	gate := &stubGate{}
	gate.reauth.Store(true) // never clears
	b := NewBackend([]Source{srcA}, WithReauthGate(gate), WithReauthTimeout(200*time.Millisecond))
	if _, err := b.Sign(pubA, []byte("x")); err == nil {
		t.Fatalf("Sign: want timeout error, got nil")
	}
}

func TestBackendSignConcurrent(t *testing.T) {
	_, _, pubA, signerA := genEd25519(t, "a")
	srcA := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}, signer: signerA}
	b := NewBackend([]Source{srcA})

	var wg sync.WaitGroup
	data := []byte("challenge")
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sig, err := b.Sign(pubA, data)
			if err != nil {
				t.Errorf("Sign: %v", err)
				return
			}
			if err := pubA.Verify(data, sig); err != nil {
				t.Errorf("verify: %v", err)
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := b.List(); err != nil {
				t.Errorf("List: %v", err)
			}
		}()
	}
	wg.Wait()
}

// TestBackendSetReauthGateRace exercises the exact race the atomic gate guards:
// the daemon calling SetReauthGate after construction while clients are already
// issuing Sign calls. Run under -race, an unsynchronised gate field trips the
// detector here.
func TestBackendSetReauthGateRace(t *testing.T) {
	_, _, pubA, signerA := genEd25519(t, "a")
	srcA := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}, signer: signerA}
	b := NewBackend([]Source{srcA})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.SetReauthGate(&stubGate{}) // each store is a distinct gate value
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = b.Sign(pubA, []byte("x"))
		}()
	}
	wg.Wait()
}

// ensure *Backend satisfies the x/crypto ExtendedAgent interface.
var _ agent.ExtendedAgent = (*Backend)(nil)

// ensure the Status helper is callable on a typed certificate identity.
func TestIdentityStatusCert(t *testing.T) {
	expiry := time.Now().Add(15 * time.Minute)
	cert := &ssh.Certificate{}
	_ = cert
	is := identityStatus(Identity{PubKey: mustTestPub(t), Comment: "c", Expiry: expiry})
	if is.ExpiresAt == "" || is.TTLSeconds <= 0 {
		t.Errorf("expected expiry/ttl populated, got %+v", is)
	}
}

func mustTestPub(t *testing.T) ssh.PublicKey {
	_, _, pub, _ := genEd25519(t, "x")
	return pub
}
