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

// TestBackendSignSkipsErroringSourceAndFindsMatch reproduces the reported bug:
// a source that can't currently produce a signature (e.g. a vault-ca source
// whose role can't mint) must not block a Sign for a key owned by a
// different, healthy source — mirroring the List-skip behaviour. Ordering the
// broken source first is the exact failure mode from the bug report.
func TestBackendSignSkipsErroringSourceAndFindsMatch(t *testing.T) {
	_, _, pubGood, signerGood := genEd25519(t, "good")
	broken := &fakeSource{name: "broken", signErr: errors.New("role can't mint")}
	good := &fakeSource{name: "good", ids: []Identity{{PubKey: pubGood}}, signer: signerGood}
	b := NewBackend([]Source{broken, good})

	data := []byte("challenge")
	sig, err := b.Sign(pubGood, data)
	if err != nil {
		t.Fatalf("Sign: want success routing around the broken source, got %v", err)
	}
	if err := pubGood.Verify(data, sig); err != nil {
		t.Errorf("signature does not verify against pubGood: %v", err)
	}
}

// TestBackendSignSkipsErroringSourceRegardlessOfOrder pins that the fix does
// not depend on the broken source coming first — the loop tries every source
// unconditionally and only returns early on a match, so a broken source
// listed after the owning source must not matter either.
func TestBackendSignSkipsErroringSourceRegardlessOfOrder(t *testing.T) {
	_, _, pubGood, signerGood := genEd25519(t, "good")
	good := &fakeSource{name: "good", ids: []Identity{{PubKey: pubGood}}, signer: signerGood}
	broken := &fakeSource{name: "broken", signErr: errors.New("role can't mint")}
	b := NewBackend([]Source{good, broken})

	data := []byte("challenge")
	sig, err := b.Sign(pubGood, data)
	if err != nil {
		t.Fatalf("Sign: want success, got %v", err)
	}
	if err := pubGood.Verify(data, sig); err != nil {
		t.Errorf("signature does not verify against pubGood: %v", err)
	}
}

// TestBackendSignAllSourcesErrorReportsCombinedError ensures that when no
// source can produce a signature, the accumulated per-source errors surface
// instead of being swallowed as a generic ErrKeyNotFound.
func TestBackendSignAllSourcesErrorReportsCombinedError(t *testing.T) {
	brokenErr := errors.New("role can't mint")
	broken := &fakeSource{name: "broken", signErr: brokenErr}
	b := NewBackend([]Source{broken})

	_, err := b.Sign(mustTestPub(t), []byte("x"))
	if err == nil {
		t.Fatal("Sign: want error, got nil")
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Errorf("want the underlying source error surfaced, got ErrKeyNotFound: %v", err)
	}
	if !errors.Is(err, brokenErr) {
		t.Errorf("want error to wrap the source's error, got %v", err)
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

// TestBackendWithoutTokenAnswersEmptyImmediately covers the pre-authentication
// window the listener now serves in. An agent that answers "no identities"
// straight away is one an ssh client moves past; the point of the probe is
// that it does so without a round of Vault calls that could not succeed, since
// a slow reply would stall the client just as an unaccepted connection does.
func TestBackendWithoutTokenAnswersEmptyImmediately(t *testing.T) {
	_, _, pubA, signerA := genEd25519(t, "a")
	srcA := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}, signer: signerA}

	var hasToken atomic.Bool
	b := NewBackend([]Source{srcA}, WithTokenProbe(hasToken.Load))

	keys, err := b.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("want no identities before authentication, got %d", len(keys))
	}
	if srcA.listCalls != 0 {
		t.Errorf("sources must not be consulted without a token; got %d calls", srcA.listCalls)
	}

	// A token arriving must not be masked by the empty answer having been
	// cached — the next List has to do a real refresh.
	hasToken.Store(true)
	keys, err = b.List()
	if err != nil {
		t.Fatalf("List after token: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("want 1 identity once authenticated, got %d", len(keys))
	}
	if srcA.listCalls != 1 {
		t.Errorf("want exactly one source refresh once authenticated, got %d", srcA.listCalls)
	}
}

// TestBackendKeepsCacheWhenTokenLostMidLife pins the ordering inside
// identities(): the token check must sit AFTER the cache check. Web mode
// clears the in-memory token on the re-auth transition, so a token going
// missing is routinely a refresh rather than a logout. Blanking the list there
// makes `ssh-add -l` return nothing and ssh drop dotvault's keys instead of
// reaching Sign, which is the call that knows how to wait the re-auth out.
func TestBackendKeepsCacheWhenTokenLostMidLife(t *testing.T) {
	_, _, pubA, signerA := genEd25519(t, "a")
	srcA := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}, signer: signerA}

	var hasToken atomic.Bool
	hasToken.Store(true)
	b := NewBackend([]Source{srcA}, WithTokenProbe(hasToken.Load))

	keys, err := b.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("want 1 identity while authenticated, got %d", len(keys))
	}

	// Token cleared, as web.Server.ForceReauth does. The cache is still
	// inside its TTL, so it must keep being served.
	hasToken.Store(false)
	keys, err = b.List()
	if err != nil {
		t.Fatalf("List after token loss: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("want the cached identity served through a re-auth, got %d", len(keys))
	}
	if srcA.listCalls != 1 {
		t.Errorf("cached answer must not re-consult sources, got %d calls", srcA.listCalls)
	}
}

// TestBackendExpiredCacheWithoutTokenAnswersEmpty is the other half: once the
// cache has aged out there is nothing valid to serve and no token to refresh
// with, so the answer is empty — and still without a doomed round of Vault
// calls.
func TestBackendExpiredCacheWithoutTokenAnswersEmpty(t *testing.T) {
	_, _, pubA, signerA := genEd25519(t, "a")
	srcA := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}, signer: signerA}

	var hasToken atomic.Bool
	hasToken.Store(true)
	now := time.Now()
	b := NewBackend([]Source{srcA},
		WithTokenProbe(hasToken.Load),
		WithCacheTTL(time.Second),
		withClock(func() time.Time { return now }),
	)

	if keys, err := b.List(); err != nil || len(keys) != 1 {
		t.Fatalf("List: keys=%d err=%v", len(keys), err)
	}

	hasToken.Store(false)
	now = now.Add(10 * time.Second) // age the cache out

	keys, err := b.List()
	if err != nil {
		t.Fatalf("List after cache expiry: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("want empty once the cache expired without a token, got %d", len(keys))
	}
	if srcA.listCalls != 1 {
		t.Errorf("sources must not be consulted without a token, got %d calls", srcA.listCalls)
	}
}

// TestBackendSignWithoutTokenFailsFast pins the other half: a Sign arriving
// before the daemon has authenticated must be refused immediately, not held
// for the re-auth timeout. There is no re-auth underway to wait out — the
// daemon has simply never logged in — and a 30s stall per signature would
// reintroduce the block this path exists to avoid.
func TestBackendSignWithoutTokenFailsFast(t *testing.T) {
	_, _, pubA, signerA := genEd25519(t, "a")
	srcA := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}, signer: signerA}
	b := NewBackend([]Source{srcA},
		WithTokenProbe(func() bool { return false }),
		WithReauthTimeout(10*time.Second),
	)

	start := time.Now()
	_, err := b.Sign(pubA, []byte("x"))
	if err == nil {
		t.Fatal("Sign: want a refusal without a token, got nil")
	}
	if !errors.Is(err, ErrNoToken) {
		t.Errorf("want ErrNoToken, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Sign waited %s without a token; it must fail fast", elapsed)
	}
}

// TestBackendSignWaitsThroughReauthWithoutToken keeps the two conditions
// distinct: a re-auth in progress is transient and still waits, so a token
// landing during the window produces a signature rather than a refusal.
func TestBackendSignWaitsThroughReauthWithoutToken(t *testing.T) {
	_, _, pubA, signerA := genEd25519(t, "a")
	srcA := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}, signer: signerA}

	gate := &stubGate{}
	gate.reauth.Store(true)
	var hasToken atomic.Bool // token cleared during reauth, as web mode does
	b := NewBackend([]Source{srcA},
		WithReauthGate(gate),
		WithTokenProbe(hasToken.Load),
		WithReauthTimeout(2*time.Second),
	)

	go func() {
		time.Sleep(150 * time.Millisecond)
		hasToken.Store(true)
		gate.reauth.Store(false)
	}()

	start := time.Now()
	if _, err := b.Sign(pubA, []byte("x")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Without the elapsed check this passes even if Sign never waited.
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("Sign returned in %s; it must have waited out the re-auth", elapsed)
	}
}
