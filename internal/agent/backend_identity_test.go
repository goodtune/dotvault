package agent

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestBackendListAllSourcesFailingReportsError pins the difference between
// "every credential source erred" and "nothing is configured".
//
// List used to answer both with (nil, nil). A consumer cannot act on that: the
// SSH forwarder, seeing zero identities, fails the dial before touching the
// network and reports an authentication failure — indistinguishable from an
// unauthorised principal, and carrying the same five-minute backoff floor. The
// usual cause is the opposite of permanent: a vault-ca mint landing inside a
// few-hundred-millisecond token-replacement window.
func TestBackendListAllSourcesFailingReportsError(t *testing.T) {
	bad := &fakeSource{name: "ca", idErr: errors.New("mint certificate: permission denied")}
	b := NewBackend([]Source{bad})

	keys, err := b.List()
	if err == nil {
		t.Fatalf("List: want an error when every source failed, got %d keys and nil", len(keys))
	}
	if keys != nil {
		t.Errorf("List: want nil keys alongside the error, got %d", len(keys))
	}
	// The failing source is named so an operator reading the forward's
	// last_error can tell which credential origin is unhappy.
	if !strings.Contains(err.Error(), "ca") {
		t.Errorf("List error %q does not name the failing source", err)
	}
}

// TestBackendListNoSourcesIsNotAnError keeps the other half honest: a backend
// with nothing to offer and nothing broken still reports success with an empty
// list, which is what `ssh-add -l` against a genuinely keyless agent means.
func TestBackendListNoSourcesIsNotAnError(t *testing.T) {
	b := NewBackend(nil)
	keys, err := b.List()
	if err != nil {
		t.Fatalf("List: want nil error for a backend with no sources, got %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("List: want 0 keys, got %d", len(keys))
	}
}

// TestBackendListDoesNotCachePartialResults pins that a listing assembled while
// a source was failing is not held for the cache TTL.
//
// Caching it would outlast the cause by an order of magnitude: the token
// replacement clears in a few hundred milliseconds, the cache window is eight
// seconds. A client retrying inside that window would keep being told the
// erroring source has no keys, long after it had recovered.
func TestBackendListDoesNotCachePartialResults(t *testing.T) {
	_, _, pubA, _ := genEd25519(t, "a")
	good := &fakeSource{name: "kv", ids: []Identity{{PubKey: pubA, Comment: "a"}}}
	bad := &fakeSource{name: "ca", idErr: errors.New("transient")}
	b := NewBackend([]Source{good, bad}, WithCacheTTL(time.Minute))

	keys, err := b.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("List: want the healthy source's 1 key, got %d", len(keys))
	}

	// The source recovers; the very next List must see it rather than a cached
	// listing taken while it was down.
	bad.idErr = nil
	_, _, pubB, _ := genEd25519(t, "b")
	bad.ids = []Identity{{PubKey: pubB, Comment: "b"}}

	keys, err = b.List()
	if err != nil {
		t.Fatalf("List 2: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("List 2: want 2 keys once the failing source recovered, got %d "+
			"(a partial listing was cached)", len(keys))
	}
}

// TestBackendListWaitsForReauth pins that List, like Sign, waits out a token
// replacement instead of answering from a client mid-swap.
//
// This is the half that turns the lifecycle fix into a working forward: an SSH
// client asks the agent what it has before choosing a key, so a List answered
// during the window is where the connection is actually lost. Waiting converts
// a dropped forward into a pause of a few hundred milliseconds.
func TestBackendListWaitsForReauth(t *testing.T) {
	_, _, pubA, _ := genEd25519(t, "a")
	src := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}}
	gate := &stubGate{}
	gate.reauth.Store(true)
	b := NewBackend([]Source{src}, WithReauthGate(gate), WithReauthTimeout(2*time.Second))

	go func() {
		time.Sleep(150 * time.Millisecond)
		gate.reauth.Store(false)
	}()

	start := time.Now()
	keys, err := b.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Error("List returned immediately; it must wait out a token replacement")
	}
	if len(keys) != 1 {
		t.Fatalf("List: want 1 key, got %d", len(keys))
	}
}

// TestBackendListReauthTimeout bounds that wait: a replacement that never
// completes must surface as an error rather than hanging the client forever.
func TestBackendListReauthTimeout(t *testing.T) {
	_, _, pubA, _ := genEd25519(t, "a")
	src := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}}
	gate := &stubGate{}
	gate.reauth.Store(true) // never clears
	b := NewBackend([]Source{src}, WithReauthGate(gate), WithReauthTimeout(200*time.Millisecond))

	if _, err := b.List(); err == nil {
		t.Fatal("List: want a timeout error while re-auth never clears, got nil")
	}
}

// TestBackendListConcurrent exercises List under -race now that it takes the
// gate path and mutates the cache conditionally.
func TestBackendListConcurrent(t *testing.T) {
	_, _, pubA, _ := genEd25519(t, "a")
	src := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}}
	b := NewBackend([]Source{src}, WithCacheTTL(time.Millisecond))

	var failures atomic.Int64
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 25; j++ {
				keys, err := b.List()
				if err != nil || len(keys) != 1 {
					failures.Add(1)
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if n := failures.Load(); n != 0 {
		t.Errorf("%d concurrent List calls did not return the single identity", n)
	}
}

// TestBackendListServesFreshCacheWithoutWaitingForReauth pins the ordering
// between the two fixes this change sits between.
//
// The re-auth gate exists so a listing is not rebuilt from a half-replaced
// token. A cache still inside its TTL is not rebuilt from anything — it needs
// no Vault call — so making it wait buys nothing and costs the very thing the
// pre-auth work exists to protect: an ssh client reads the identity list
// before it picks a key, so a List that stalls loses the connection just as
// surely as one that comes back blank. Web mode clears the in-memory token on
// the re-auth transition, which is exactly when both conditions hold at once.
func TestBackendListServesFreshCacheWithoutWaitingForReauth(t *testing.T) {
	_, _, pubA, _ := genEd25519(t, "a")
	src := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}}
	gate := &stubGate{}
	// A deliberately short re-auth budget: the point of the test is the
	// elapsed-time assertion below, and with the production 30s budget a
	// regression fails on the returned error after a 30s stall instead,
	// leaving the timing check dead.
	b := NewBackend([]Source{src}, WithReauthGate(gate),
		WithCacheTTL(time.Minute), WithReauthTimeout(time.Second))

	// Populate the cache while healthy.
	if _, err := b.List(); err != nil {
		t.Fatalf("List: %v", err)
	}

	// A replacement starts and never finishes within this test. The cached
	// answer is still valid and must come back immediately.
	gate.reauth.Store(true)

	start := time.Now()
	keys, err := b.List()
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("List during re-auth: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("want the cached identity served through a re-auth, got %d", len(keys))
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("List took %s to serve a cached answer; it waited on the "+
			"re-auth gate before checking the cache", elapsed)
	}
	if src.listCalls != 1 {
		t.Errorf("cached answer must not re-consult sources, got %d calls", src.listCalls)
	}
}

// TestBackendCacheHitDoesNotQueueBehindSlowRefresh pins that the cache fast
// path is not merely ordered before the gate but genuinely unblocked.
//
// Holding one mutex across the source fan-out made "answered first" mean
// "answered first once the refresh finishes" — up to the full source timeout,
// which is the same stall arrived at by a different route. A cache read and a
// Vault round trip contend for nothing, so they must not share a lock.
//
// The cache is aged and un-aged through the injected clock rather than by
// writing b.cached directly: touching the fields would need b.mu, which is the
// very lock under test, so a regression would deadlock the test instead of
// failing it. The measured List runs in its own goroutine for the same reason
// — a blocked fast path has to be observable as elapsed time, not as a hang.
func TestBackendCacheHitDoesNotQueueBehindSlowRefresh(t *testing.T) {
	_, _, pubA, _ := genEd25519(t, "a")
	release := make(chan struct{})
	slow := &blockingSource{
		fakeSource: fakeSource{name: "slow", ids: []Identity{{PubKey: pubA}}},
		block:      release,
	}

	base := time.Now()
	var offset atomic.Int64 // nanoseconds added to base
	b := NewBackend([]Source{slow}, WithCacheTTL(time.Minute),
		withClock(func() time.Time { return base.Add(time.Duration(offset.Load())) }))

	// Populate the cache at the base instant.
	if _, err := b.List(); err != nil {
		t.Fatalf("List: %v", err)
	}

	// Age it past the TTL so the next caller must refresh, and park that
	// refresh inside the source.
	offset.Store(int64(2 * time.Minute))
	slow.arm()
	refreshDone := make(chan struct{})
	go func() {
		defer close(refreshDone)
		_, _ = b.List()
	}()
	slow.waitEntered(t)

	// With a refresh in flight and parked, wind the clock back so the existing
	// cache entry is inside its window again. A concurrent caller now has a
	// valid answer available and must get it without waiting for the refresh.
	offset.Store(0)

	measured := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		if _, err := b.List(); err != nil {
			t.Errorf("List during refresh: %v", err)
		}
		measured <- time.Since(start)
	}()

	select {
	case d := <-measured:
		if d > 500*time.Millisecond {
			t.Errorf("cache hit took %s while a refresh was in flight; the "+
				"fast path is sharing a lock with the source fan-out", d)
		}
	case <-time.After(2 * time.Second):
		t.Error("cache hit blocked behind an in-flight refresh; the fast path " +
			"is sharing a lock with the source fan-out")
	}

	close(release)
	<-refreshDone
}

// blockingSource parks inside Identities until released, so a test can hold a
// refresh open and observe what other callers can do meanwhile.
type blockingSource struct {
	fakeSource
	block   chan struct{}
	armed   atomic.Bool
	entered chan struct{}
	once    sync.Once
}

func (s *blockingSource) arm() {
	s.entered = make(chan struct{})
	s.armed.Store(true)
}

func (s *blockingSource) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-s.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh never reached the source")
	}
}

func (s *blockingSource) Identities(ctx context.Context) ([]Identity, error) {
	if s.armed.Load() {
		s.once.Do(func() { close(s.entered) })
		<-s.block
	}
	return s.fakeSource.Identities(ctx)
}

// TestBackendListWaitsOutReauthWhenTokenCleared pins the case where the two
// rules this change reconciles actually meet.
//
// Web mode clears the in-memory token on the re-auth transition, so during a
// replacement the token is absent *and* a gate is up. With a cold cache there
// is nothing to serve, and answering empty there would be the blank
// `ssh-add -l` that makes ssh drop dotvault's keys — the very failure the
// pre-auth work exists to prevent, reached by a different route. An absent
// token under a raised gate is transient, so List waits for it.
func TestBackendListWaitsOutReauthWhenTokenCleared(t *testing.T) {
	_, _, pubA, _ := genEd25519(t, "a")
	src := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}}

	var hasToken atomic.Bool
	gate := &stubGate{}
	gate.reauth.Store(true) // replacement under way, token cleared
	b := NewBackend([]Source{src}, WithTokenProbe(hasToken.Load),
		WithReauthGate(gate), WithReauthTimeout(5*time.Second))

	go func() {
		time.Sleep(150 * time.Millisecond)
		hasToken.Store(true) // replacement lands
		gate.reauth.Store(false)
	}()

	keys, err := b.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("want the identity that became available once the replacement "+
			"landed, got %d — List answered empty instead of waiting", len(keys))
	}
}

// TestBackendListAndSignDifferWithoutToken pins the asymmetry gatedContext's
// wait parameter exists for, which is otherwise invisible: every other path
// into it already holds a token, so swapping the two waits changes nothing a
// test would notice.
//
// An unauthenticated daemon owes List an empty list — an ssh client reads that
// and moves straight on to its next authentication method — and owes Sign a
// refusal, because a signature it cannot produce must not look like a key it
// does not have. No gate is raised here: nothing is coming, so neither call
// waits.
func TestBackendListAndSignDifferWithoutToken(t *testing.T) {
	_, _, pubA, signerA := genEd25519(t, "a")
	src := &fakeSource{name: "a", ids: []Identity{{PubKey: pubA}}, signer: signerA}

	var hasToken atomic.Bool // stays false
	b := NewBackend([]Source{src}, WithTokenProbe(hasToken.Load),
		WithReauthGate(&stubGate{}), WithReauthTimeout(5*time.Second))

	keys, err := b.List()
	if err != nil {
		t.Fatalf("List without a token: want an empty list, got error %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("List without a token: want 0 keys, got %d", len(keys))
	}

	if _, err := b.Sign(pubA, []byte("x")); !errors.Is(err, ErrNoToken) {
		t.Errorf("Sign without a token: want ErrNoToken, got %v", err)
	}
}
