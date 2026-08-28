package agent

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
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
				var keys []*agent.Key
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
