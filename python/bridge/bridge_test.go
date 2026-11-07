//go:build cgo

package main

// This test file is deliberately cgo-free: a _test.go may not import "C". It
// exercises the pure-Go helpers (categoryOf, the handle table, syncEnv) through
// the cgo-free seams in bridge.go (lookupID/dropID, cSetenv/cUnsetenv).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/dotvault/client"
)

func TestCategoryOf(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, catOK},
		{"login required", fmt.Errorf("wrap: %w", client.ErrLoginRequired), catLoginRequired},
		{"denied", fmt.Errorf("wrap: %w", client.ErrDenied), catDenied},
		{"unreachable", fmt.Errorf("wrap: %w", client.ErrUnreachable), catUnreachable},
		{"auth failed", fmt.Errorf("wrap: %w", client.ErrAuthFailed), catAuthFailed},
		{"peer unavailable", fmt.Errorf("wrap: %w", client.ErrPeerUnavailable), catPeerUnavailable},
		{"not configured", fmt.Errorf("wrap: %w", client.ErrNotConfigured), catNotConfigured},
		// Transient and not a Vault verdict: the base DotvaultError in
		// Python, like ErrSignPaced.
		{"sign in progress", fmt.Errorf("wrap: %w", client.ErrSignInProgress), catOther},
		{"sign paced", fmt.Errorf("wrap: %w", client.ErrSignPaced), catOther},
		{"unknown", errors.New("something else"), catOther},
		{"unknown handle", errUnknownHandle, catOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := categoryOf(tt.err); got != tt.want {
				t.Fatalf("categoryOf(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func TestHandleTableLifecycle(t *testing.T) {
	// store issues a positive handle and lookupID resolves it.
	c := &client.Client{}
	h := store(c)
	if h <= 0 {
		t.Fatalf("store returned non-positive handle %d", h)
	}
	got, ok := lookupID(h)
	if !ok || got != c {
		t.Fatalf("lookupID(%d) = %v, %v; want the stored client", h, got, ok)
	}

	// A second store issues a distinct handle (monotonic, never reused).
	h2 := store(&client.Client{})
	if h2 == h {
		t.Fatalf("store reused handle %d", h)
	}

	// dropID removes only the named handle.
	dropID(h)
	if _, ok := lookupID(h); ok {
		t.Fatalf("lookupID(%d) still resolves after drop", h)
	}
	if _, ok := lookupID(h2); !ok {
		t.Fatalf("dropID(%d) also removed unrelated handle %d", h, h2)
	}

	// An unknown handle never resolves.
	if _, ok := lookupID(h2 + 1000); ok {
		t.Fatal("lookupID resolved a never-issued handle")
	}
}

func TestSyncEnvReadsLiveCEnvironment(t *testing.T) {
	// The Go runtime snapshots env at init; syncEnv must reflect a value set in
	// the live C environment afterwards. Manipulate the C environment (as the
	// host process would) and confirm syncEnv propagates it into Go.
	cSetenv("DOTVAULT_TOKEN", "s.synced-token")
	t.Cleanup(func() { cUnsetenv("DOTVAULT_TOKEN") })

	syncEnv()
	if got := os.Getenv("DOTVAULT_TOKEN"); got != "s.synced-token" {
		t.Fatalf("after syncEnv, os env = %q, want the C-set value", got)
	}

	// Unsetting in C must propagate as an unset in Go, not a stale value.
	cUnsetenv("DOTVAULT_TOKEN")
	syncEnv()
	if got, ok := os.LookupEnv("DOTVAULT_TOKEN"); ok {
		t.Fatalf("after unset+syncEnv, os env still set to %q", got)
	}
}

func TestClientCertificateNilOutputNeverSigns(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("DOTVAULT_TOKEN", "s.token")
	t.Setenv("VAULT_MAX_RETRIES", "0")
	c, err := client.New(&client.Config{
		Vault:      client.VaultConfig{Address: srv.URL, AuthMethod: "token"},
		TokenFile:  t.TempDir() + "/token",
		ClientCert: client.ClientCertConfig{Enabled: true, PKIRole: "tools", CommonName: "{{.os_user}}"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientCertificate(context.Background(), c, false); !errors.Is(err, errNilOutput) {
		t.Fatalf("err = %v, want errNilOutput", err)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("Vault saw %d requests for a call that could not receive the result", n)
	}
}

// TestWipeZeroesOutString proves the string dotvault_free releases is zeroed
// first. Out strings carry tokens, secret values and a private key, and freed
// malloc memory is not cleared, so without the wipe they would linger in the
// host process's heap until reused.
func TestWipeZeroesOutString(t *testing.T) {
	const secret = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49\n-----END PRIVATE KEY-----\n"
	got := wipedCString(secret)
	if len(got) != len(secret) {
		t.Fatalf("read back %d bytes, want %d", len(got), len(secret))
	}
	for i, b := range got {
		if b != 0 {
			t.Fatalf("byte %d = %#x after wipe, want 0", i, b)
		}
	}
}

func TestEventJSONShape(t *testing.T) {
	js, err := eventJSON(client.Event{Key: "gh", Version: 7, Source: "refresh", Time: time.Date(2026, 11, 7, 1, 2, 3, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"key":"gh","version":7,"source":"refresh","time":"2026-11-07T01:02:03Z"}`
	if js != want {
		t.Fatalf("eventJSON = %s, want %s", js, want)
	}
	js, _ = eventJSON(client.Event{Key: "gh", Version: 1})
	if js != `{"key":"gh","version":1,"source":"","time":""}` {
		t.Fatalf("zero time not rendered empty: %s", js)
	}
}

func TestSubscriptionHandlesAreNeverReused(t *testing.T) {
	a := storeSub(nil)
	if _, ok := takeSubID(a); !ok {
		t.Fatal("stored subscription not found")
	}
	if _, ok := lookupSubID(a); ok {
		t.Fatal("taken subscription still resolves")
	}
	if b := storeSub(nil); b == a {
		t.Fatal("subscription handle reused")
	}
}

func TestSubscriptionClosedHasItsOwnCategory(t *testing.T) {
	if got := categoryOf(fmt.Errorf("wrapped: %w", client.ErrSubscriptionClosed)); got != catClosed {
		t.Fatalf("categoryOf(ErrSubscriptionClosed) = %d, want catClosed (%d)", got, catClosed)
	}
}

func TestUnknownSubscriptionReadsAsClosed(t *testing.T) {
	// close frees the handle, so a next racing it on another thread finds the
	// handle gone; that must reach Python as SubscriptionClosed, not an error.
	if got := categoryOf(errUnknownSubscription); got != catClosed {
		t.Fatalf("categoryOf(errUnknownSubscription) = %d, want catClosed (%d)", got, catClosed)
	}
}
