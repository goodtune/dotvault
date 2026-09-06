package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// forbiddenErr builds the error shape a Vault 403 produces, which is what
// vault.IsForbidden classifies.
func forbiddenErr() error {
	return &vaultapi.ResponseError{StatusCode: http.StatusForbidden, Errors: []string{"permission denied"}}
}

func TestTokenDenylist_DenyAndDenied(t *testing.T) {
	ctx := context.Background()
	d := NewTokenDenylist()

	if d.Denied(ctx, "tok") {
		t.Fatal("Denied() = true for a token never denied")
	}
	if !d.Deny("tok") {
		t.Error("Deny() = false on first denial, want true (callers log once per episode)")
	}
	if d.Deny("tok") {
		t.Error("Deny() = true while already suppressed, want false")
	}
	if !d.Denied(ctx, "tok") {
		t.Error("Denied() = false after Deny()")
	}
	// A different token must be unaffected: this is what lets a rewritten
	// token file be picked up on a platform with no inotify, where nothing
	// clears the cache and only the value differs.
	if d.Denied(ctx, "another") {
		t.Error("Denied() = true for a different token; suppression must be per-token")
	}
}

func TestTokenDenylist_EmptyTokenNeverSuppressed(t *testing.T) {
	ctx := context.Background()
	d := NewTokenDenylist()

	if d.Deny("") {
		t.Error("Deny(\"\") = true; the empty token is not a credential")
	}
	if d.Denied(ctx, "") {
		t.Error("Denied(\"\") = true; \"no token\" is the caller's own state, not a denial")
	}
	if d.Len() != 0 {
		t.Errorf("Len() = %d after denying the empty token, want 0", d.Len())
	}
}

func TestTokenDenylist_NilReceiverIsInert(t *testing.T) {
	ctx := context.Background()
	var d *TokenDenylist

	// Every method must tolerate a nil receiver so call sites with no cache
	// wired (tests, one-shot commands) need no branch.
	if d.Denied(ctx, "tok") {
		t.Error("Denied() = true on a nil denylist")
	}
	if d.Deny("tok") {
		t.Error("Deny() = true on a nil denylist")
	}
	d.NoteRejection(ctx, "tok", forbiddenErr())
	if n := d.Clear(ctx); n != 0 {
		t.Errorf("Clear() = %d on a nil denylist, want 0", n)
	}
	if d.Len() != 0 {
		t.Errorf("Len() = %d on a nil denylist, want 0", d.Len())
	}
}

func TestTokenDenylist_SuppressionLapses(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	d := &TokenDenylist{
		denied:   make(map[string]time.Time),
		interval: 15 * time.Minute,
		now:      func() time.Time { return now },
	}

	d.Deny("tok")
	now = now.Add(14 * time.Minute)
	if !d.Denied(ctx, "tok") {
		t.Error("Denied() = false inside the re-probe window")
	}
	now = now.Add(2 * time.Minute)
	if d.Denied(ctx, "tok") {
		t.Error("Denied() = true past the re-probe window; a server-side fix must eventually be retried")
	}
	if d.Len() != 0 {
		t.Errorf("Len() = %d after a lapsed entry was read, want 0 (lapsed entries drop lazily)", d.Len())
	}
}

func TestTokenDenylist_Clear(t *testing.T) {
	ctx := context.Background()
	d := NewTokenDenylist()
	d.Deny("a")
	d.Deny("b")

	if n := d.Clear(ctx); n != 2 {
		t.Errorf("Clear() = %d, want 2", n)
	}
	if d.Denied(ctx, "a") || d.Denied(ctx, "b") {
		t.Error("token still suppressed after Clear()")
	}
	if n := d.Clear(ctx); n != 0 {
		t.Errorf("Clear() on an empty denylist = %d, want 0", n)
	}
}

func TestTokenDenylist_BoundedSize(t *testing.T) {
	d := NewTokenDenylist()
	for i := 0; i < maxDeniedTokens*3; i++ {
		d.Deny(fmt.Sprintf("token-%d", i))
	}
	if got := d.Len(); got > maxDeniedTokens {
		t.Errorf("Len() = %d, want <= %d; the cache must not grow without bound", got, maxDeniedTokens)
	}
}

func TestTokenDenylist_NoteRejectionOnlyForRejections(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"403 forbidden", forbiddenErr(), true},
		{"expired sentinel", errTokenExpired, true},
		{"500 server error", &vaultapi.ResponseError{StatusCode: http.StatusInternalServerError}, false},
		{"503 sealed", &vaultapi.ResponseError{StatusCode: http.StatusServiceUnavailable}, false},
		{"transport failure", errors.New("dial tcp: connection refused"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := NewTokenDenylist()
			d.NoteRejection(ctx, "tok", tc.err)
			if got := d.Denied(ctx, "tok"); got != tc.want {
				t.Errorf("Denied() = %v after NoteRejection(%v), want %v — a transient fault must leave the token retryable", got, tc.err, tc.want)
			}
			if got := IsTokenRejected(tc.err); got != tc.want {
				t.Errorf("IsTokenRejected(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsDenied(t *testing.T) {
	if !IsDenied(errTokenDenied) {
		t.Error("IsDenied(errTokenDenied) = false")
	}
	// The cached verdict and a live one are different facts; conflating them
	// would make the Start loop unable to tell "we asked" from "we didn't".
	if IsDenied(errTokenExpired) || IsDenied(forbiddenErr()) {
		t.Error("IsDenied() matched a live Vault error")
	}
	if IsExpired(errTokenDenied) {
		t.Error("IsExpired() matched the suppressed-token sentinel")
	}
}

func TestTokenDenylist_KeysAreHashed(t *testing.T) {
	// The cache is a suppression structure, never a token store: nothing it
	// holds should be a usable credential.
	d := NewTokenDenylist()
	d.Deny("hvs.super-secret-token")
	d.mu.Lock()
	defer d.mu.Unlock()
	for k := range d.denied {
		if k == "hvs.super-secret-token" {
			t.Fatal("denylist stored the raw token as its key")
		}
		if len(k) != 64 {
			t.Errorf("denylist key %q is not a hex sha256 digest", k)
		}
	}
}

// TestTokenDenylist_EvictsClosestToReprobe pins the eviction choice the bound
// documents. Entries are given distinct deadlines through the injected clock —
// without that they share a near-identical expiry and any eviction order looks
// correct, which is why an entry-count assertion alone does not cover this.
func TestTokenDenylist_EvictsClosestToReprobe(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	d := &TokenDenylist{
		denied:   make(map[string]time.Time),
		interval: time.Hour,
		now:      func() time.Time { return now },
	}

	// "oldest" is denied first and so re-probes soonest; fill the rest of the
	// cache a minute apart.
	d.Deny("oldest")
	for i := 1; i < maxDeniedTokens; i++ {
		now = now.Add(time.Minute)
		d.Deny(fmt.Sprintf("token-%d", i))
	}
	if d.Len() != maxDeniedTokens {
		t.Fatalf("precondition: Len() = %d, want %d", d.Len(), maxDeniedTokens)
	}

	// One more entry must displace the one whose suppression was worth least.
	now = now.Add(time.Minute)
	d.Deny("newcomer")

	if d.Denied(ctx, "oldest") {
		t.Error("evicted entry should have been the one closest to re-probing, but \"oldest\" is still suppressed")
	}
	if !d.Denied(ctx, "newcomer") {
		t.Error("newly denied token was not retained")
	}
	if !d.Denied(ctx, "token-1") {
		t.Error("a newer entry was evicted ahead of the oldest one")
	}
	if got := d.Len(); got > maxDeniedTokens {
		t.Errorf("Len() = %d, want <= %d", got, maxDeniedTokens)
	}
}
