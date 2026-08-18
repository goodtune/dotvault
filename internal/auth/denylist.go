package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/observability"
	"github.com/goodtune/dotvault/internal/vault"
)

// DenyProbeInterval is how long a token stays suppressed after Vault rejected
// it, before one lookup is allowed through again.
//
// A strict never-retry cache would be the obvious reading of "blacklist the
// token", and for the case that motivates this — an expired or revoked token
// sitting in ~/.dotvault-token — it is also the correct one: that token is
// permanently dead and no amount of re-asking changes the answer. But a 403 on
// lookup-self is not exclusively "the token is dead": a token whose policy set
// omits auth/token/lookup-self answers identically (see the least-privilege
// policy notes in the config reference), and so does a token presented while
// Vault is mid-failover or misconfigured at the namespace level. Those clear up
// server-side without anything happening on this host, and a never-retry cache
// would wedge the daemon until someone restarted it or rewrote the token file.
//
// So the suppression is a long re-probe window rather than a permanent verdict.
// At the lifecycle manager's 10s recovery cadence this turns ~8,600 lookups per
// day into ~96 — the volume problem is gone either way — while leaving the
// daemon able to heal itself from a server-side fix. Every event that plausibly
// means "the credential situation changed" (a token-file write, a peer socket
// reconnecting, SIGHUP) clears the cache outright, so the window is only ever
// the fallback for changes dotvault cannot observe.
const DenyProbeInterval = 15 * time.Minute

// maxDeniedTokens bounds the cache. In practice it holds one or two entries
// (the file's stale token, maybe a peer's), but the inputs are external — a
// peer socket handing back a fresh-but-unusable token each poll would otherwise
// grow the map without limit. On overflow the entry closest to re-probing is
// evicted, since it is the one whose suppression is worth the least.
const maxDeniedTokens = 16

// TokenDenylist remembers Vault tokens that Vault has already answered "denied"
// for, so the daemon stops re-presenting them on every poll.
//
// The bug it exists to fix: with an expired token in ~/.dotvault-token, the
// lifecycle manager's recovery poll (and, at startup, the headless idle loop)
// re-read that same file every 10 seconds and re-ran lookup-self against it
// forever. Nothing about the request changed between attempts, so the answer
// could not either — one host produced tens of thousands of denied lookups a
// week, and a fleet of them produced millions.
//
// Entries are keyed by SHA-256 of the token rather than the token itself. The
// cache is a pure lookup-suppression structure and never needs to reproduce a
// token, so hashing costs nothing and keeps a long-lived process-wide map from
// becoming somewhere Vault credentials accumulate. (The live token is of course
// still in memory on the Vault client — this is about not adding a second,
// broader home for dead ones.)
//
// All methods are safe on a nil receiver, so a call site that has no denylist
// wired (tests, one-shot commands) needs no branch.
type TokenDenylist struct {
	mu sync.Mutex
	// denied maps a token digest to the time its suppression lapses.
	denied map[string]time.Time

	// interval and now are fields rather than package constants so tests can
	// drive the re-probe window without sleeping.
	interval time.Duration
	now      func() time.Time
}

// NewTokenDenylist returns an empty denylist using the default re-probe window.
func NewTokenDenylist() *TokenDenylist {
	return &TokenDenylist{
		denied:   make(map[string]time.Time),
		interval: DenyProbeInterval,
		now:      time.Now,
	}
}

// tokenKey is the map key for a token: a hex SHA-256 digest, so the cache holds
// no usable credential.
func tokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Denied reports whether token is currently suppressed, and records the
// avoided-lookup metric when it is. An expired suppression is dropped here, so
// the next attempt goes to Vault normally and either succeeds (the server-side
// cause cleared) or re-denies (restarting the window).
//
// The empty token is never suppressed: "no token at all" is a different state,
// handled by the caller's own empty checks, and treating it as a denylist entry
// would collide across unrelated call sites.
func (d *TokenDenylist) Denied(ctx context.Context, token string) bool {
	if d == nil || token == "" {
		return false
	}
	key := tokenKey(token)
	d.mu.Lock()
	defer d.mu.Unlock()
	until, ok := d.denied[key]
	if !ok {
		return false
	}
	if !d.clock().Before(until) {
		delete(d.denied, key)
		return false
	}
	observability.RecordTokenDenylist(ctx, "suppressed")
	return true
}

// Deny suppresses token for the re-probe window and reports whether this was a
// new suppression (as opposed to extending one already in force). Callers use
// the return value to log once per episode rather than once per attempt.
func (d *TokenDenylist) Deny(token string) bool {
	if d == nil || token == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	key := tokenKey(token)
	now := d.clock()
	until, existing := d.denied[key]
	if existing && now.Before(until) {
		// Already suppressed; refresh the window but don't re-announce it.
		d.denied[key] = now.Add(d.window())
		return false
	}
	if !existing && len(d.denied) >= maxDeniedTokens {
		d.evictOldestLocked()
	}
	d.denied[key] = now.Add(d.window())
	return true
}

// NoteRejection records token when err is Vault's way of saying the token
// itself was rejected, logging and metering the first suppression of an
// episode. Errors that mean anything else (Vault unreachable, sealed, a 5xx)
// are ignored: those are transient, and suppressing a token over them would
// turn a blip into a stall.
func (d *TokenDenylist) NoteRejection(ctx context.Context, token string, err error) {
	if d == nil || !IsTokenRejected(err) {
		return
	}
	if d.Deny(token) {
		observability.RecordTokenDenylist(ctx, "denied")
		slog.Warn("vault rejected this token; suppressing repeat lookups for it",
			"error", err, "retry_after", d.window())
	}
}

// Clear drops every suppression and reports how many were dropped. Called when
// something that plausibly changes the credential situation happens — the token
// file being rewritten, a peer socket reconnecting, an operator SIGHUP — so a
// token given up on gets an immediate retry rather than waiting out the window.
// A token Vault denies again is re-denied on the spot and suppression resumes.
func (d *TokenDenylist) Clear(ctx context.Context) int {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	n := len(d.denied)
	if n > 0 {
		d.denied = make(map[string]time.Time)
	}
	d.mu.Unlock()

	if n > 0 {
		observability.RecordTokenDenylist(ctx, "cleared")
		slog.Debug("cleared denied-token suppression; previously-rejected tokens will be retried", "entries", n)
	}
	return n
}

// Len reports how many suppressions are currently held, lapsed ones included
// (they are dropped lazily on the next Denied). For tests and introspection.
func (d *TokenDenylist) Len() int {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.denied)
}

// window returns the configured re-probe interval, and clock the configured
// time source. Both tolerate a zero-value denylist built by a struct literal
// rather than NewTokenDenylist, so a hand-built one degrades to the defaults
// instead of panicking on a nil func.
func (d *TokenDenylist) window() time.Duration {
	if d.interval <= 0 {
		return DenyProbeInterval
	}
	return d.interval
}

func (d *TokenDenylist) clock() time.Time {
	if d.now == nil {
		return time.Now()
	}
	return d.now()
}

// evictOldestLocked removes the entry whose suppression lapses soonest. Called
// with d.mu held.
func (d *TokenDenylist) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for k, until := range d.denied {
		if oldestKey == "" || until.Before(oldest) {
			oldestKey, oldest = k, until
		}
	}
	if oldestKey != "" {
		delete(d.denied, oldestKey)
	}
}

// IsTokenRejected reports whether err from a Vault call is Vault saying the
// presented token is no good — a 403 (revoked, expired, or denied) or the
// lifecycle manager's expired-token sentinel. It is deliberately narrow:
// anything else (connection refused, a sealed or failing-over Vault, a 5xx) is
// a fault of the moment rather than a verdict on the token, and must leave the
// token usable so the next attempt can succeed.
func IsTokenRejected(err error) bool {
	return vault.IsForbidden(err) || IsExpired(err)
}
