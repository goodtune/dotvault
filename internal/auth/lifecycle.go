package auth

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goodtune/dotvault/internal/observability"
	"github.com/goodtune/dotvault/internal/vault"
)

// LifecycleManager manages token TTL checks and renewal.
type LifecycleManager struct {
	client         *vault.Client
	checkInterval  time.Duration
	disableRenewal bool
	needsReauth    atomic.Bool

	// reloadCh is signalled by Reload() to force an immediate tryReload
	// on the lifecycle goroutine. Buffered size 1 so a burst of signals
	// coalesces to a single pass; the surplus is dropped because every
	// reload reads the same file and an extra round-trip adds nothing.
	reloadCh chan struct{}

	// Token file path. When the current in-memory token becomes invalid,
	// the manager will first read this file directly (and only then fall
	// back to VAULT_TOKEN) before signalling re-auth. The file-first
	// precedence is deliberate: VAULT_TOKEN cannot be updated from
	// another shell, so if the env value is itself the broken token the
	// daemon was started with, env-first ordering would loop on the
	// same stale value. Empty means no reload attempt is made.
	tokenFilePath string

	// OnReauth, when non-nil, is invoked exactly once each time the
	// manager transitions to the needs-reauth state. Used by web mode to
	// clear in-memory auth state and force the SPA back to its login
	// screen. Reset when a subsequent check succeeds, so the callback
	// fires again on the next failure.
	onReauth func()

	// Recovery poll interval used while in the needs-reauth state. When
	// the token is broken we want to pick up a freshly-minted token from
	// the file faster than the normal 5-minute lookup cycle. Defaults to
	// 10s, capped at checkInterval.
	recoveryInterval time.Duration

	// Exponential backoff state for check failures.
	currentDelay time.Duration
	maxDelay     time.Duration

	// baselineTTL is the largest TTL we've observed for the current
	// token. It anchors the renew-threshold computation when the
	// Vault `creation_ttl` field is unavailable (some auth/token role
	// configurations omit it): without a stable baseline a short-TTL
	// token would otherwise satisfy the 15-minute fallback threshold
	// on every check and the daemon would call RenewSelf at every
	// poll interval. Updated whenever an observed TTL exceeds the
	// stored value (which can only happen after a successful renewal
	// or token swap), so the threshold tracks the live lease's
	// shape without needing explicit reset hooks.
	//
	// baselineToken pins the baseline to the token it was measured
	// against: when the in-memory token swaps (tryReload picking up
	// a fresh token, an OnReauth-driven re-login) the baseline is
	// reset so a new shorter-TTL token cannot inherit an oversized
	// baseline from its predecessor.
	//
	// baselineMu guards both baseline fields. checkAndRenew is the
	// only writer today, but a future code path that exposes the
	// renewal cadence (e.g. for /api/v1/status or a metric) would
	// race with the lifecycle goroutine without this lock. Matches
	// the mutex-around-mutable-state pattern Engine uses.
	baselineMu    sync.Mutex
	baselineTTL   time.Duration
	baselineToken string
}

// NewLifecycleManager creates a new token lifecycle manager. When
// disableRenewal is true the manager still monitors TTL and signals re-auth
// when the token expires, but never calls RenewSelf.
func NewLifecycleManager(client *vault.Client, checkInterval time.Duration, disableRenewal bool) *LifecycleManager {
	recovery := 10 * time.Second
	if recovery > checkInterval {
		recovery = checkInterval
	}
	return &LifecycleManager{
		client:           client,
		checkInterval:    checkInterval,
		disableRenewal:   disableRenewal,
		recoveryInterval: recovery,
		currentDelay:     checkInterval,
		maxDelay:         5 * time.Minute,
		reloadCh:         make(chan struct{}, 1),
	}
}

// Reload signals the lifecycle goroutine to perform an immediate
// tryReload on the next scheduling pass — used by the SIGHUP handler
// (driven in turn by the bundled dotvault-token-watch.path unit) so a
// freshly-written ~/.vault-token is picked up without waiting for the
// 5-minute lifecycle tick. Coalescing: concurrent or back-to-back
// calls collapse into a single reload. Safe to call before or after
// Start; calls made before Start are buffered and consumed by the
// goroutine on its first select.
func (lm *LifecycleManager) Reload() {
	select {
	case lm.reloadCh <- struct{}{}:
	default:
	}
}

// SetTokenFilePath wires a token file path so that on detection of an
// invalid/expired token the manager will attempt to reload (and re-validate)
// the token from disk or VAULT_TOKEN before declaring re-auth necessary.
// This lets an external facility (e.g. a tty session running `dotvault login`)
// recover a running daemon without a restart.
func (lm *LifecycleManager) SetTokenFilePath(p string) {
	lm.tokenFilePath = p
}

// SetOnReauth registers a callback fired when the manager transitions into
// the needs-reauth state. The callback runs synchronously on the lifecycle
// goroutine — keep it short. In web mode this is used to clear the
// in-memory Vault token so the SPA's status check reflects "logged out".
func (lm *LifecycleManager) SetOnReauth(fn func()) {
	lm.onReauth = fn
}

// NeedsReauth returns true if the token is expired or needs re-authentication.
func (lm *LifecycleManager) NeedsReauth() bool {
	return lm.needsReauth.Load()
}

// Start begins the token lifecycle goroutine. Returns a channel that receives
// errors (e.g., when re-auth is needed). The goroutine stops when ctx is cancelled.
func (lm *LifecycleManager) Start(ctx context.Context) <-chan error {
	errCh := make(chan error, 1)

	go func() {
		defer close(errCh)

		timer := time.NewTimer(lm.currentDelay)
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-lm.reloadCh:
				// External nudge (SIGHUP → Reload()). Try to swap to a
				// fresh token from disk. On success, reset the timer to
				// the normal check interval so a recovery-mode 10s tick
				// doesn't fire shortly after. On failure (no candidate,
				// or all candidates invalid) leave the schedule alone —
				// the original timer.C tick will run checkAndRenew on
				// its existing cadence.
				if lm.tryReload(ctx) {
					lm.clearReauth()
					lm.currentDelay = lm.checkInterval
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					timer.Reset(lm.currentDelay)
				}
			case <-timer.C:
				if err := lm.checkAndRenew(ctx); err != nil {
					// Recoverable failure modes:
					//   - 403 (token revoked/invalid)
					//   - sentinel for an expired token reported via
					//     lookup-self with a concrete expire_time
					//   - we are already in the needs-reauth state, OR the
					//     current client token is empty (because OnReauth
					//     just cleared it). In the empty-token case Vault
					//     returns "missing client token" (400), which is
					//     neither 403 nor the expired sentinel — without
					//     this branch the manager would slip into the
					//     transient-error path, back off to 5m, and never
					//     observe a fresh token written to disk.
					if vault.IsForbidden(err) || IsExpired(err) || lm.needsReauth.Load() || lm.client.Token() == "" {
						// Try reloading the token from disk/env before
						// declaring re-auth — a parallel `dotvault login`
						// may have already written a fresh token. If the
						// reload yields a working token we treat the
						// failure as transient.
						if lm.tryReload(ctx) {
							lm.clearReauth()
							lm.currentDelay = lm.checkInterval
							timer.Reset(lm.currentDelay)
							continue
						}
						nextDelay := lm.recoveryInterval
						slog.Warn("vault token invalid, re-authentication required", "error", err, "next_retry", nextDelay)
						lm.signalReauth(ctx, errCh, err)
						lm.currentDelay = nextDelay
					} else {
						// Transient error: backoff up to maxDelay.
						nextDelay := lm.currentDelay * 2
						if nextDelay > lm.maxDelay {
							nextDelay = lm.maxDelay
						}
						slog.Warn("token lifecycle check failed, will retry", "error", err, "next_retry", nextDelay)
						lm.currentDelay = nextDelay
					}
				} else {
					// Reset to base interval on success and clear any
					// previously-set re-auth state (a freshly-loaded token
					// can succeed even after the previous one was revoked).
					lm.clearReauth()
					lm.currentDelay = lm.checkInterval
				}
				timer.Reset(lm.currentDelay)
			}
		}
	}()

	return errCh
}

// signalReauth flips the manager into the needs-reauth state and invokes
// the OnReauth callback once per transition. The error is pushed onto errCh
// non-blockingly so a consumer that has stopped reading doesn't deadlock.
// Takes the lifecycle goroutine's ctx so the metric record carries
// the same cancellation / trace context the rest of the cycle uses.
func (lm *LifecycleManager) signalReauth(ctx context.Context, errCh chan<- error, err error) {
	if lm.needsReauth.Load() {
		return
	}
	lm.needsReauth.Store(true)
	observability.RecordTokenRenewal(ctx, "reauth_required")
	if lm.onReauth != nil {
		lm.onReauth()
	}
	select {
	case errCh <- err:
	default:
	}
}

// clearReauth resets the needs-reauth flag — used when a check succeeds
// (either after a clean cycle or after picking up a fresh token from disk).
func (lm *LifecycleManager) clearReauth() {
	lm.needsReauth.Store(false)
}

// tryReload re-reads the token file (and VAULT_TOKEN env) and, if a
// different value is present, swaps it onto the Vault client and
// validates with LookupSelf. Returns true iff one of the candidates
// produced a working token. On failure the previous (broken) token is
// restored so the caller's error-handling path sees the same state it
// would have without a reload.
//
// Candidate ordering: the token file is consulted before VAULT_TOKEN
// because the env variable cannot be mutated by an external
// `dotvault login` running in another shell — if VAULT_TOKEN itself is
// the expired token the daemon was started with, ResolveToken's
// env-first policy would keep selecting it and never see a fresh
// value on disk. Reading the file first sidesteps that loop.
func (lm *LifecycleManager) tryReload(ctx context.Context) bool {
	if lm.tokenFilePath == "" {
		return false
	}
	current := lm.client.Token()

	candidates := make([]string, 0, 2)
	if fileToken, _ := ReadTokenFile(lm.tokenFilePath); fileToken != "" && fileToken != current {
		candidates = append(candidates, fileToken)
	}
	if envToken := ReadTokenEnv(); envToken != "" && envToken != current {
		// Skip if we already queued an identical file token, but still
		// try env when it differs from both the current and file values.
		if len(candidates) == 0 || candidates[0] != envToken {
			candidates = append(candidates, envToken)
		}
	}
	if len(candidates) == 0 {
		return false
	}

	for _, candidate := range candidates {
		lm.client.SetToken(candidate)
		if _, err := lm.client.LookupSelf(ctx); err == nil {
			slog.Info("picked up fresh vault token")
			return true
		} else {
			slog.Warn("attempted token reload, candidate is also invalid", "error", err)
		}
	}
	lm.client.SetToken(current)
	return false
}

func (lm *LifecycleManager) checkAndRenew(ctx context.Context) error {
	secret, err := lm.client.LookupSelf(ctx)
	if err != nil {
		return err
	}

	// Extract TTL
	ttlRaw, ok := secret.Data["ttl"]
	if !ok {
		return nil // No TTL = root token or non-expiring
	}

	var ttl time.Duration
	switch v := ttlRaw.(type) {
	case json.Number:
		secs, _ := v.Int64()
		ttl = time.Duration(secs) * time.Second
	case float64:
		ttl = time.Duration(v) * time.Second
	default:
		return nil
	}
	observability.RecordTokenTTL(ctx, ttl)

	// TTL=0 with no expire_time means non-expiring (root token)
	if ttl <= 0 {
		expireTime, _ := secret.Data["expire_time"]
		if expireTime == nil {
			return nil // Non-expiring token (e.g., root)
		}
		// Token has expired — surface this as a tokenExpiredError so the
		// goroutine runs the same recovery path (token-file reload, then
		// signal re-auth) it uses for 403 responses.
		return errTokenExpired
	}

	// Check if renewable
	renewableRaw, _ := secret.Data["renewable"]
	renewable, _ := renewableRaw.(bool)

	// Renew when ≤25 % of the token's baseline TTL remains, mirroring
	// the policy login-check uses. The previous form computed
	// `renewThreshold := ttl / 4` and tested `ttl <= renewThreshold`,
	// which can never be true for any positive TTL (ttl/4 < ttl) — so
	// renewal silently never fired and tokens would only ever expire
	// into a forced re-auth.
	//
	// Baseline selection (in priority order):
	//   1. `creation_ttl` from Vault — most reliable when present.
	//   2. The largest TTL we've observed for the current token —
	//      captures the lease's true shape after the first poll, even
	//      when creation_ttl is missing.
	//   3. A 15-minute floor — only relevant on the very first check
	//      of a token whose creation_ttl is also unavailable.
	//
	// Anchoring on a stable baseline (step 2) is what prevents the
	// pathological renew loop for short-lived tokens: without it, a
	// 5-minute token with no creation_ttl would satisfy the 15-minute
	// fallback threshold on every check and the daemon would call
	// RenewSelf at every poll interval (~5min).
	creationTTLSec, _ := readSecondsField(secret.Data, "creation_ttl")
	creationTTL := time.Duration(creationTTLSec) * time.Second
	// Reset the cached baseline when the token swaps so a shorter
	// new token doesn't inherit an oversized baseline from a longer
	// previous one (which would make `ttl <= baseline/4` true on
	// every check and trigger RenewSelf in a tight loop). The
	// read-compare-write pair runs under baselineMu so a concurrent
	// reader (added in a future status / metric path) can't observe
	// a torn state.
	lm.baselineMu.Lock()
	if currentToken := lm.client.Token(); currentToken != lm.baselineToken {
		lm.baselineTTL = 0
		lm.baselineToken = currentToken
	}
	if ttl > lm.baselineTTL {
		lm.baselineTTL = ttl
	}
	baselineTTL := lm.baselineTTL
	lm.baselineMu.Unlock()

	// baseline is guaranteed positive here: the ttl<=0 early-return
	// above means ttl is positive, and lm.baselineTTL was just
	// max()'d up to ttl. The earlier draft had a `15 * time.Minute`
	// floor for the "no baseline information at all" case, but the
	// baselineTTL cache makes that branch unreachable — drop it
	// rather than carry dead code.
	baseline := creationTTL
	if baseline <= 0 {
		baseline = baselineTTL
	}
	renewThreshold := baseline / 4
	if ttl <= renewThreshold && renewable && !lm.disableRenewal {
		slog.Info("renewing token", "ttl_remaining", ttl)
		_, err := lm.client.RenewSelf(ctx, 0)
		if err != nil {
			observability.RecordTokenRenewal(ctx, "failed")
			return err
		}
		observability.RecordTokenRenewal(ctx, "renewed")
		slog.Info("token renewed successfully")
	}

	return nil
}

// readSecondsField proxies vault.ReadSecondsField, kept as an
// unexported package-local alias so existing call sites stay
// readable. The implementation lives in internal/vault so the
// CLI's login-check path can share it without re-defining the
// json.Number / float64 / int type switch.
func readSecondsField(data map[string]any, key string) (int64, bool) {
	return vault.ReadSecondsField(data, key)
}

// errTokenExpired is the sentinel returned by checkAndRenew when
// LookupSelf succeeds but reports the token has expired (TTL=0 with a
// concrete expire_time). The Start loop treats it identically to a 403:
// attempt a file-based reload, then signal re-auth if that fails.
var errTokenExpired = &expiredError{}

type expiredError struct{}

func (*expiredError) Error() string { return "vault token has expired" }

// IsExpired reports whether err is the token-expired sentinel. The Start
// loop uses this to route expired tokens through the same recovery path
// as a 403 response.
func IsExpired(err error) bool {
	_, ok := err.(*expiredError)
	return ok
}
