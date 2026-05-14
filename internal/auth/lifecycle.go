package auth

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
)

// LifecycleManager manages token TTL checks and renewal.
type LifecycleManager struct {
	client         *vault.Client
	checkInterval  time.Duration
	disableRenewal bool
	needsReauth    atomic.Bool

	// Token file path. When the current in-memory token becomes invalid,
	// the manager will first attempt to reload from this path (or the
	// VAULT_TOKEN env var via ResolveToken) before signalling re-auth.
	// Empty means no reload attempt is made.
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
			case <-timer.C:
				if err := lm.checkAndRenew(ctx); err != nil {
					if vault.IsForbidden(err) || IsExpired(err) {
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
						lm.signalReauth(errCh, err)
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
func (lm *LifecycleManager) signalReauth(errCh chan<- error, err error) {
	if lm.needsReauth.Load() {
		return
	}
	lm.needsReauth.Store(true)
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

	// Renew at 75% of TTL (i.e., when only 25% remains), unless renewal is disabled.
	renewThreshold := ttl / 4
	if ttl <= renewThreshold && renewable && !lm.disableRenewal {
		slog.Info("renewing token", "ttl_remaining", ttl)
		_, err := lm.client.RenewSelf(ctx, 0)
		if err != nil {
			return err
		}
		slog.Info("token renewed successfully")
	}

	return nil
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
