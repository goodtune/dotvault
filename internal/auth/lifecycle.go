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

	// Exponential backoff state for check failures.
	currentDelay time.Duration
	maxDelay     time.Duration
}

// NewLifecycleManager creates a new token lifecycle manager. When
// disableRenewal is true the manager still monitors TTL and signals re-auth
// when the token expires, but never calls RenewSelf.
func NewLifecycleManager(client *vault.Client, checkInterval time.Duration, disableRenewal bool) *LifecycleManager {
	return &LifecycleManager{
		client:         client,
		checkInterval:  checkInterval,
		disableRenewal: disableRenewal,
		currentDelay:   checkInterval,
		maxDelay:       5 * time.Minute,
	}
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
					// Compute next capped delay before logging so the logged value is accurate
					nextDelay := lm.currentDelay * 2
					if nextDelay > lm.maxDelay {
						nextDelay = lm.maxDelay
					}
					if vault.IsForbidden(err) {
						slog.Warn("vault token forbidden (403), re-authentication required", "error", err, "next_retry", nextDelay)
						if !lm.needsReauth.Load() {
							lm.needsReauth.Store(true)
							select {
							case errCh <- err:
							default:
							}
						}
					} else {
						slog.Warn("token lifecycle check failed, will retry", "error", err, "next_retry", nextDelay)
					}
					lm.currentDelay = nextDelay
				} else {
					// Reset to base interval on success
					lm.currentDelay = lm.checkInterval
				}
				timer.Reset(lm.currentDelay)
			}
		}
	}()

	return errCh
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
		slog.Warn("token expired")
		lm.needsReauth.Store(true)
		return nil
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
		lm.needsReauth.Store(false)
	}

	return nil
}
