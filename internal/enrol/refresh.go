package enrol

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
)

// Clock abstracts time.Now so refresh-manager unit tests can drive the
// half-life calculation deterministically without sleeping.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

// RefreshManager periodically scans configured enrolments, asks any whose
// engines implement Refresher to rotate credentials past their half-life,
// and writes the rotated secret back to Vault. Modeled on
// auth.LifecycleManager — one goroutine, stateless between ticks, with
// per-enrolment exponential backoff so a single flaky provider does not
// stall the others.
type RefreshManager struct {
	client        *vault.Client
	kvMount       string
	userPrefix    string // e.g. "users/alice/"
	checkInterval time.Duration
	maxBackoff    time.Duration
	clock         Clock

	mu         sync.Mutex
	enrolments map[string]config.Enrolment
	backoffs   map[string]time.Duration // per-enrolment backoff state; cleared on success
}

// RefreshManagerOption configures a RefreshManager at construction time.
type RefreshManagerOption func(*RefreshManager)

// WithClock overrides the wall clock. Intended for tests.
func WithClock(c Clock) RefreshManagerOption {
	return func(m *RefreshManager) { m.clock = c }
}

// WithMaxBackoff overrides the backoff cap. Intended for tests.
func WithMaxBackoff(d time.Duration) RefreshManagerOption {
	return func(m *RefreshManager) { m.maxBackoff = d }
}

// NewRefreshManager constructs a RefreshManager. userPrefix must already
// include the username and a trailing slash (e.g. "users/alice/"), matching
// the convention used by the rest of the daemon.
func NewRefreshManager(
	client *vault.Client,
	kvMount, userPrefix string,
	enrolments map[string]config.Enrolment,
	checkInterval time.Duration,
	opts ...RefreshManagerOption,
) *RefreshManager {
	m := &RefreshManager{
		client:        client,
		kvMount:       kvMount,
		userPrefix:    userPrefix,
		checkInterval: checkInterval,
		maxBackoff:    5 * time.Minute,
		clock:         realClock{},
		enrolments:    enrolments,
		backoffs:      make(map[string]time.Duration),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// UpdateConfig replaces the enrolment map atomically. Called when the
// daemon's background config-reload loop detects changes.
func (m *RefreshManager) UpdateConfig(enrolments map[string]config.Enrolment) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enrolments = enrolments
	// Drop backoff state for any enrolment that was removed.
	for key := range m.backoffs {
		if _, ok := enrolments[key]; !ok {
			delete(m.backoffs, key)
		}
	}
}

// Start launches the refresh goroutine. It stops when ctx is cancelled.
func (m *RefreshManager) Start(ctx context.Context) {
	go m.run(ctx)
}

func (m *RefreshManager) run(ctx context.Context) {
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	// Run an initial tick immediately so tokens past half-life at startup
	// get refreshed without waiting a full interval.
	m.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.tick(ctx)
		}
	}
}

// tick iterates all enrolments and triggers a refresh for each Refresher
// whose token is past half-life. Each enrolment is handled independently;
// one failure does not block others.
func (m *RefreshManager) tick(ctx context.Context) {
	m.mu.Lock()
	snapshot := make(map[string]config.Enrolment, len(m.enrolments))
	for k, v := range m.enrolments {
		snapshot[k] = v
	}
	m.mu.Unlock()

	for key, enrolment := range snapshot {
		if ctx.Err() != nil {
			return
		}
		engine, ok := GetEngine(enrolment.Engine)
		if !ok {
			continue
		}
		refresher, ok := engine.(Refresher)
		if !ok {
			continue // engine doesn't rotate; nothing to do
		}

		m.refreshOne(ctx, key, enrolment, refresher)
	}
}

// refreshOne handles a single enrolment: read Vault, check half-life, call
// Refresh, write back. All errors are logged; the caller recovers state on
// the next tick.
func (m *RefreshManager) refreshOne(ctx context.Context, key string, enrolment config.Enrolment, engine Refresher) {
	path := m.userPrefix + key
	secret, err := m.client.ReadKVv2(ctx, m.kvMount, path)
	if err != nil {
		slog.Warn("refresh: failed to read secret", "key", key, "error", err)
		m.bumpBackoff(key)
		return
	}
	if secret == nil {
		// No enrolment yet — not our problem; the enrolment wizard handles it.
		return
	}

	existing := stringifyStringMap(secret.Data)

	// Legacy pass-through: if there's no expires_at, this is a secret from
	// a previous version of dotvault. Skip silently — re-enrolment is how
	// users migrate.
	expiresAtStr, ok := existing["expires_at"]
	if !ok || expiresAtStr == "" {
		return
	}
	issuedAtStr := existing["issued_at"]
	if issuedAtStr == "" {
		slog.Error("refresh: secret has expires_at but no issued_at, skipping", "key", key)
		return
	}

	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		slog.Error("refresh: invalid expires_at, skipping", "key", key, "value", expiresAtStr, "error", err)
		return
	}
	issuedAt, err := time.Parse(time.RFC3339, issuedAtStr)
	if err != nil {
		slog.Error("refresh: invalid issued_at, skipping", "key", key, "value", issuedAtStr, "error", err)
		return
	}

	halfLife := issuedAt.Add(expiresAt.Sub(issuedAt) / 2)
	now := m.clock.Now()
	if now.Before(halfLife) {
		return
	}

	slog.Info("refresh: rotating token past half-life", "key", key, "engine", enrolment.Engine, "half_life", halfLife, "expires_at", expiresAt)

	rotated, err := engine.Refresh(ctx, enrolment.Settings, existing)
	if err != nil {
		if errors.Is(err, ErrRevoked) {
			slog.Warn("refresh: upstream credential revoked, wiping vault secret so user can re-enrol", "key", key, "error", err)
			if delErr := m.client.DeleteKVv2(ctx, m.kvMount, path); delErr != nil {
				slog.Error("refresh: failed to delete revoked secret", "key", key, "error", delErr)
			}
			// No backoff on revocation — the state is terminal until re-enrol.
			m.resetBackoff(key)
			return
		}
		slog.Warn("refresh: transient failure, will retry", "key", key, "error", err)
		m.bumpBackoff(key)
		return
	}

	data := make(map[string]any, len(rotated))
	for k, v := range rotated {
		data[k] = v
	}
	if err := m.client.WriteKVv2(ctx, m.kvMount, path, data); err != nil {
		slog.Warn("refresh: failed to write rotated secret", "key", key, "error", err)
		m.bumpBackoff(key)
		return
	}

	slog.Info("refresh: rotation complete", "key", key, "new_expires_at", rotated["expires_at"])
	m.resetBackoff(key)
}

// bumpBackoff doubles this enrolment's pending retry delay, capped at
// maxBackoff. Because tick() runs on a fixed ticker rather than rescheduling
// against the backoff value, backoff in practice just means "don't retry
// sooner than the next tick" — the data structure is in place so that
// longer check intervals (or a future per-enrolment scheduler) can use it.
func (m *RefreshManager) bumpBackoff(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.backoffs[key]
	if current == 0 {
		current = m.checkInterval
	} else {
		current *= 2
	}
	if current > m.maxBackoff {
		current = m.maxBackoff
	}
	m.backoffs[key] = current
}

func (m *RefreshManager) resetBackoff(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.backoffs, key)
}

// stringifyStringMap converts Vault's map[string]any data (where every
// value is already a string in KVv2 secrets, but typed as `any`) into the
// string→string map that engines expect. Non-string values are skipped,
// which matches how findPending treats malformed secrets.
func stringifyStringMap(data map[string]any) map[string]string {
	out := make(map[string]string, len(data))
	for k, v := range data {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// Compile-time check that the JFrog engine implements Refresher so the
// refresh manager will route it through the rotation path.
var _ Refresher = (*JFrogEngine)(nil)
