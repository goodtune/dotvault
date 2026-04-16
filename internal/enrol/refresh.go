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
// defaultRefreshInterval is the fallback cadence if a caller supplies a
// non-positive checkInterval (which would otherwise panic time.NewTicker).
const defaultRefreshInterval = time.Minute

type RefreshManager struct {
	client        *vault.Client
	kvMount       string
	userPrefix    string // e.g. "users/alice/"
	checkInterval time.Duration
	maxBackoff    time.Duration
	clock         Clock

	mu         sync.Mutex
	enrolments map[string]config.Enrolment
	// backoff state per-enrolment. `delay` is the current wait interval
	// (doubled on each failure, capped at maxBackoff, cleared on success).
	// `nextAttempt` is the clock time before which tick() skips this
	// enrolment — this is what actually makes the backoff observable.
	backoffs map[string]backoffState
}

type backoffState struct {
	delay       time.Duration
	nextAttempt time.Time
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
// the convention used by the rest of the daemon. A non-positive
// checkInterval is coerced to defaultRefreshInterval with a WARN log so
// the ticker cannot panic.
func NewRefreshManager(
	client *vault.Client,
	kvMount, userPrefix string,
	enrolments map[string]config.Enrolment,
	checkInterval time.Duration,
	opts ...RefreshManagerOption,
) *RefreshManager {
	if checkInterval <= 0 {
		slog.Warn("refresh: invalid check_interval, using fallback",
			"check_interval", checkInterval, "fallback", defaultRefreshInterval)
		checkInterval = defaultRefreshInterval
	}
	m := &RefreshManager{
		client:        client,
		kvMount:       kvMount,
		userPrefix:    userPrefix,
		checkInterval: checkInterval,
		maxBackoff:    5 * time.Minute,
		clock:         realClock{},
		enrolments:    enrolments,
		backoffs:      make(map[string]backoffState),
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
// one failure does not block others. Enrolments whose previous attempt
// failed are skipped until their backoff deadline has elapsed.
func (m *RefreshManager) tick(ctx context.Context) {
	m.mu.Lock()
	snapshot := make(map[string]config.Enrolment, len(m.enrolments))
	for k, v := range m.enrolments {
		snapshot[k] = v
	}
	m.mu.Unlock()

	now := m.clock.Now()
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
		if m.inBackoff(key, now) {
			// Previous attempt failed; not yet time to retry.
			continue
		}

		m.refreshOne(ctx, key, enrolment, refresher)
	}
}

// inBackoff reports whether this enrolment is still inside its retry
// cooldown window as of `now`.
func (m *RefreshManager) inBackoff(key string, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.backoffs[key]
	if !ok {
		return false
	}
	return now.Before(s.nextAttempt)
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
		// Bump backoff so a malformed secret doesn't re-log this ERROR
		// every tick — the state is only fixable by re-enrolment or a
		// manual Vault edit, and in both cases polling harder doesn't help.
		slog.Error("refresh: secret has expires_at but no issued_at, skipping", "key", key)
		m.bumpBackoff(key)
		return
	}

	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		slog.Error("refresh: invalid expires_at, skipping", "key", key, "value", expiresAtStr, "error", err)
		m.bumpBackoff(key)
		return
	}
	issuedAt, err := time.Parse(time.RFC3339, issuedAtStr)
	if err != nil {
		slog.Error("refresh: invalid issued_at, skipping", "key", key, "value", issuedAtStr, "error", err)
		m.bumpBackoff(key)
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
				// Treat Vault cleanup failure as transient: keep backoff
				// so we retry the delete on a later tick instead of
				// re-calling Refresh against a known-revoked credential
				// every cycle.
				slog.Error("refresh: failed to delete revoked secret, will retry", "key", key, "error", delErr)
				m.bumpBackoff(key)
				return
			}
			// No backoff once the revoked secret has been wiped — the
			// state is terminal until the user re-enrols.
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

// bumpBackoff records a failure for this enrolment and sets the next
// allowed attempt time. Delay doubles on each consecutive failure,
// capped at maxBackoff, and starts at checkInterval (so a transient
// failure costs at least one tick before the next attempt). The
// nextAttempt timestamp is the actual gate consulted by tick().
func (m *RefreshManager) bumpBackoff(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.backoffs[key]
	if s.delay == 0 {
		s.delay = m.checkInterval
	} else {
		s.delay *= 2
	}
	if s.delay > m.maxBackoff {
		s.delay = m.maxBackoff
	}
	s.nextAttempt = m.clock.Now().Add(s.delay)
	m.backoffs[key] = s
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
