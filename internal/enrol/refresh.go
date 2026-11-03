package enrol

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
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
	// revoked holds, per enrolment, the KVv2 version whose refresh token the
	// provider rejected. The wipe runs a tick later, and only if that version
	// is still current; see refreshOne.
	revoked map[string]revokedMark
}

// revokedMark identifies the rejected KVv2 version by number and creation
// time together. The number alone is not an identity: deleting a secret's
// metadata and enrolling again restarts its versions at 1, so a fresh
// credential could otherwise match the mark and be wiped on its first tick.
// A read without version metadata leaves CreatedTime zero on both sides, so
// the match falls back to the version number alone, as it was before.
type revokedMark struct {
	version int
	created time.Time
}

func (r revokedMark) matches(s *vault.Secret) bool {
	return r.version == s.Version && r.created.Equal(s.CreatedTime)
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
		revoked:       make(map[string]revokedMark),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// UpdateConfig replaces the enrolment map atomically, dropping backoff and
// pending-wipe state for every enrolment it removes or changes. Called when
// the daemon's background config-reload loop detects changes.
func (m *RefreshManager) UpdateConfig(enrolments map[string]config.Enrolment) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.enrolments
	m.enrolments = enrolments
	// Drop backoff and revocation state for any enrolment that was removed or
	// changed. A removed key's mark would be judged against whatever a later
	// enrolment under that key writes. A changed one matters as much: a
	// rejection can be the configuration's fault rather than the
	// credential's (a wrong client_id, say), and a mark surviving the fix
	// would wipe a credential the corrected enrolment could have refreshed.
	for key := range m.backoffs {
		if !sameEnrolment(old, enrolments, key) {
			delete(m.backoffs, key)
		}
	}
	for key := range m.revoked {
		if !sameEnrolment(old, enrolments, key) {
			delete(m.revoked, key)
		}
	}
}

// sameEnrolment reports whether key is configured identically in both maps.
func sameEnrolment(old, cur map[string]config.Enrolment, key string) bool {
	o, okOld := old[key]
	c, okCur := cur[key]
	return okOld && okCur && refreshEquivalent(o, c)
}

// refreshEquivalent reports whether two enrolments would refresh the same
// way: the engine and the settings handed to Refresh. Fields that play no
// part in a refresh (HelpText) are ignored, so editing them neither cancels
// a pending wipe nor lets a rejected token be presented again.
func refreshEquivalent(a, b config.Enrolment) bool {
	return a.Engine == b.Engine && reflect.DeepEqual(a.Settings, b.Settings)
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
		// Clear any stale backoff from a previous attempt (e.g. the secret
		// was deleted externally while we were in a backoff window).
		m.resetBackoff(key)
		m.clearRevoked(key)
		return
	}

	if mark, ok := m.revocation(key); ok {
		if mark.matches(secret) {
			m.wipeRevoked(ctx, key, path, enrolment)
			return
		}
		// The secret moved on after the rejection, so whoever spent that
		// token wrote its replacement. Judge the new version on its merits.
		m.clearRevoked(key)
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

	if !expiresAt.After(issuedAt) {
		slog.Error("refresh: expires_at is not after issued_at, skipping", "key", key, "issued_at", issuedAtStr, "expires_at", expiresAtStr)
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
			// A rotating refresh token is single-use, so a rejection does not
			// prove the credential is dead: a daemon on another host sharing
			// this secret may have spent it and be about to write the result.
			// Wiping now would delete that, and Vault offers no conditional
			// delete, so arm the wipe and let the next tick decide on evidence.
			// The token is not presented again in the meantime.
			slog.Warn("refresh: upstream rejected the credential, wiping on the next check unless the secret or its enrolment config changes", "key", key, "error", err)
			m.setRevoked(key, enrolment, revokedMark{version: secret.Version, created: secret.CreatedTime})
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
	// Check-and-set against the version the refresh token came from: anything
	// written since (a re-enrolment, say) is newer than this rotation.
	if err := m.client.WriteKVv2CAS(ctx, m.kvMount, path, data, secret.Version); err != nil {
		if errors.Is(err, vault.ErrCASMismatch) {
			slog.Info("refresh: secret changed during rotation, keeping the newer version", "key", key)
			m.resetBackoff(key)
			return
		}
		slog.Warn("refresh: failed to write rotated secret", "key", key, "error", err)
		m.bumpBackoff(key)
		return
	}

	slog.Info("refresh: rotation complete", "key", key, "new_expires_at", rotated["expires_at"])
	m.resetBackoff(key)
}

// wipeRevoked deletes a secret whose refresh token the provider rejected and
// which no other writer has replaced since. A failed delete stays armed and
// backs off, so it is retried without presenting the token again.
//
// The mark and the enrolment are re-checked just before the delete: a reload
// landing after tick took its snapshot has cleared the mark of a changed
// enrolment, and deleting anyway would undo exactly that. What remains is the
// delete's own round trip, since holding m.mu across a Vault call would stall
// UpdateConfig behind it.
func (m *RefreshManager) wipeRevoked(ctx context.Context, key, path string, used config.Enrolment) {
	if !m.stillArmed(key, used) {
		return
	}
	slog.Warn("refresh: upstream credential revoked, wiping vault secret so user can re-enrol", "key", key)
	if err := m.client.DeleteKVv2(ctx, m.kvMount, path); err != nil {
		slog.Error("refresh: failed to delete revoked secret, will retry", "key", key, "error", err)
		m.bumpBackoff(key)
		return
	}
	// No backoff once the revoked secret has been wiped — the state is
	// terminal until the user re-enrols.
	m.resetBackoff(key)
	m.clearRevoked(key)
}

func (m *RefreshManager) revocation(key string) (revokedMark, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.revoked[key]
	return r, ok
}

// stillArmed reports whether key still carries a mark and is still
// configured as the enrolment the caller is acting under.
func (m *RefreshManager) stillArmed(key string, used config.Enrolment) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.revoked[key]; !ok {
		return false
	}
	cur, ok := m.enrolments[key]
	return ok && refreshEquivalent(cur, used)
}

// setRevoked arms the wipe, but only if key is still configured as the
// enrolment the rejected attempt ran under. A config reload landing while
// the refresh was in flight has already cleared state for a changed or
// removed key (see UpdateConfig); arming afterwards would bring back a
// rejection the reload had invalidated.
func (m *RefreshManager) setRevoked(key string, used config.Enrolment, mark revokedMark) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.enrolments[key]; !ok || !refreshEquivalent(cur, used) {
		return
	}
	m.revoked[key] = mark
}

func (m *RefreshManager) clearRevoked(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.revoked, key)
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

// Compile-time check that the JFrog, Databricks and GitHub engines implement
// Refresher so the refresh manager will route them through the rotation path.
var (
	_ Refresher = (*JFrogEngine)(nil)
	_ Refresher = (*DatabricksEngine)(nil)
	_ Refresher = (*GitHubEngine)(nil)
)
