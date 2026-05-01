package enrol

import (
	"bytes"
	"context"
	"fmt"
	iolib "io"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
)

// defaultWatchPollInterval is the fallback poll interval if the caller
// supplies a non-positive value (which would otherwise panic
// time.NewTicker).
const defaultWatchPollInterval = time.Minute

// WatchManager polls and (where available) subscribes to Vault events
// for enrolments whose engines implement Watcher. Each tick it asks the
// engine to re-derive its output and writes the result to the user's
// enrolment path only when it differs from what's already there.
//
// The structure mirrors RefreshManager: one goroutine, snapshotting
// configuration per tick, with per-enrolment exponential backoff so a
// single flaky upstream does not block the others. Refresh and Watch
// are intentionally separate managers — they handle orthogonal concerns
// (credential rotation vs. data mirroring) and coupling them would mean
// every tick of the rotation half-life check has to walk Watcher
// engines and vice versa.
type WatchManager struct {
	client       *vault.Client
	kvMount      string
	userPrefix   string // e.g. "users/alice/"
	username     string
	pollInterval time.Duration
	maxBackoff   time.Duration
	clock        Clock
	io           IO

	mu         sync.Mutex
	enrolments map[string]config.Enrolment
	backoffs   map[string]backoffState
	// triggerCh is buffered so an event can request an immediate tick
	// without blocking the event-dispatch goroutine.
	triggerCh chan string // enrolment key, or "" for all
}

// WatchManagerOption configures a WatchManager at construction.
type WatchManagerOption func(*WatchManager)

// WithWatchClock overrides the wall clock. Intended for tests.
func WithWatchClock(c Clock) WatchManagerOption {
	return func(m *WatchManager) { m.clock = c }
}

// WithWatchMaxBackoff overrides the backoff cap. Intended for tests.
func WithWatchMaxBackoff(d time.Duration) WatchManagerOption {
	return func(m *WatchManager) { m.maxBackoff = d }
}

// NewWatchManager constructs a WatchManager. userPrefix must already
// include the username and a trailing slash (e.g. "users/alice/"),
// matching the convention used by Manager and RefreshManager.
func NewWatchManager(
	client *vault.Client,
	kvMount, userPrefix, username string,
	enrolments map[string]config.Enrolment,
	pollInterval time.Duration,
	opts ...WatchManagerOption,
) *WatchManager {
	if pollInterval <= 0 {
		slog.Warn("watch: invalid poll_interval, using fallback",
			"poll_interval", pollInterval, "fallback", defaultWatchPollInterval)
		pollInterval = defaultWatchPollInterval
	}
	m := &WatchManager{
		client:       client,
		kvMount:      kvMount,
		userPrefix:   userPrefix,
		username:     username,
		pollInterval: pollInterval,
		maxBackoff:   5 * time.Minute,
		clock:        realClock{},
		enrolments:   enrolments,
		backoffs:     make(map[string]backoffState),
		triggerCh:    make(chan string, 16),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// UpdateConfig replaces the enrolment map atomically.
func (m *WatchManager) UpdateConfig(enrolments map[string]config.Enrolment) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enrolments = enrolments
	for key := range m.backoffs {
		if _, ok := enrolments[key]; !ok {
			delete(m.backoffs, key)
		}
	}
}

// Start launches the watch goroutines. They stop when ctx is cancelled.
// Start returns immediately; failures (event subscription unavailable,
// transient poll errors) are logged but never propagated.
func (m *WatchManager) Start(ctx context.Context) {
	go m.run(ctx)
}

func (m *WatchManager) run(ctx context.Context) {
	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	// Try to subscribe to Vault events for immediate reaction on Enterprise.
	// Failures degrade gracefully to poll-only; the existing sync engine
	// owns its own subscription, so we deliberately open a separate one
	// rather than multiplexing across managers — keeps the dependency
	// graph one-way (enrol depends on vault, not on sync).
	go m.runEventLoop(ctx)

	// Initial poll so changes that happened while the daemon was offline
	// land without waiting a full interval.
	m.tickAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.tickAll(ctx)
		case key := <-m.triggerCh:
			if key == "" {
				m.tickAll(ctx)
			} else {
				m.tickOne(ctx, key)
			}
		}
	}
}

// runEventLoop subscribes to kv-v2/data-write events and pushes a
// trigger onto triggerCh whenever an event matches one of the
// configured Watcher source paths. Reconnects with exponential backoff
// on transient failures; gives up silently if the Events API isn't
// available (community Vault), in which case polling is the only path.
func (m *WatchManager) runEventLoop(ctx context.Context) {
	delay := time.Second
	const maxDelay = 5 * time.Minute
	for {
		if ctx.Err() != nil {
			return
		}
		eventCh, errCh, err := m.client.SubscribeEvents(ctx, "kv-v2/data-write")
		if err != nil {
			slog.Info("watch: event subscription not available, using poll-only",
				"error", err)
			return
		}
		slog.Info("watch: subscribed to vault events")
		delay = time.Second // reset on a successful connect

	consume:
		for {
			select {
			case <-ctx.Done():
				return
			case evt, ok := <-eventCh:
				if !ok {
					slog.Warn("watch: event channel closed, will reconnect")
					break consume
				}
				m.dispatchEvent(evt)
			case err, ok := <-errCh:
				if ok && err != nil {
					slog.Warn("watch: event subscription error, will reconnect", "error", err)
					break consume
				}
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay *= 2
		if delay > maxDelay {
			delay = maxDelay
		}
	}
}

// dispatchEvent maps an incoming Vault data-write event to the
// enrolment(s) whose declared source paths it matches and pushes a
// per-key trigger onto triggerCh. Events that don't match any
// configured source are silently ignored.
func (m *WatchManager) dispatchEvent(evt vault.Event) {
	m.mu.Lock()
	snapshot := make(map[string]config.Enrolment, len(m.enrolments))
	for k, v := range m.enrolments {
		snapshot[k] = v
	}
	m.mu.Unlock()

	for key, enrolment := range snapshot {
		engine, ok := GetEngine(enrolment.Engine)
		if !ok {
			continue
		}
		watcher, ok := engine.(Watcher)
		if !ok {
			continue
		}
		for _, src := range watcher.WatchSources(enrolment.Settings, m.username) {
			if eventMatchesSource(evt, src) {
				select {
				case m.triggerCh <- key:
				default:
					// A trigger for this enrolment is already pending; the
					// next tick will consume it and re-evaluate, so dropping
					// a duplicate is safe.
				}
				break
			}
		}
	}
}

// eventMatchesSource reports whether the given Vault event refers to
// the same KVv2 path as the source. Vault's MountPath includes a
// trailing slash and the Path is stripped of the "data/" segment, so
// this is straightforward equality after trimming.
func eventMatchesSource(evt vault.Event, src WatchSource) bool {
	mount := strings.Trim(evt.MountPath, "/")
	if mount != src.Mount {
		return false
	}
	return evt.Path == src.Path
}

// tickAll evaluates every Watcher enrolment.
func (m *WatchManager) tickAll(ctx context.Context) {
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
		if m.inBackoff(key, now) {
			continue
		}
		m.tickOneWithEnrolment(ctx, key, enrolment)
	}
}

// tickOne evaluates a single Watcher enrolment by key.
func (m *WatchManager) tickOne(ctx context.Context, key string) {
	m.mu.Lock()
	enrolment, ok := m.enrolments[key]
	m.mu.Unlock()
	if !ok {
		return
	}
	m.tickOneWithEnrolment(ctx, key, enrolment)
}

func (m *WatchManager) tickOneWithEnrolment(ctx context.Context, key string, enrolment config.Enrolment) {
	engine, ok := GetEngine(enrolment.Engine)
	if !ok {
		return
	}
	if _, ok := engine.(Watcher); !ok {
		return
	}

	vaultPath := m.userPrefix + key
	io := m.io
	if io.Log == nil {
		io.Log = slog.Default()
	}
	if io.Out == nil {
		io.Out = iolib.Discard
	}
	io.Vault = m.client
	io.KVMount = m.kvMount
	io.Username = m.username
	io.TargetPath = vaultPath
	// Capture but discard engine output: the engine logs through Log,
	// and we don't want re-runs to spam the wizard's stdout.
	if _, ok := io.Out.(*bytes.Buffer); !ok {
		io.Out = iolib.Discard
	}

	creds, err := engine.Run(ctx, enrolment.Settings, io)
	if err != nil {
		slog.Warn("watch: engine run failed, will retry", "key", key, "engine", enrolment.Engine, "error", err)
		m.bumpBackoff(key)
		return
	}

	data := make(map[string]any, len(creds))
	for k, v := range creds {
		data[k] = v
	}
	if !HasAllFields(data, EngineFields(engine, enrolment.Settings)) {
		slog.Warn("watch: engine returned incomplete credentials, will retry", "key", key)
		m.bumpBackoff(key)
		return
	}

	// Skip the write if the target already matches what the engine
	// produced — saves a Vault round-trip and avoids creating an
	// otherwise-identical KVv2 version on each tick.
	existing, err := m.client.ReadKVv2(ctx, m.kvMount, vaultPath)
	if err != nil {
		slog.Warn("watch: failed to read target for diff, will retry", "key", key, "error", err)
		m.bumpBackoff(key)
		return
	}
	if existing != nil && targetMatches(existing.Data, data) {
		m.resetBackoff(key)
		return
	}

	if err := m.client.WriteKVv2(ctx, m.kvMount, vaultPath, data); err != nil {
		slog.Warn("watch: failed to write target, will retry", "key", key, "error", err)
		m.bumpBackoff(key)
		return
	}

	slog.Info("watch: target updated from upstream source", "key", key, "engine", enrolment.Engine)
	m.resetBackoff(key)
}

// targetMatches reports whether the existing Vault data already
// contains every key from desired with the same string value. Extra
// keys in existing are ignored — the engine's merge already preserves
// them, and another writer may have added unrelated fields concurrently
// that we shouldn't clobber. We only need every desired key present
// with the right value to declare a no-op.
func targetMatches(existing, desired map[string]any) bool {
	for k, v := range desired {
		ev, ok := existing[k]
		if !ok {
			return false
		}
		if !reflect.DeepEqual(v, ev) {
			// Coerce both to strings as a fallback: KVv2 round-trips
			// every value as a string, but in tests a fake client
			// might keep the typed value, so DeepEqual misses the
			// match. Compare string forms before declaring a diff.
			if fmt.Sprintf("%v", v) != fmt.Sprintf("%v", ev) {
				return false
			}
		}
	}
	return true
}

func (m *WatchManager) inBackoff(key string, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.backoffs[key]
	if !ok {
		return false
	}
	return now.Before(s.nextAttempt)
}

func (m *WatchManager) bumpBackoff(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.backoffs[key]
	if s.delay == 0 {
		s.delay = m.pollInterval
	} else {
		s.delay *= 2
	}
	if s.delay > m.maxBackoff {
		s.delay = m.maxBackoff
	}
	s.nextAttempt = m.clock.Now().Add(s.delay)
	m.backoffs[key] = s
}

func (m *WatchManager) resetBackoff(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.backoffs, key)
}
