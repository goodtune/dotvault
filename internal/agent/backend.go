package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ReauthGate lets the backend observe the daemon's token-lifecycle state so a
// Sign issued mid-reauth waits briefly rather than failing. *auth.LifecycleManager
// satisfies it.
type ReauthGate interface {
	NeedsReauth() bool
}

// gateHolder wraps a ReauthGate so it can live in an atomic.Value. atomic.Value
// panics if successive Stores use different concrete types; wrapping every gate
// in this single struct type keeps the stored type stable regardless of which
// ReauthGate implementation (the real LifecycleManager, a test stub) is wired.
type gateHolder struct{ gate ReauthGate }

const (
	defaultListCacheTTL  = 8 * time.Second
	defaultReauthTimeout = 30 * time.Second
)

// Backend is the platform-neutral agent.ExtendedAgent served by both
// listeners. It is safe for concurrent use: List results are cached behind a
// short TTL and every Sign is serviced independently.
type Backend struct {
	sources  []Source
	endpoint string

	// gate holds a gateHolder. It is read on every Sign and written by
	// SetReauthGate (which the daemon calls after construction, before the
	// listener accepts connections). The atomic.Value makes that wiring safe
	// against a concurrent Sign rather than relying on the happens-before being
	// obvious to a future caller.
	gate          atomic.Value
	reauthTimeout time.Duration
	cacheTTL      time.Duration
	now           func() time.Time

	mu       sync.Mutex
	cached   []Identity
	cachedAt time.Time
}

// Option configures a Backend.
type Option func(*Backend)

// WithReauthGate wires the token-lifecycle gate used to block Sign briefly
// during a re-authentication window.
func WithReauthGate(g ReauthGate) Option { return func(b *Backend) { b.setGate(g) } }

// SetReauthGate wires the gate after construction. Safe to call concurrently
// with Sign — the store is atomic — though in practice the daemon sets it once,
// before the listener begins accepting connections. A nil argument is a no-op
// (the gate cannot be un-wired); nothing relies on clearing it.
func (b *Backend) SetReauthGate(g ReauthGate) { b.setGate(g) }

// setGate stores the gate, ignoring a nil so WithReauthGate(nil) (the headless
// / no-lifecycle case) leaves the backend gate-less rather than boxing a nil.
func (b *Backend) setGate(g ReauthGate) {
	if g != nil {
		b.gate.Store(gateHolder{gate: g})
	}
}

// reauthGate returns the wired gate, or nil if none has been set.
func (b *Backend) reauthGate() ReauthGate {
	if h, ok := b.gate.Load().(gateHolder); ok {
		return h.gate
	}
	return nil
}

// WithReauthTimeout bounds how long Sign waits for re-auth to clear.
func WithReauthTimeout(d time.Duration) Option {
	return func(b *Backend) {
		if d > 0 {
			b.reauthTimeout = d
		}
	}
}

// WithCacheTTL sets the List cache window.
func WithCacheTTL(d time.Duration) Option {
	return func(b *Backend) {
		if d > 0 {
			b.cacheTTL = d
		}
	}
}

// WithEndpoint records the listen address for status reporting.
func WithEndpoint(addr string) Option { return func(b *Backend) { b.endpoint = addr } }

// withClock overrides the time source (tests).
func withClock(fn func() time.Time) Option { return func(b *Backend) { b.now = fn } }

// NewBackend builds a backend over the given ordered sources.
func NewBackend(sources []Source, opts ...Option) *Backend {
	b := &Backend{
		sources:       sources,
		reauthTimeout: defaultReauthTimeout,
		cacheTTL:      defaultListCacheTTL,
		now:           time.Now,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// identities returns the aggregated identities, refreshing from every source
// when the cache has expired. Sources that error are skipped (logged at debug)
// so one failing source does not blank the whole agent.
func (b *Backend) identities(ctx context.Context) []Identity {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cached != nil && b.now().Sub(b.cachedAt) < b.cacheTTL {
		return b.cached
	}
	var all []Identity
	for _, src := range b.sources {
		ids, err := src.Identities(ctx)
		if err != nil {
			slog.Debug("ssh agent: source failed to list identities", "source", src.Name(), "error", err)
			continue
		}
		all = append(all, ids...)
	}
	b.cached = all
	b.cachedAt = b.now()
	return all
}

// List enumerates the available identities (cached briefly).
func (b *Backend) List() ([]*agent.Key, error) {
	ids := b.identities(context.Background())
	keys := make([]*agent.Key, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, &agent.Key{
			Format:  id.PubKey.Type(),
			Blob:    id.PubKey.Marshal(),
			Comment: id.Comment,
		})
	}
	return keys, nil
}

// Sign signs data with the key, defaulting the signature algorithm.
func (b *Backend) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return b.SignWithFlags(key, data, 0)
}

// SignWithFlags matches key to a source and signs data, honouring the
// rsa-sha2 flags. If the daemon is mid-reauth it waits up to reauthTimeout for
// a usable token before failing.
func (b *Backend) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	ctx, cancel := context.WithTimeout(context.Background(), b.reauthTimeout)
	defer cancel()

	if err := b.waitForToken(ctx); err != nil {
		return nil, err
	}

	for _, src := range b.sources {
		sig, matched, err := src.Sign(ctx, key, data, flags)
		if err != nil {
			return nil, fmt.Errorf("ssh agent: sign via %s: %w", src.Name(), err)
		}
		if matched {
			return sig, nil
		}
	}
	return nil, fmt.Errorf("ssh agent: %w", ErrKeyNotFound)
}

// waitForToken blocks while the lifecycle manager reports a re-auth in
// progress, up to the deadline carried by ctx. Without a gate it returns
// immediately.
func (b *Backend) waitForToken(ctx context.Context) error {
	gate := b.reauthGate()
	if gate == nil || !gate.NeedsReauth() {
		return nil
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("ssh agent: vault token unavailable (re-auth in progress): %w", ctx.Err())
		case <-ticker.C:
			if !gate.NeedsReauth() {
				return nil
			}
		}
	}
}

// ErrKeyNotFound is returned by Sign when no source owns the requested key.
var ErrKeyNotFound = fmt.Errorf("no matching key")

// --- read-only surface: dotvault is one-way, so the agent is too. ---

func (b *Backend) Add(key agent.AddedKey) error   { return ErrReadOnly }
func (b *Backend) Remove(key ssh.PublicKey) error { return ErrReadOnly }
func (b *Backend) RemoveAll() error               { return ErrReadOnly }
func (b *Backend) Lock(passphrase []byte) error   { return ErrReadOnly }
func (b *Backend) Unlock(passphrase []byte) error { return ErrReadOnly }
func (b *Backend) Signers() ([]ssh.Signer, error) { return nil, ErrReadOnly }

// Extension reports no extensions are supported.
func (b *Backend) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
