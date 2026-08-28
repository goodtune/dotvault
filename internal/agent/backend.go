package agent

import (
	"context"
	"errors"
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

	// hasToken reports whether the daemon currently holds a Vault token. It
	// is what lets the listener run before the daemon has authenticated: an
	// agent that answers "no identities" instantly is one an ssh client moves
	// straight past, where an endpoint nothing accepts leaves that client
	// blocked with no timeout of its own. Nil means "no opinion" (a Backend
	// built without a probe, as in tests) and is treated as having a token,
	// so nothing has to wire it to behave as before.
	hasToken func() bool

	// gate holds a gateHolder. It is read on every Sign and written by
	// SetReauthGate, which the daemon calls once the lifecycle manager exists
	// — after authentication, and so under an already-accepting listener,
	// since the listener now starts before auth. The atomic.Value is what
	// makes that wiring safe against a concurrent Sign; it is load-bearing
	// rather than defensive.
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

// SetReauthGate wires the gate after construction. The daemon sets it once,
// when the lifecycle manager comes up — by which point the listener is already
// accepting connections, so a concurrent Sign is a real possibility and the
// atomic store is what makes this safe. A nil argument is a no-op (the gate
// cannot be un-wired); nothing relies on clearing it.
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

// WithTokenProbe wires the predicate reporting whether the daemon holds a
// Vault token. Without one the backend assumes it does.
func WithTokenProbe(fn func() bool) Option { return func(b *Backend) { b.hasToken = fn } }

// haveToken reports whether a Vault token is available for the sources to use.
// A backend with no probe wired has no opinion and answers true.
func (b *Backend) haveToken() bool { return b.hasToken == nil || b.hasToken() }

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
// when the cache has expired. It performs the Vault work; the two answers that
// need no Vault call at all are served ahead of it by identitiesWithoutVault.
//
// A source that errors is skipped so one failing source does not blank the
// whole agent — but the failure is not discarded:
//
//   - If other sources produced identities, the partial list is returned and
//     NOT cached. Caching it would pin a listing that is missing a source for
//     the whole TTL, long after the cause had cleared.
//   - If every source failed, the joined error is returned instead of an empty
//     list. "This source hit a transient error" and "nothing is configured"
//     are different answers, and an agent client cannot act on the first if it
//     is told the second: a caller that sees zero identities reasonably gives
//     up, where one that sees an error can retry. The motivating case is a
//     vault-ca source whose mint lands inside a token-replacement window —
//     hundreds of milliseconds during which the whole agent used to report
//     itself as having no keys at all.
//
// The cache and token checks are repeated here rather than trusted from the
// caller: a concurrent List may have refreshed the cache, or the token may
// have gone away, while this call waited on the re-auth gate.
func (b *Backend) identities(ctx context.Context) ([]Identity, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cached != nil && b.now().Sub(b.cachedAt) < b.cacheTTL {
		return b.cached, nil
	}
	if !b.haveToken() {
		return nil, nil
	}
	var all []Identity
	var errs []error
	for _, src := range b.sources {
		ids, err := src.Identities(ctx)
		if err != nil {
			slog.Debug("ssh agent: source failed to list identities", "source", src.Name(), "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", src.Name(), err))
			continue
		}
		all = append(all, ids...)
	}
	if len(errs) > 0 {
		if len(all) == 0 {
			return nil, fmt.Errorf("ssh agent: %w", errors.Join(errs...))
		}
		return all, nil
	}
	b.cached = all
	b.cachedAt = b.now()
	return all, nil
}

// identitiesWithoutVault returns the answer that is available without
// consulting any source, reporting done=true when it found one. A refresh is
// required otherwise.
//
// Both answers it can give are owed to the caller *immediately*, which is why
// they are separated out and taken before the re-auth gate:
//
//   - A cache still inside its TTL. The token check deliberately sits after
//     it, because web mode clears the in-memory token on the re-auth
//     transition, so a token going missing is routinely a refresh rather than
//     a logout, and a still-fresh list must keep being served through it.
//   - The empty list a daemon with no token owes. There is nothing any source
//     could resolve, so the round of doomed Vault calls is skipped and the
//     cache left untouched, letting the first List after a token arrives do a
//     real refresh.
//
// Neither path touches Vault, so neither can present a half-replaced token —
// which is what makes it safe to answer them without waiting out a re-auth,
// and necessary to: an ssh client reads the identity list before it picks a
// key, so a List that stalls costs the connection just as surely as one that
// comes back blank.
func (b *Backend) identitiesWithoutVault() (ids []Identity, done bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cached != nil && b.now().Sub(b.cachedAt) < b.cacheTTL {
		return b.cached, true
	}
	if !b.haveToken() {
		return nil, true
	}
	return nil, false
}

// List enumerates the available identities (cached briefly).
//
// A refresh waits out a re-authentication window, as SignWithFlags does: List
// is what an SSH client calls before choosing a key, so refreshing from a
// half-replaced token turns a pause into a failed connection. The answers that
// need no refresh are served first and never wait — see
// identitiesWithoutVault.
//
// It waits on waitForReauth rather than waitForToken: an unauthenticated
// daemon owes an empty list, not the ErrNoToken that Sign owes, so that the
// client moves on to its next authentication method. A source failure that
// leaves nothing to advertise is still an error — see identities.
func (b *Backend) List() ([]*agent.Key, error) {
	ids, done := b.identitiesWithoutVault()
	if !done {
		ctx, cancel := context.WithTimeout(context.Background(), b.reauthTimeout)
		defer cancel()
		if err := b.waitForReauth(ctx); err != nil {
			return nil, err
		}
		var err error
		if ids, err = b.identities(ctx); err != nil {
			return nil, err
		}
	}
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
//
// A source that errors (e.g. a vault-ca source whose role can't currently
// mint) is skipped rather than aborting the whole call, mirroring
// identities(): a source's own failure must not deny signing for a key owned
// by a different, healthy source. The error only surfaces if no source ends
// up matching the key, so a genuine "no source can produce this signature"
// case still reports why.
func (b *Backend) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	ctx, cancel := context.WithTimeout(context.Background(), b.reauthTimeout)
	defer cancel()

	if err := b.waitForToken(ctx); err != nil {
		return nil, err
	}

	var errs []error
	for _, src := range b.sources {
		sig, matched, err := src.Sign(ctx, key, data, flags)
		if err != nil {
			slog.Debug("ssh agent: source failed to sign", "source", src.Name(), "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", src.Name(), err))
			continue
		}
		if matched {
			return sig, nil
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("ssh agent: %w", errors.Join(errs...))
	}
	return nil, fmt.Errorf("ssh agent: %w", ErrKeyNotFound)
}

// waitForToken blocks while the lifecycle manager reports a re-auth in
// progress, up to the deadline carried by ctx, then requires that a token
// actually be present. Without a gate there is nothing to wait for and only
// the presence check applies.
//
// The two are distinct conditions and the order matters. A re-auth in progress
// is transient — a signature issued in that window should wait it out rather
// than fail — whereas a daemon that has never authenticated (the listener now
// runs before the first login) has no token and no re-auth underway, so it
// must fail immediately: waiting the full reauthTimeout would reintroduce, at
// 30s a time, exactly the stall this path exists to avoid.
func (b *Backend) waitForToken(ctx context.Context) error {
	if err := b.waitForReauth(ctx); err != nil {
		return err
	}
	if !b.haveToken() {
		return fmt.Errorf("ssh agent: %w", ErrNoToken)
	}
	return nil
}

// waitForReauth blocks while the lifecycle gate reports a re-auth in progress,
// up to the deadline carried by ctx. Without a gate it returns immediately.
func (b *Backend) waitForReauth(ctx context.Context) error {
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

// ErrNoToken is returned by Sign when the daemon is serving the agent but
// holds no Vault token — it has not authenticated yet, or its token expired
// and could not be replaced. Answering plainly is the point: the client gets a
// refusal it can act on instead of a connection nobody accepts.
var ErrNoToken = errors.New("dotvault holds no vault token (not authenticated); run `dotvault login`")

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
