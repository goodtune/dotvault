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

// RejectionReporter lets the backend report a Vault-confirmed token rejection
// it observed independently of the daemon's own token-lifecycle poll — a
// vault-ca source's certificate mint hitting a 403 is the motivating case —
// so recovery starts now instead of waiting out that poll's own check
// interval (5 minutes by default). *auth.LifecycleManager satisfies it via
// NotifyRejected, which classifies the error itself, so this side needs no
// classification of its own: every source error is reported unconditionally
// and a transient fault (Vault unreachable, sealed) is simply ignored on the
// other end.
//
// This is the write side of the relationship ReauthGate is the read side of:
// the backend waits on the gate before using a token mid-replacement, and
// reports here when it independently discovers the token is bad. The two are
// deliberately separate interfaces (mirroring LifecycleManager's own
// NeedsReauth/ReauthSignalled split) — a component that only ever waits (a
// test stub wired as a ReauthGate) is not obligated to also implement this.
type RejectionReporter interface {
	NotifyRejected(err error)
}

// reporterHolder wraps a RejectionReporter for the same atomic.Value reason
// gateHolder wraps a ReauthGate.
type reporterHolder struct{ reporter RejectionReporter }

const (
	defaultListCacheTTL  = 8 * time.Second
	defaultReauthTimeout = 30 * time.Second

	// defaultSourceTimeout bounds the Vault work itself — a source fan-out for
	// List, a signature for Sign — and is deliberately a *separate* budget from
	// reauthTimeout rather than a share of it. Spending one budget on both
	// would mean a replacement that cleared at the 29th second left nothing for
	// the work it had been waiting to do, turning a successful recovery into a
	// deadline-exceeded failure at the last moment.
	defaultSourceTimeout = 30 * time.Second
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
	sourceTimeout time.Duration
	cacheTTL      time.Duration
	now           func() time.Time

	// reporter holds a reporterHolder, wired the same way and at the same
	// time as gate (SetReauthGate and SetReauthReporter are called together
	// in cmd/dotvault, once the lifecycle manager exists). Read whenever a
	// source reports an error from identities/SignWithFlags, so a rejection
	// this backend discovers independently reaches the lifecycle manager's
	// recovery path instead of sitting unacted on until its next poll.
	reporter atomic.Value

	// mu guards the cache fields only, and is never held across a source
	// call. refreshMu serialises the fan-out itself. Splitting them is what
	// makes cachedIdentities' "never waits" true: with one mutex, a
	// cache hit queued behind an in-flight refresh for as long as the refresh
	// took — up to sourceTimeout — which is exactly the stall that answering
	// from cache exists to avoid. Lock order is always refreshMu then mu;
	// nothing takes them the other way round.
	mu       sync.Mutex
	cached   []Identity
	cachedAt time.Time

	refreshMu sync.Mutex
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

// WithReauthReporter wires the rejection reporter used to notify the
// lifecycle manager of a Vault rejection a source discovers independently.
func WithReauthReporter(r RejectionReporter) Option {
	return func(b *Backend) { b.setReporter(r) }
}

// SetReauthReporter wires the reporter after construction, mirroring
// SetReauthGate — the daemon calls both together once the lifecycle manager
// exists. A nil argument is a no-op; nothing relies on clearing it.
func (b *Backend) SetReauthReporter(r RejectionReporter) { b.setReporter(r) }

// setReporter stores the reporter, ignoring a nil so WithReauthReporter(nil)
// (the headless / no-lifecycle case, and every test that doesn't care) leaves
// the backend reporter-less rather than boxing a nil.
func (b *Backend) setReporter(r RejectionReporter) {
	if r != nil {
		b.reporter.Store(reporterHolder{reporter: r})
	}
}

// reportRejection forwards err to the wired reporter, a no-op if none is set.
// Every source error from identities/SignWithFlags is reported unconditionally
// — classification of "is this actually a rejection, or a transient fault"
// belongs to the reporter (LifecycleManager.NotifyRejected), which already
// owns that predicate for its own checkAndRenew path. Duplicating it here
// would risk the two classifications drifting apart.
//
// Logs at debug regardless of whether the reporter's own classification
// accepts or discards it — the caller (identities/SignWithFlags) already
// logged the source failure itself; this line is what lets that failure be
// correlated with "and it was forwarded to the lifecycle manager", which
// otherwise has no visible trace on this side of the interface.
func (b *Backend) reportRejection(err error) {
	h, ok := b.reporter.Load().(reporterHolder)
	if !ok || h.reporter == nil {
		return
	}
	slog.Debug("ssh agent: reporting source failure to the token lifecycle manager", "error", err)
	h.reporter.NotifyRejected(err)
}

// WithReauthTimeout bounds how long Sign waits for re-auth to clear.
func WithReauthTimeout(d time.Duration) Option {
	return func(b *Backend) {
		if d > 0 {
			b.reauthTimeout = d
		}
	}
}

// WithSourceTimeout bounds the Vault work a List or Sign performs, separately
// from the re-auth wait that may precede it.
func WithSourceTimeout(d time.Duration) Option {
	return func(b *Backend) {
		if d > 0 {
			b.sourceTimeout = d
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
		sourceTimeout: defaultSourceTimeout,
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
// need no Vault call at all are handled around it: a fresh cache by
// cachedIdentities, and a tokenless daemon by the probe below.
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
// have gone away, while this call waited on the re-auth gate or on refreshMu.
func (b *Backend) identities(ctx context.Context) ([]Identity, error) {
	// One refresh at a time. The re-check that follows is what collapses a
	// thundering herd: callers that queued here while another was fanning out
	// take its result rather than repeating the work — and, when that work
	// failed and cached nothing, they would otherwise each redo the whole
	// doomed fan-out in turn.
	b.refreshMu.Lock()
	defer b.refreshMu.Unlock()
	if ids, ok := b.cachedIdentities(); ok {
		return ids, nil
	}
	// Without a token, consult only the sources that need none. That is not
	// the same as consulting nothing: the upstream-agent proxy holds no Vault
	// credential, so a daemon that has not authenticated (or cannot) must
	// still serve the user's own agents through it — otherwise pointing every
	// client permanently at dotvault would make an unreachable Vault take the
	// legacy keys down with it. Vault-backed sources are skipped exactly as
	// before, so the "answer instantly, make no doomed Vault calls" property
	// the probe exists for is unchanged.
	sources, reduced := b.usableSources()
	if len(sources) == 0 {
		return nil, nil
	}

	var all []Identity
	var errs []error
	for _, src := range sources {
		ids, err := src.Identities(ctx)
		if err != nil {
			slog.Debug("ssh agent: source failed to list identities", "source", src.Name(), "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", src.Name(), err))
			// Report unconditionally — a vault-ca mint's 403 is exactly the
			// case this exists for, and a transient fault (Vault
			// unreachable, sealed) is filtered out on the reporter's side
			// (LifecycleManager.NotifyRejected), not here. See
			// RejectionReporter.
			b.reportRejection(err)
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
	if reduced {
		// A listing assembled from only the token-independent sources is
		// missing the Vault-backed ones, for the same reason a partial listing
		// above is not cached: holding it would keep those keys hidden for a
		// TTL after a token arrives, when the whole point is that the first
		// List afterwards does a real refresh.
		return all, nil
	}
	b.mu.Lock()
	b.cached = all
	b.cachedAt = b.now()
	b.mu.Unlock()
	return all, nil
}

// usableSources returns the sources that can be consulted right now, and
// whether the set was narrowed because no Vault token is held.
func (b *Backend) usableSources() (sources []Source, reduced bool) {
	if b.haveToken() {
		return b.sources, false
	}
	for _, src := range b.sources {
		if !sourceNeedsToken(src) {
			sources = append(sources, src)
		}
	}
	return sources, true
}

// cachedIdentities returns the cached listing while it is still inside its
// TTL. It is the one answer List can give without any Vault call at all, and
// so the one it never makes anyone wait for.
//
// It deliberately does not consider the token. Web mode clears the in-memory
// token on the re-auth transition, so a token going missing is routinely a
// refresh rather than a logout, and a still-fresh list must keep being served
// through it: a blank `ssh-add -l` makes ssh drop dotvault's keys before it
// ever reaches Sign, which is the call that knows how to wait. The token check
// belongs after this one, in identities, where a refresh is actually about to
// happen.
func (b *Backend) cachedIdentities() ([]Identity, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cached != nil && b.now().Sub(b.cachedAt) < b.cacheTTL {
		return b.cached, true
	}
	return nil, false
}

// gatedContext waits out a token replacement using the caller's wait — List
// and Sign owe different answers to an unauthenticated daemon, so each passes
// its own — and then returns a context budgeted for the Vault work that
// follows, along with its cancel func.
//
// The two budgets are separate on purpose — see defaultSourceTimeout. Callers
// must call cancel when the returned error is nil.
func (b *Backend) gatedContext(wait func(context.Context) error) (context.Context, context.CancelFunc, error) {
	waitCtx, cancelWait := context.WithTimeout(context.Background(), b.reauthTimeout)
	defer cancelWait()
	if err := wait(waitCtx); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), b.sourceTimeout)
	return ctx, cancel, nil
}

// List enumerates the available identities (cached briefly).
//
// A cache still inside its TTL is served immediately and never waits, because
// it needs no Vault call and so cannot be built from a half-replaced token —
// see cachedIdentities. Anything else is a refresh, and a refresh waits out a
// re-authentication window as SignWithFlags does: List is what an SSH client
// calls before choosing a key, so rebuilding that list from a token Vault has
// already rejected turns a pause into a failed connection.
//
// Waiting *before* the token probe is deliberate, and it is why the probe sits
// in identities rather than out here. An absent token means two different
// things: mid-replacement, where it is transient and about to come back, and
// never-authenticated (or logged out), where nothing is coming. The gate is
// what tells them apart, so the first waits and then refreshes normally, while
// the second falls through the probe to an empty list at once — no gate is
// wired before the daemon's first login, so that path never stalls.
//
// It waits on waitForReauth rather than waitForToken: if the token is still
// absent afterwards an unauthenticated daemon owes an empty list, not the
// ErrNoToken that Sign owes, so the client moves on to its next authentication
// method rather than treating dotvault as broken. A source failure that leaves
// nothing to advertise is still an error — see identities.
func (b *Backend) List() ([]*agent.Key, error) {
	ids, ok := b.cachedIdentities()
	if !ok {
		ctx, cancel, err := b.gatedContext(b.waitForReauth)
		if err != nil {
			return nil, err
		}
		defer cancel()
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
	ctx, cancel, err := b.gatedContext(b.waitForReauth)
	if err != nil {
		return nil, err
	}
	defer cancel()

	// Waiting on waitForReauth rather than waitForToken, then narrowing, is
	// what lets a token-independent source sign on an unauthenticated daemon.
	// The re-auth wait itself is unchanged — a signature issued mid-replacement
	// still waits it out — and a config with only Vault-backed sources still
	// gets ErrNoToken immediately rather than stalling, because the narrowed
	// set is then empty.
	sources, _ := b.usableSources()
	if len(sources) == 0 {
		return nil, fmt.Errorf("ssh agent: %w", ErrNoToken)
	}

	var errs []error
	for _, src := range sources {
		sig, matched, err := src.Sign(ctx, key, data, flags)
		if err != nil {
			slog.Debug("ssh agent: source failed to sign", "source", src.Name(), "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", src.Name(), err))
			// See the matching call in identities: reported unconditionally,
			// classified on the reporter's side.
			b.reportRejection(err)
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

// --- mutating surface: forwarded to an upstream agent, else read-only. ---
//
// dotvault's own identities come from Vault and are never added, removed, or
// locked by a client, so with no upstream configured every operation below is
// ErrReadOnly exactly as before. With one configured they are proxied to the
// agent dotvault shadows, which is what lets a user point their clients at the
// dotvault endpoint permanently instead of switching SSH_AUTH_SOCK back and
// forth to run an `ssh-add`.
//
// None of these wait on the Vault token or the re-auth gate the way List and
// Sign do. They touch no Vault-backed source by definition — the only source
// that can serve them is the upstream proxy — so making them block on a token
// dotvault does not need would strand `ssh-add` on an unauthenticated daemon
// for no benefit. They take the source timeout alone.

// mutatingSources returns the sources that accept mutations, in config order.
func (b *Backend) mutatingSources() []MutatingSource {
	var out []MutatingSource
	for _, src := range b.sources {
		if ms, ok := src.(MutatingSource); ok {
			out = append(out, ms)
		}
	}
	return out
}

// mutationContext bounds a forwarded mutation. See the note above on why this
// is the source timeout alone and not gatedContext.
func (b *Backend) mutationContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), b.sourceTimeout)
}

// invalidate drops the cached listing so a mutation is visible to the very
// next List rather than up to a cache TTL later — `ssh-add` followed
// immediately by `ssh-add -l` is the normal way a user checks it worked.
func (b *Backend) invalidate() {
	b.mu.Lock()
	b.cached = nil
	b.cachedAt = time.Time{}
	b.mu.Unlock()
}

// Add forwards a key to the first source that accepts one — the upstream
// agent. Nothing is written to disk or to Vault on this path.
func (b *Backend) Add(key agent.AddedKey) error {
	srcs := b.mutatingSources()
	if len(srcs) == 0 {
		return ErrReadOnly
	}
	ctx, cancel := b.mutationContext()
	defer cancel()

	// The first mutating source, and only it. Falling through on failure would
	// hand the private key to a source the user did not name — the same
	// objection as fanning out, arrived at by a different route.
	src := srcs[0]
	if err := src.Add(ctx, key); err != nil {
		return fmt.Errorf("ssh agent: %s: %w", src.Name(), err)
	}
	b.invalidate()
	return nil
}

// Remove deletes a key from whichever upstream holds it. A key no upstream
// owns — a Vault-backed identity, or one that was never here — is ErrReadOnly:
// the client asked for something dotvault will not do, and saying so is more
// useful than a success that removed nothing.
func (b *Backend) Remove(key ssh.PublicKey) error {
	srcs := b.mutatingSources()
	if len(srcs) == 0 {
		return ErrReadOnly
	}
	ctx, cancel := b.mutationContext()
	defer cancel()

	var errs []error
	for _, src := range srcs {
		matched, err := src.Remove(ctx, key)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", src.Name(), err))
			continue
		}
		if matched {
			b.invalidate()
			return nil
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("ssh agent: %w", errors.Join(errs...))
	}
	return ErrReadOnly
}

// RemoveAll clears every upstream agent. dotvault's own identities are
// untouched — they are not the agent's to delete and would return from Vault
// regardless — so this means for the shadowed agent exactly what it would have
// meant addressed directly.
func (b *Backend) RemoveAll() error {
	return b.broadcast(func(ctx context.Context, src MutatingSource) error { return src.RemoveAll(ctx) }, true)
}

// Lock locks every upstream agent. dotvault's own identities are governed by
// the Vault token rather than a passphrase, so they are unaffected.
func (b *Backend) Lock(passphrase []byte) error {
	// Invalidates, like the removals: a locked agent advertises nothing, so a
	// cache held over from before would keep offering keys that can no longer
	// sign — `ssh-add -x` followed by `ssh-add -l` must show the lock took.
	return b.broadcast(func(ctx context.Context, src MutatingSource) error { return src.Lock(ctx, passphrase) }, true)
}

// Unlock unlocks every upstream agent.
func (b *Backend) Unlock(passphrase []byte) error {
	// Invalidates for the mirror-image reason to Lock: the keys are available
	// again and the cache from the locked window says otherwise.
	return b.broadcast(func(ctx context.Context, src MutatingSource) error { return src.Unlock(ctx, passphrase) }, true)
}

// broadcast applies an agent-wide operation to every mutating source, joining
// the failures. Unlike Add these are not key-scoped, so every shadowed agent
// is addressed: a client locking "the agent" means all of what it serves.
func (b *Backend) broadcast(op func(context.Context, MutatingSource) error, invalidates bool) error {
	srcs := b.mutatingSources()
	if len(srcs) == 0 {
		return ErrReadOnly
	}
	ctx, cancel := b.mutationContext()
	defer cancel()

	var errs []error
	for _, src := range srcs {
		if err := op(ctx, src); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", src.Name(), err))
		}
	}
	if invalidates {
		b.invalidate()
	}
	if len(errs) > 0 {
		return fmt.Errorf("ssh agent: %w", errors.Join(errs...))
	}
	return nil
}

// Signers stays read-only regardless of the upstream. It is a client-side
// convenience on agent.Agent with no wire representation — the agent protocol
// has no "give me your signers" request — so there is nothing to forward and
// nothing a remote caller can reach it through.
func (b *Backend) Signers() ([]ssh.Signer, error) { return nil, ErrReadOnly }

// Extension answers dotvault's own identity probe and nothing else.
//
// Extensions are deliberately not forwarded upstream. Some are connection-
// scoped by design — OpenSSH's session-bind@openssh.com binds the *client's*
// connection to a session, and answering it from a proxied connection to a
// different agent would be a lie about what was bound — and a blanket forward
// would extend dotvault's surface to whatever the upstream implements without
// anyone having reasoned about it. Refusing is a valid, expected answer:
// clients treat SSH_AGENT_FAILURE here as "unsupported" and move on.
//
// IDExtension is the exception because it is about this process rather than
// about any agent's keys: it is how upstream discovery recognises a candidate
// endpoint as this very daemon reached under another path, and so how the
// delegation loop is prevented. See IDExtension.
func (b *Backend) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType == IDExtension {
		return processAgentID, nil
	}
	return nil, agent.ErrExtensionUnsupported
}
