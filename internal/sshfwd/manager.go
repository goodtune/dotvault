package sshfwd

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Deps are the daemon-supplied capabilities a managed remote needs. They are
// funcs rather than values because each is re-resolved per connection attempt:
// a Vault-CA certificate rotated since the last dial must be picked up on the
// next one without any cache of its own.
type Deps struct {
	Signers    func() ([]ssh.Signer, error)
	User       func() (string, error)
	Target     Dialer
	TargetName string

	// Policy returns *HostKeyPolicy, not a value: the policy carries a
	// mutex-guarded CA-parse cache (see hostkey.go), and copying it would
	// both trip go vet's copylocks check and silently defeat the cache by
	// handing every dial its own never-populated copy.
	Policy func(Remote) *HostKeyPolicy
}

// Manager reconciles the set of managed remotes against the configured list.
//
// Reconciliation is deliberately isolated from every trigger that can cause it
// — daemon startup, the config-refresh loop, an API mutation, a test — so all
// four enter through one door and none can drift.
type Manager struct {
	deps Deps

	// base is the lifetime every runner's context derives from. It is
	// captured once, at construction, and is deliberately NOT the context a
	// caller passes to Reconcile: an API mutation reconciles under the HTTP
	// request's context, which Go cancels the moment the handler returns, so
	// deriving runner lifetimes from it killed every remote a `dotvault ssh
	// add` (or web add) started — permanently, because the entry stayed in
	// m.remotes with cfg.sameAs matching and every later Reconcile therefore
	// saw it as unchanged and never restarted it. The daemon's own context is
	// the correct parent: shutdown still stops everything, and no shorter-lived
	// caller can truncate a connection that is meant to outlive its request.
	base context.Context

	mu      sync.Mutex
	remotes map[string]*ManagedRemote
	closed  bool

	// newRunner is the goroutine body for a managed remote, injected so
	// reconciliation is testable without an SSH server.
	newRunner func(host string) func(context.Context)
}

// NewManager returns a Manager with no remotes running. base is the lifetime
// every managed connection is bound to — pass the daemon's context, not a
// per-request one; see Manager.base. A nil base is treated as
// context.Background(), so a Manager built without one never starts a runner
// under an already-cancelled context.
func NewManager(base context.Context, d Deps) *Manager {
	if base == nil {
		base = context.Background()
	}
	m := &Manager{deps: d, base: base, remotes: map[string]*ManagedRemote{}}
	return m
}

// normalizeHost is the map-key form of a Remote's identity: lower-cased, to
// match File.Find's case-insensitive host matching (config.go). Two entries
// differing only in case name the same connection, not two different ones.
func normalizeHost(host string) string { return strings.ToLower(host) }

// Reconcile brings the running set in line with remotes: unchanged entries keep
// running untouched, new ones start, removed ones stop, changed ones restart.
// A disabled entry is treated as removed but retains a status row so the user
// can see it is configured-but-off rather than missing.
//
// ctx bounds Reconcile's own work only — it is NOT the lifetime of the
// connections it starts. Those derive from the Manager's base context (see
// Manager.base), so an API mutation reconciling under an HTTP request context
// does not hand every remote it starts a lifetime that ends when the handler
// returns.
//
// Safe to call concurrently with itself, with Status, and with Close: a
// Reconcile that arrives after Close has run is rejected outright rather than
// silently repopulating a manager that has already told its caller it is
// done, which would otherwise start goroutines nothing will ever stop.
func (m *Manager) Reconcile(ctx context.Context, remotes []Remote) error {
	for _, r := range remotes {
		if err := ValidateRemote(r); err != nil {
			return fmt.Errorf("remote %q: %w", r.Host, err)
		}
	}

	desired := make(map[string]Remote, len(remotes))
	for _, r := range remotes {
		key := normalizeHost(r.Host)
		if dup, ok := desired[key]; ok {
			return fmt.Errorf("duplicate remote host %q and %q: host is case-insensitive and must be unique", dup.Host, r.Host)
		}
		desired[key] = r
	}

	// Reconcile is three phases, not two, specifically so a changed remote's
	// outgoing connection is fully stopped before its replacement starts:
	//
	//  1. Lock, decide which remotes are victims (removed, disabled, or
	//     changed), delete them from the map, unlock.
	//  2. Stop the victims — outside the lock, since a stuck dial handshake
	//     (Dial's is not ctx-interruptible — see dial.go) can hold this up
	//     for a while, and Status() must not be blocked behind it.
	//  3. Lock again, re-check closed (Close or another Reconcile may have
	//     run during phase 2), start the additions — new remotes and the
	//     replacements for anything phase 1 removed — unlock.
	//
	// An earlier two-phase version stopped victims after unlocking but
	// started additions inside the same first critical section, so a
	// changed remote's replacement began dialling — and, for an unchanged
	// host/socket, tried to bind the same remote socket — while the outgoing
	// connection was still live. That surfaced as a spurious "a live
	// listener already owns this path" failure (Task 9's stale-socket probe
	// correctly refusing to unlink a socket a real listener still owns) on
	// every config edit that changed a running remote, self-healing on the
	// next backoff tick but never something a user should see for an
	// ordinary re-pin.
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return fmt.Errorf("sshfwd: Reconcile called after Close")
	}

	var toStop []*ManagedRemote
	for key, mr := range m.remotes {
		want, ok := desired[key]
		switch {
		case !ok:
			toStop = append(toStop, mr)
			delete(m.remotes, key)
		case !want.EnabledOrDefault():
			// A remote already sitting disabled, with nothing else about it
			// changed, is left alone: recreating it would discard its status
			// row for no observable benefit. Anything that actually changed
			// (was running, or its config differs) still goes through
			// stop-then-recreate below so the disabled placeholder reflects
			// the new config.
			if mr.isRunning() || !mr.cfg.sameAs(want) {
				toStop = append(toStop, mr)
				delete(m.remotes, key)
			}
		case !mr.cfg.sameAs(want):
			toStop = append(toStop, mr)
			delete(m.remotes, key)
		}
	}
	m.mu.Unlock()

	for _, mr := range toStop {
		mr.stop()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		// Close ran while phase 2 was stopping victims. There is nothing to
		// resurrect: the victims are already stopped and stay out of the
		// map, and starting the additions now would be exactly the
		// resurrection-after-Close case the closed flag exists to prevent.
		return fmt.Errorf("sshfwd: Reconcile called after Close")
	}
	for key, r := range desired {
		if _, ok := m.remotes[key]; ok {
			continue
		}
		mr := newManagedRemote(r, m.deps)
		if !r.EnabledOrDefault() {
			mr.setState(StateDisabled, nil)
			m.remotes[key] = mr
			continue
		}
		run := mr.run
		if m.newRunner != nil {
			run = m.newRunner(r.Host)
		}
		mr.start(m.base, run)
		m.remotes[key] = mr
	}
	return nil
}

// Status returns a snapshot of every managed remote, ordered by host so CLI
// output is stable between invocations.
func (m *Manager) Status() []RemoteStatus {
	m.mu.Lock()
	out := make([]RemoteStatus, 0, len(m.remotes))
	for _, mr := range m.remotes {
		out = append(out, mr.status(m.deps.TargetName))
	}
	m.mu.Unlock()

	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// Close stops every managed remote and waits for them to finish. A Manager
// is not reusable after Close: a subsequent Reconcile is rejected rather than
// resurrecting remotes into a manager whose owner has already been told
// shutdown is complete.
//
// The remotes are stopped concurrently, not one after another. Each stop() is
// independent — it cancels that remote's own context and waits on that
// remote's own WaitGroup — so serialising them made shutdown cost the sum of
// every remote's teardown when it need only cost the slowest one. That is
// visible on any real machine with more than one configured remote, since a
// teardown is never instant (an in-flight dial, an identity resolution, a
// connection's forwarding goroutines winding down).
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	remotes := make([]*ManagedRemote, 0, len(m.remotes))
	for host, mr := range m.remotes {
		remotes = append(remotes, mr)
		delete(m.remotes, host)
	}
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, mr := range remotes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mr.stop()
		}()
	}
	wg.Wait()
}
