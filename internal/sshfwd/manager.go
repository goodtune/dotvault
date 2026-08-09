package sshfwd

import (
	"context"
	"fmt"
	"sort"
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

	mu      sync.Mutex
	remotes map[string]*ManagedRemote

	// newRunner is the goroutine body for a managed remote, injected so
	// reconciliation is testable without an SSH server.
	newRunner func(host string) func(context.Context)
}

// NewManager returns a Manager with no remotes running.
func NewManager(d Deps) *Manager {
	m := &Manager{deps: d, remotes: map[string]*ManagedRemote{}}
	return m
}

// Reconcile brings the running set in line with remotes: unchanged entries keep
// running untouched, new ones start, removed ones stop, changed ones restart.
// A disabled entry is treated as removed but retains a status row so the user
// can see it is configured-but-off rather than missing.
func (m *Manager) Reconcile(ctx context.Context, remotes []Remote) error {
	for _, r := range remotes {
		if err := ValidateRemote(r); err != nil {
			return fmt.Errorf("remote %q: %w", r.Host, err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	desired := make(map[string]Remote, len(remotes))
	for _, r := range remotes {
		desired[r.Host] = r
	}

	for host, mr := range m.remotes {
		want, ok := desired[host]
		if !ok || !want.EnabledOrDefault() || mr.cfg != want {
			mr.stop()
			delete(m.remotes, host)
		}
	}

	for host, r := range desired {
		if _, ok := m.remotes[host]; ok {
			continue
		}
		mr := newManagedRemote(r, m.deps)
		if !r.EnabledOrDefault() {
			mr.setState(StateDisabled, nil)
			m.remotes[host] = mr
			continue
		}
		run := mr.run
		if m.newRunner != nil {
			run = m.newRunner(host)
		}
		mr.start(ctx, run)
		m.remotes[host] = mr
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

// Close stops every managed remote and waits for them to finish.
func (m *Manager) Close() {
	m.mu.Lock()
	remotes := make([]*ManagedRemote, 0, len(m.remotes))
	for host, mr := range m.remotes {
		remotes = append(remotes, mr)
		delete(m.remotes, host)
	}
	m.mu.Unlock()

	for _, mr := range remotes {
		mr.stop()
	}
}
