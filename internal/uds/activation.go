package uds

import (
	"os"
	"sort"
	"sync"
)

// systemd socket activation (sd_listen_fds). The protocol layer — parsing
// LISTEN_FDS/LISTEN_PID/LISTEN_FDNAMES, setting CLOEXEC on the inherited
// fds, scrubbing the environment — comes from the canonical
// github.com/coreos/go-systemd/v22 activation package (see
// activation_linux.go); owning a bespoke copy of an ecosystem-standard
// protocol was judged not worth it. What remains here is everything the
// library deliberately does not do: dotvault's rule that every socket it
// serves is owner-only or nothing, enforced on *inherited* fds
// (activation_unix.go), and the retained-master claim model below.
//
// The daemon consumes this through ActivatedListener("api") /
// ActivatedListener("agent"), matching the FileDescriptorName= set in the
// packaged dotvault-api.socket / dotvault-agent.socket units. Activation is
// strictly optional: with no LISTEN_FDS in the environment every call reports
// "no activation" and the self-bind path in Listen runs exactly as before.
// systemd holding the listening fd is what makes a daemon restart transparent
// to clients — connections queue in the backlog instead of failing — and it
// is Linux-only by nature (launchd has its own, incompatible convention; see
// activation_other.go).
//
// The inherited fds are retained as process-lifetime masters, and every
// ActivatedListener call hands out a fresh dup (net.FileListener duplicates
// internally). That is load-bearing, not a convenience: the SSH agent's
// supervision loop tears its listener down and calls platformListen again
// after an unexpected failure, and under a consume-once model the retry
// would find the fd gone, fall through to a self-bind against the
// systemd-owned path, and loop forever on "already running" while clients
// hang in systemd's backlog. Re-claiming from the retained master makes a
// listener restart under activation behave exactly like one under self-bind.

// activationState is the one-time snapshot of the activation environment:
// the inherited fds as retained master files, keyed by FileDescriptorName.
//
// The mutex is not decorative. The web server claims "api" on its Start
// goroutine while the SSH agent claims "agent" from its own serve goroutine
// (and re-claims on listener restart); today's daemon start-up ordering
// happens to serialise the first claims, but nothing structural enforces
// that, and a lock-free map mutation is a data race the moment it drifts.
type activationState struct {
	mu sync.Mutex
	// byName holds the retained masters. Entries are never removed: masters
	// live for the process lifetime so claims are repeatable.
	byName map[string][]*os.File
	// claimed marks names some surface has adopted, so unclaimed-fd
	// housekeeping (DrainUnclaimedActivation) can tell "enabled surface owns
	// this" from "nobody will ever serve this".
	claimed map[string]bool
}

// master returns the retained master file for name — marking the name
// claimed — or nil when activation is off or carries nothing under that
// name. The master stays open and owned by the snapshot; callers adopt it
// via net.FileListener (which dups) and must never close it.
func (s *activationState) master(name string) *os.File {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	files := s.byName[name]
	if len(files) == 0 {
		return nil
	}
	if s.claimed == nil {
		s.claimed = make(map[string]bool)
	}
	s.claimed[name] = true
	return files[0]
}

// unclaimedNames lists names no surface has claimed, sorted for stable logs.
func (s *activationState) unclaimedNames() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for name := range s.byName {
		if !s.claimed[name] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
