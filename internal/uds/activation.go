package uds

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// systemd socket activation (sd_listen_fds), hand-rolled like
// internal/sdnotify rather than imported: the protocol is three environment
// variables and a file-descriptor convention, and dotvault's rule for every
// socket it serves — owner-only or nothing — has to be enforced on *inherited*
// fds too, which a stock helper does not do.
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

// listenFdsStart is SD_LISTEN_FDS_START: the first inherited listener fd.
// Fixed by the sd_listen_fds contract, not configurable.
const listenFdsStart = 3

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

// parseActivation interprets the sd_listen_fds environment triplet and
// claims the inherited fds.
//
// It returns nil (no error) when activation is not in effect: LISTEN_FDS
// absent, or LISTEN_PID naming a different process — the latter is the
// protocol's own rule, since the variables may have been inherited from a
// parent that was the real activation target. Malformed values are an error
// rather than a silent nil: under a socket unit, misreading the environment
// means serving nothing while systemd believes we hold the fds, which
// deserves a loud failure.
//
// fileAt adopts fd number listenFdsStart+i; it is a parameter so tests can
// substitute real listeners at arbitrary fd numbers (a test cannot arrange
// for its fds to sit at exactly 3..n). The contract callers rely on: once
// the fd *count* has parsed, fileAt runs for every fd BEFORE the names are
// validated, so the production hook's CLOEXEC scrub covers fds addressed to
// us even when LISTEN_FDNAMES turns out to be malformed — those fds must
// not leak into exec'd children just because the name list was garbled. On
// a name error the claimed files are closed and the error returned.
func parseActivation(listenPid, listenFds, listenFdNames string, ourPid int, fileAt func(i int) *os.File) (map[string][]*os.File, error) {
	if listenFds == "" {
		return nil, nil
	}
	pid, err := strconv.Atoi(listenPid)
	if err != nil {
		return nil, fmt.Errorf("LISTEN_PID %q is not a PID", listenPid)
	}
	if pid != ourPid {
		// Addressed to another process (our parent, typically). Per the
		// protocol, not ours to touch.
		return nil, nil
	}
	n, err := strconv.Atoi(listenFds)
	if err != nil || n < 0 {
		return nil, fmt.Errorf("LISTEN_FDS %q is not a count", listenFds)
	}
	if n == 0 {
		return nil, nil
	}

	// Claim every fd first — see the fileAt contract above.
	files := make([]*os.File, n)
	for i := range files {
		files[i] = fileAt(i)
	}

	// LISTEN_FDNAMES is colon-separated, one entry per fd. systemd sends the
	// FileDescriptorName= of each socket unit; an fd with no name (a unit
	// without the setting, or systemd < 227 which does not send names at
	// all) is "unknown" per the protocol. dotvault claims fds strictly by
	// name, so "unknown" entries are never consumed — the daemon drains
	// them with a warning naming the fix (set FileDescriptorName= in the
	// socket unit).
	names := make([]string, n)
	for i := range names {
		names[i] = "unknown"
	}
	if listenFdNames != "" {
		split := strings.Split(listenFdNames, ":")
		if len(split) != n {
			for _, f := range files {
				f.Close()
			}
			return nil, fmt.Errorf("LISTEN_FDNAMES carries %d names for %d fds", len(split), n)
		}
		copy(names, split)
	}

	byName := make(map[string][]*os.File, n)
	for i, name := range names {
		byName[name] = append(byName[name], files[i])
	}
	return byName, nil
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
