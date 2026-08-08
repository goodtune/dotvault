//go:build linux

package uds

import (
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/coreos/go-systemd/v22/activation"
)

var (
	activationOnce sync.Once
	activated      *activationState
)

// snapshotActivation claims the sd_listen_fds environment exactly once, via
// go-systemd's activation package, which owns the protocol mechanics:
// LISTEN_PID matching (variables inherited from a parent that was the real
// target are ignored), CLOEXEC on every inherited fd, and unsetting
// LISTEN_FDS/LISTEN_PID/LISTEN_FDNAMES. Both scrubs matter to dotvault
// specifically because it execs children (the clipboard writers, the
// enrolment engines) that must inherit neither live listening sockets nor
// variables claiming fds 3..n are theirs — which is also why the snapshot
// is taken eagerly on first touch rather than lazily per name: it runs
// whether or not any surface consumes a listener.
//
// Each file's Name() carries the socket unit's FileDescriptorName=. An fd
// without one (a unit missing the setting, or systemd < 227, which sends
// no names) arrives as the library's "LISTEN_FD_<n>" placeholder; dotvault
// claims strictly by name, so those are never consumed and end up drained
// by DrainUnclaimedActivation with a warning naming the fix.
//
// Library semantics adopted knowingly: a garbled LISTEN_PID/LISTEN_FDS
// reads as "no activation" rather than a loud error, and a garbled name
// list degrades to placeholder names rather than aborting. Neither failure
// is silent in practice — unclaimed placeholder names are drained with a
// warning, and a daemon that claims nothing self-binds and immediately
// trips over systemd's live socket with an "already serving" error — but
// the messages name the symptom, not the garbled environment.
func snapshotActivation() {
	activationOnce.Do(func() {
		files := activation.Files(true)
		if len(files) == 0 {
			return
		}
		byName := make(map[string][]*os.File, len(files))
		for _, f := range files {
			byName[f.Name()] = append(byName[f.Name()], f)
		}
		activated = &activationState{byName: byName}
	})
}

// ActivatedListener returns a listener for the systemd-activated fd carrying
// FileDescriptorName name, together with the socket's actual filesystem path
// (from getsockname, so it is authoritative even when the socket unit's
// ListenStream= disagrees with dotvault's configured path). It returns
// (nil, "", nil) when socket activation is not in effect or passes nothing
// under that name — the caller falls through to its normal self-bind.
//
// Claims are repeatable: the inherited fd is a retained master and each call
// hands out a fresh dup, so a surface that tears its listener down and
// re-listens (the SSH agent's supervision loop does exactly this) gets a
// working listener again instead of finding the fd consumed and
// self-binding against the systemd-owned path.
//
// A non-nil error is a refusal and callers must treat it as fatal for the
// surface: the fd exists but violates an invariant (mode wider than 0600,
// loose or foreign-owned parent directory, not a unix stream socket).
// Falling back to a self-bind on error would be wrong twice over — it would
// paper over a unit misconfiguration the operator needs to see, and systemd
// still owns the path.
func ActivatedListener(name string) (net.Listener, string, error) {
	snapshotActivation()
	m := activated.master(name)
	if m == nil {
		return nil, "", nil
	}
	return adoptActivated(name, m)
}

// DrainUnclaimedActivation deals with activated fds whose names no enabled
// surface will claim — an "api" fd on a daemon with api.enabled false, an
// unnamed "LISTEN_FD_<n>" fd from a socket unit missing
// FileDescriptorName=. Each one is adopted and *drained*: connections are
// accepted and closed immediately, so clients fail fast with EOF. Merely
// closing our dup would refuse no one — systemd retains its own copy of
// the listening fd, so clients would still connect into a backlog nobody
// accepts and hang indefinitely. The warning is the operability half: the
// mismatch is a configuration disagreement only the operator can resolve.
//
// keep lists the names enabled surfaces claim, now or later — the daemon
// calls this once at startup, and the SSH agent does not take its listener
// until after the first successful Vault auth, so "claimed" cannot be
// inferred from the snapshot alone.
func DrainUnclaimedActivation(keep ...string) {
	snapshotActivation()
	kept := make(map[string]bool, len(keep))
	for _, k := range keep {
		kept[k] = true
	}
	for _, name := range activated.unclaimedNames() {
		if kept[name] {
			continue
		}
		m := activated.master(name) // marks it claimed so this runs once
		ln, err := net.FileListener(m)
		if err != nil {
			slog.Warn("systemd passed an unusable fd dotvault is not configured to serve", "name", name, "error", err)
			continue
		}
		slog.Warn("systemd passed a socket dotvault is not configured to serve; draining it so clients fail fast instead of hanging in the backlog",
			"name", name,
			"hint", "disable the socket unit, enable the matching dotvault surface, or set FileDescriptorName= if the name looks like LISTEN_FD_<n>")
		go drainListener(ln)
	}
}
