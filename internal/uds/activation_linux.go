//go:build linux

package uds

import (
	"log/slog"
	"net"
	"os"
	"sync"
	"syscall"
)

var (
	activationOnce     sync.Once
	activation         *activationState
	activationParseErr error
)

// snapshotActivation reads the sd_listen_fds environment exactly once,
// claims the inherited fds as process-lifetime masters, and scrubs the
// process state:
//
//   - CLOEXEC is set on every inherited fd the moment its count is known,
//     before the name list is even validated. systemd necessarily passes
//     the fds without it (they had to survive the exec into us), so until
//     this runs every child dotvault spawns — the clipboard writers, the
//     enrolment engines — would inherit live listening sockets. A garbled
//     LISTEN_FDNAMES must not leave the fds unscrubbed.
//   - LISTEN_FDS / LISTEN_PID / LISTEN_FDNAMES are unset, for the same
//     reason: a child seeing them would believe fds 3..n are its own.
//
// Both scrubs run regardless of whether any surface consumes a listener,
// which is why the snapshot is taken eagerly on first touch rather than
// lazily per name. A malformed environment is remembered and surfaced on
// every consumption attempt (and by DrainUnclaimedActivation) rather than
// swallowed — under a socket unit, silently serving nothing while systemd
// believes we hold the fds is the worst outcome available.
func snapshotActivation() {
	activationOnce.Do(func() {
		listenPid := os.Getenv("LISTEN_PID")
		listenFds := os.Getenv("LISTEN_FDS")
		listenFdNames := os.Getenv("LISTEN_FDNAMES")
		os.Unsetenv("LISTEN_PID")
		os.Unsetenv("LISTEN_FDS")
		os.Unsetenv("LISTEN_FDNAMES")

		byName, err := parseActivation(listenPid, listenFds, listenFdNames, os.Getpid(), func(i int) *os.File {
			fd := listenFdsStart + i
			syscall.CloseOnExec(fd)
			return os.NewFile(uintptr(fd), "systemd-activated-fd")
		})
		if err != nil {
			activationParseErr = err
			return
		}
		if byName != nil {
			activation = &activationState{byName: byName}
		}
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
// surface: either the environment is malformed, or the fd exists but
// violates an invariant (mode wider than 0600, loose or foreign-owned
// parent directory, not a unix stream socket). Falling back to a self-bind
// on error would be wrong twice over — it would paper over a unit
// misconfiguration the operator needs to see, and systemd still owns the
// path.
func ActivatedListener(name string) (net.Listener, string, error) {
	snapshotActivation()
	if activationParseErr != nil {
		return nil, "", activationParseErr
	}
	m := activation.master(name)
	if m == nil {
		return nil, "", nil
	}
	return adoptActivated(name, m)
}

// DrainUnclaimedActivation deals with activated fds whose names no enabled
// surface will claim — an "api" fd on a daemon with api.enabled false, an
// "unknown" fd from a socket unit missing FileDescriptorName=. Each one is
// adopted and *drained*: connections are accepted and closed immediately,
// so clients fail fast with EOF. Merely closing our dup would refuse
// no one — systemd retains its own copy of the listening fd, so clients
// would still connect into a backlog nobody accepts and hang indefinitely.
// The warning is the operability half: the mismatch is a configuration
// disagreement only the operator can resolve.
//
// keep lists the names enabled surfaces claim, now or later — the daemon
// calls this once at startup, and the SSH agent does not take its listener
// until after the first successful Vault auth, so "claimed" cannot be
// inferred from the snapshot alone.
func DrainUnclaimedActivation(keep ...string) {
	snapshotActivation()
	if activationParseErr != nil {
		// Claims by enabled surfaces will fail loudly with this same error;
		// this covers the daemon shape with no socket surface enabled at
		// all, which would otherwise swallow it.
		slog.Warn("systemd socket activation environment is malformed; inherited sockets will not be served", "error", activationParseErr)
		return
	}
	kept := make(map[string]bool, len(keep))
	for _, k := range keep {
		kept[k] = true
	}
	for _, name := range activation.unclaimedNames() {
		if kept[name] {
			continue
		}
		m := activation.master(name) // marks it claimed so this runs once
		ln, err := net.FileListener(m)
		if err != nil {
			slog.Warn("systemd passed an unusable fd dotvault is not configured to serve", "name", name, "error", err)
			continue
		}
		slog.Warn("systemd passed a socket dotvault is not configured to serve; draining it so clients fail fast instead of hanging in the backlog",
			"name", name,
			"hint", "disable the socket unit, enable the matching dotvault surface, or set FileDescriptorName= if the name is \"unknown\"")
		go drainListener(ln)
	}
}
