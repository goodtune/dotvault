// Package uds creates per-user Unix domain socket listeners with dotvault's
// owner-only permission invariant.
//
// dotvault serves two independent surfaces over a Unix socket — the SSH agent
// (internal/agent) and the local API socket (internal/web) — and both carry
// live credential material: the agent signs with keys derived from the Vault
// token, and the API socket hands out the Vault token itself. The bind
// sequence that keeps them owner-only is fiddly enough (0700 parent, stale
// socket detection that must not clobber a live instance, bind-then-chmod
// rather than a umask swap) that having two copies would let them drift. This
// package is the single implementation.
package uds

import (
	"errors"
	"net"
)

// ErrAlreadyListening is returned by Listen when a live process is already
// accepting connections on the requested path. Callers wrap it with a message
// naming their own surface ("dotvault agent already running at …") — the
// remedy differs per surface, but the detection must not.
var ErrAlreadyListening = errors.New("another process is already listening on the socket")

// ErrUnsupported is returned by Listen on platforms where dotvault does not
// serve Unix domain sockets (Windows, which uses named pipes instead).
var ErrUnsupported = errors.New("unix domain sockets are not supported on this platform")

// DrainListener accepts and immediately closes every connection on ln until
// the listener dies. It is the honest refusal available for a socket whose
// listening fd something else retains — systemd, under socket activation —
// where merely closing our own dup refuses nobody: clients would still
// connect into a backlog nobody accepts and hang there. Drained, each one
// fails fast with EOF. Exported for a surface that claimed an activated fd
// and then could not start (the Docker volume plugin's Run), which must not
// leave the fd kept-but-unserved; the unclaimed-fd housekeeping uses it too.
func DrainListener(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Close()
	}
}
