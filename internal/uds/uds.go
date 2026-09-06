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

import "errors"

// ErrAlreadyListening is returned by Listen when a live process is already
// accepting connections on the requested path. Callers wrap it with a message
// naming their own surface ("dotvault agent already running at …") — the
// remedy differs per surface, but the detection must not.
var ErrAlreadyListening = errors.New("another process is already listening on the socket")

// ErrUnsupported is returned by Listen on platforms where dotvault does not
// serve Unix domain sockets (Windows, which uses named pipes instead).
var ErrUnsupported = errors.New("unix domain sockets are not supported on this platform")
