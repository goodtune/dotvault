//go:build !windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/goodtune/dotvault/internal/uds"
)

// dialEndpoint connects to an existing agent endpoint as a client. It never
// creates the socket — `dotvault status` must observe the running daemon, not
// stand up a competing listener.
func dialEndpoint(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", addr)
}

// platformListen creates the Unix domain socket with 0600 permissions and a
// 0700 parent directory, refusing to clobber a socket a live instance still
// owns. The bind sequence is shared with the local API socket
// (internal/web) via internal/uds so the owner-only invariant has exactly one
// implementation; only the already-running message is agent-specific, because
// the remedy an operator needs differs per surface.
func (l *Listener) platformListen() (net.Listener, error) {
	ln, err := uds.Listen(l.addr)
	if errors.Is(err, uds.ErrAlreadyListening) {
		return nil, fmt.Errorf("dotvault agent already running at %s", l.addr)
	}
	if err != nil {
		return nil, fmt.Errorf("agent socket: %w", err)
	}
	return ln, nil
}

// pageantPipeName is Windows-only; the Pageant named-pipe convention has no
// Unix analogue. resolveServeEndpoints never calls this off Windows (it gates
// on runtime.GOOS first), but the symbol must exist for the package to build.
func pageantPipeName() (string, error) {
	return "", fmt.Errorf("pageant pipe is only supported on windows")
}

// platformCleanup removes the socket file. net.UnixListener.Close already
// unlinks it in the common case; this is a best-effort backstop for paths it
// doesn't (e.g. a bind that failed after creating the node).
func (l *Listener) platformCleanup() {
	uds.Cleanup(l.addr)
}
