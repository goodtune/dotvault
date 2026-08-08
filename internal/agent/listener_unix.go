//go:build !windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
//
// A systemd-activated fd (FileDescriptorName=agent, from the packaged
// dotvault-agent.socket unit) takes precedence over self-binding: systemd
// bound it before we started and keeps it across our restarts, so SSH
// clients queue instead of failing while the daemon is down. An activation
// error is fatal — the fd violates an invariant (mode, type) and
// self-binding would mask the misconfiguration while failing anyway, since
// systemd owns the path.
func (l *Listener) platformListen() (net.Listener, error) {
	aln, actual, err := activatedAgentListener()
	if err != nil {
		return nil, fmt.Errorf("agent socket (systemd activation): %w", err)
	}
	if aln != nil {
		l.mu.Lock()
		if actual != l.addr {
			// The socket unit's ListenStream=, not the configured path,
			// decides where the socket lives under activation. Adopt the
			// truth so Addr()/Endpoint() (and therefore `dotvault status`,
			// which dials the reported endpoint) point at the socket that
			// actually exists.
			slog.Warn("systemd-activated agent socket path differs from the configured path; the socket unit wins", "activated", actual, "configured", l.addr)
			l.addr = actual
		}
		// systemd owns the node: platformCleanup must not unlink it out
		// from under the socket unit on our shutdown.
		l.activated = true
		l.mu.Unlock()
		return aln, nil
	}

	ln, err := uds.Listen(l.addr)
	if errors.Is(err, uds.ErrAlreadyListening) {
		return nil, fmt.Errorf("dotvault agent already running at %s", l.addr)
	}
	if err != nil {
		return nil, fmt.Errorf("agent socket: %w", err)
	}
	return ln, nil
}

// activatedAgentListener claims the systemd-activated "agent" socket, when
// one exists. Injectable for tests (the activation snapshot is
// process-global and once-guarded, so it cannot be faked in-process); the
// production value re-claims from the retained master on every call, which
// is what lets the supervision loop's re-Serve after a listener failure get
// a working listener again.
var activatedAgentListener = func() (net.Listener, string, error) {
	return uds.ActivatedListener("agent")
}

// pageantPipeName is Windows-only; the Pageant named-pipe convention has no
// Unix analogue. resolveServeEndpoints never calls this off Windows (it gates
// on runtime.GOOS first), but the symbol must exist for the package to build.
func pageantPipeName() (string, error) {
	return "", fmt.Errorf("pageant pipe is only supported on windows")
}

// platformCleanup removes the socket file. net.UnixListener.Close already
// unlinks it in the common case; this is a best-effort backstop for paths it
// doesn't (e.g. a bind that failed after creating the node). A
// systemd-activated socket is exempt: the node belongs to the socket unit,
// which keeps serving it across our restarts, and unlinking it would leave
// systemd listening on an inode no client can reach.
func (l *Listener) platformCleanup() {
	l.mu.Lock()
	activated := l.activated
	l.mu.Unlock()
	if activated {
		return
	}
	uds.Cleanup(l.addr)
}
