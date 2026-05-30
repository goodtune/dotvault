//go:build windows

package agent

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
)

// agentPipeSDDL is the security descriptor applied to the named pipe. Windows
// has no per-user protected subspace in the pipe namespace, so the ACL is the
// lock — the Unix-socket-0600 equivalent. It is a protected DACL (P, no
// inheritance) granting Generic All only to the creating user (OW = Owner
// Rights, S-1-3-4) and LocalSystem (SY); no ACE for Everyone or Authenticated
// Users, so no other principal can open the pipe.
const agentPipeSDDL = "D:P(A;;GA;;;OW)(A;;GA;;;SY)"

// platformListen creates the named pipe in byte mode (the agent protocol
// carries its own length-prefixed framing) with the owner-only security
// descriptor applied at creation time.
func (l *Listener) platformListen() (net.Listener, error) {
	cfg := &winio.PipeConfig{
		SecurityDescriptor: agentPipeSDDL,
		MessageMode:        false,
	}
	ln, err := winio.ListenPipe(l.addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("listen pipe %s: %w", l.addr, err)
	}
	return ln, nil
}

// platformCleanup is a no-op on Windows: closing the pipe listener releases the
// namespace entry, there is no filesystem node to unlink.
func (l *Listener) platformCleanup() {}
