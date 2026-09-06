//go:build linux

package agent

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the uid of the process on the other end of a Unix-domain
// connection, via SO_PEERCRED. ok is false when the connection is not a Unix
// socket or the kernel would not answer.
//
// This is the check that actually protects the fan-out, and it is deliberately
// made against the *connection in use* rather than the path it was reached
// through. A path check answers "who owned this name a moment ago", which is
// not the same question: with the /tmp glob among the candidates, a local
// attacker can point a symlink at the victim's real agent so the path check
// passes, then re-point it before the dial. Since mutations are forwarded, the
// endpoint that wins that race receives the private key from an `ssh-add`.
// There is no such gap here — the credentials belong to the socket this
// connection is already attached to, so nothing can be swapped underneath it.
func peerUID(conn net.Conn) (uid uint32, ok bool) {
	uc, isUnix := conn.(*net.UnixConn)
	if !isUnix {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var (
		cred    *unix.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil || cred == nil {
		return 0, false
	}
	return cred.Uid, true
}

// peerCredentialsAvailable reports whether peerUID can actually answer on this
// platform. It is what lets shared code state the trust model honestly instead
// of assuming the strongest one everywhere; see warnRelayDetectionTrust.
const peerCredentialsAvailable = true
