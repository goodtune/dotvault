//go:build darwin

package agent

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the uid of the process on the other end of a Unix-domain
// connection, via LOCAL_PEERCRED. See the linux build for why the check is
// made against the connection rather than the path.
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
		cred    *unix.Xucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil || credErr != nil || cred == nil {
		return 0, false
	}
	return cred.Uid, true
}

// peerCredentialsAvailable reports whether peerUID can actually answer on this
// platform. It is what lets shared code state the trust model honestly instead
// of assuming the strongest one everywhere; see warnRelayDetectionTrust.
const peerCredentialsAvailable = true
