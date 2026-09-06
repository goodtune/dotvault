//go:build !linux && !darwin

package agent

import "net"

// peerUID has no implementation on this platform, so it reports "unknown"
// (ok == false) and every caller falls back to whatever weaker evidence it
// has. That is a deliberate fail-*open*: the alternative — treating "cannot
// ask" as "not ours" — would disable upstream detection wholesale on a
// platform where the risk it addresses may not even exist (Windows named pipes
// are not filesystem paths and carry no symlink race).
//
// The consequence is stated where it matters rather than assumed: see
// candidateEndpoints in discover_windows.go for what Windows relies on
// instead, and docs/guide/ssh-agent.md for the residual risk.
func peerUID(net.Conn) (uid uint32, ok bool) { return 0, false }
