package sshfwd

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeSSHDConfig configures the in-memory sshd (real TCP loopback, no
// external process) shared by liveprobe_test.go and verify_test.go. Both
// need a fake sshd for a different reason — one to script
// direct-streamlocal@openssh.com channel-open decisions, the other to dial
// through Verify's real Dial()+HostKeyPolicy path — so only what actually
// differs between them is parameterised here; everything else (auth,
// session/exec, the streamlocal-forward/cancel-streamlocal-forward global
// requests ListenUnix/Close send) is identical and was previously
// duplicated between the two files.
type fakeSSHDConfig struct {
	// signer is the host key (or a certificate wrapping one, via
	// ssh.NewCertSigner) presented during the handshake. Nil generates a
	// fresh ed25519 key per call.
	signer ssh.Signer

	// home is written as the sole line of stdout for every "exec" session,
	// satisfying ExpandRemotePath's "echo $HOME" probe. Empty is fine for a
	// caller that only runs commands whose output is never read (e.g.
	// liveprobe_test.go's rm -f probes).
	home string

	// onDirectStreamLocal handles a direct-streamlocal@openssh.com
	// channel-open. Nil rejects every one with UnknownChannelType, matching
	// an sshd this package never dials the bound socket through.
	onDirectStreamLocal func(newCh ssh.NewChannel)

	// refuseStreamlocalForward makes the FIRST streamlocal-forward@openssh.com
	// global request (ListenUnix) fail, simulating AllowStreamLocalForwarding
	// no or an unwritable remote path for the caller's own socket — the
	// failure *shape* ListenUnix sees, not the real sshd directive (that
	// needs Task 17's live server). Every later streamlocal-forward request
	// on the same connection succeeds: a diagnostic that reacts to the first
	// failure by binding a second, scratch path (liveListenerAt's
	// directStreamLocalWorks, forward.go) needs that second bind to work so
	// its own behaviour — including whatever cleanup it runs — can be
	// observed and asserted on.
	refuseStreamlocalForward bool

	// sawExec records, if non-nil, the command line of every "exec" request
	// this connection serves — used to assert that a caller's flow never
	// runs a remote command it has no business running (e.g. Verify's
	// contract 5: no stale-socket rm -f on a bind failure). It records the
	// commands rather than only counting them because a bare count cannot
	// tell a command that is meant to run from one that is not: the count
	// changes whenever a legitimate command is added to a flow, forcing the
	// assertion to be relaxed and quietly weakening the guard it exists to
	// be.
	sawExec *execRecorder
}

// execRecorder collects the exec command lines a fake sshd connection
// serves. Guarded by a mutex because the recording happens on a server
// goroutine and the assertions on the test goroutine.
type execRecorder struct {
	mu   sync.Mutex
	cmds []string
}

func (r *execRecorder) record(cmd string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cmds = append(r.cmds, cmd)
}

// commands returns a copy of what has been recorded so far.
func (r *execRecorder) commands() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.cmds...)
}

// matching returns the recorded commands containing substr.
func (r *execRecorder) matching(substr string) []string {
	var out []string
	for _, cmd := range r.commands() {
		if strings.Contains(cmd, substr) {
			out = append(out, cmd)
		}
	}
	return out
}

// serveFakeSSHDConn serves one accepted connection as an in-memory sshd
// configured by cfg. NoClientAuth: nothing in this package checks the
// offered credential server-side; Dial's own auth-method wiring is what's
// under test, not sshd's acceptance of it.
func serveFakeSSHDConn(conn net.Conn, cfg fakeSSHDConfig) {
	signer := cfg.signer
	if signer == nil {
		// Every current caller supplies a signer (startFakeSSHD defaults it
		// when cfg.signer is nil before ever reaching here;
		// dialFakeStreamlocalServer always passes its own), but
		// ServerConfig.AddHostKey panics on a nil Signer rather than
		// returning an error — defend here too so a future caller's mistake
		// fails the specific test cleanly instead of taking down the whole
		// run.
		var err error
		_, priv, kerr := ed25519.GenerateKey(rand.Reader)
		if kerr != nil {
			return
		}
		signer, err = ssh.NewSignerFromSigner(priv)
		if err != nil {
			return
		}
	}

	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)

	_, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}

	go func() {
		var forwardCalls int
		for req := range reqs {
			switch req.Type {
			case "streamlocal-forward@openssh.com":
				forwardCalls++
				ok := !(cfg.refuseStreamlocalForward && forwardCalls == 1)
				if req.WantReply {
					req.Reply(ok, nil)
				}
			case "cancel-streamlocal-forward@openssh.com":
				if req.WantReply {
					req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}()

	for newCh := range chans {
		switch newCh.ChannelType() {
		case "direct-streamlocal@openssh.com":
			if cfg.onDirectStreamLocal != nil {
				cfg.onDirectStreamLocal(newCh)
				continue
			}
			newCh.Reject(ssh.UnknownChannelType, "unsupported in this fake server")
		case "session":
			ch, chReqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			go func() {
				for r := range chReqs {
					if r.Type == "exec" {
						if cfg.sawExec != nil {
							var payload struct{ Command string }
							// A malformed payload is recorded as "" rather
							// than dropped: an exec that went unrecorded
							// would be invisible to exactly the assertions
							// this recorder exists for.
							_ = ssh.Unmarshal(r.Payload, &payload)
							cfg.sawExec.record(payload.Command)
						}
						if r.WantReply {
							r.Reply(true, nil)
						}
						if cfg.home != "" {
							ch.Write([]byte(cfg.home + "\n"))
						}
						ch.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{0}))
						ch.Close()
					} else if r.WantReply {
						r.Reply(false, nil)
					}
				}
			}()
		default:
			newCh.Reject(ssh.UnknownChannelType, "unsupported in this fake server")
		}
	}
}

// startFakeSSHD stands up serveFakeSSHDConn on a loopback TCP listener,
// accepting connections until the test ends, and returns the host/port to
// dial plus the signer actually presented (generated when cfg.signer is
// nil) so callers can assert against it (e.g. the fingerprint offered).
func startFakeSSHD(t *testing.T, cfg fakeSSHDConfig) (host string, port int, hostSigner ssh.Signer) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	if cfg.signer == nil {
		cfg.signer, _ = testKey(t)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeSSHDConn(conn, cfg)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, cfg.signer
}
