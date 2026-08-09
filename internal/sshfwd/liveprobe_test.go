package sshfwd

import (
	"context"
	"io"
	"net"
	"path"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// streamlocalDecision describes how a fake sshd answers the Nth
// direct-streamlocal@openssh.com channel-open request it receives.
type streamlocalDecision struct {
	accept bool
	reason ssh.RejectionReason
}

// dialFakeStreamlocalServer stands up an in-memory sshd (real TCP loopback,
// no external process) that answers direct-streamlocal@openssh.com
// channel-open requests according to decisions, in order — the Nth
// direct-streamlocal open gets decisions[N], or a ConnectionFailed rejection
// once decisions is exhausted. streamlocal-forward@openssh.com /
// cancel-streamlocal-forward@openssh.com global requests (ListenUnix / Close)
// always succeed, and "session" channels (removeRemoteFile, sshRunner) always
// report a successful exec with no real filesystem behind it — this test
// suite is only exercising the channel-open decision logic, not a real
// remote filesystem.
func dialFakeStreamlocalServer(t *testing.T, decisions []streamlocalDecision) *ssh.Client {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	serverSigner, _ := testKey(t)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		config := &ssh.ServerConfig{NoClientAuth: true}
		config.AddHostKey(serverSigner)

		_, chans, reqs, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return
		}

		go func() {
			for req := range reqs {
				switch req.Type {
				case "streamlocal-forward@openssh.com", "cancel-streamlocal-forward@openssh.com":
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

		var n int32
		for newCh := range chans {
			switch newCh.ChannelType() {
			case "direct-streamlocal@openssh.com":
				i := int(atomic.AddInt32(&n, 1)) - 1
				d := streamlocalDecision{reason: ssh.ConnectionFailed}
				if i < len(decisions) {
					d = decisions[i]
				}
				if d.accept {
					ch, chReqs, err := newCh.Accept()
					if err != nil {
						continue
					}
					go ssh.DiscardRequests(chReqs)
					go io.Copy(io.Discard, ch) // keep the channel draining until the client closes it
				} else {
					newCh.Reject(d.reason, "rejected")
				}
			case "session":
				ch, chReqs, err := newCh.Accept()
				if err != nil {
					continue
				}
				go func() {
					for r := range chReqs {
						if r.Type == "exec" {
							if r.WantReply {
								r.Reply(true, nil)
							}
							_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{0}))
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
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clientConn.Close() })

	clientConfig := &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	sc, chans, reqs, err := ssh.NewClientConn(clientConn, ln.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	cl := ssh.NewClient(sc, chans, reqs)
	t.Cleanup(func() { cl.Close() })
	return cl
}

func TestLiveListenerAtDetectsLiveListener(t *testing.T) {
	cl := dialFakeStreamlocalServer(t, []streamlocalDecision{
		{accept: true}, // the real-path probe succeeds: something is listening
	})

	live, err := liveListenerAt(context.Background(), cl, "/run/user/1000/dotvault.sock")
	if err != nil {
		t.Fatalf("liveListenerAt returned an error for a live listener: %v", err)
	}
	if !live {
		t.Error("liveListenerAt reported not-live for a socket that accepted the probe dial")
	}
}

func TestLiveListenerAtInconclusiveOnProhibited(t *testing.T) {
	cl := dialFakeStreamlocalServer(t, []streamlocalDecision{
		{reason: ssh.Prohibited}, // a rejection reason other than ConnectionFailed
	})

	live, err := liveListenerAt(context.Background(), cl, "/run/user/1000/dotvault.sock")
	if live {
		t.Error("liveListenerAt reported live on a Prohibited rejection")
	}
	if err == nil {
		t.Error("liveListenerAt returned nil error on a Prohibited rejection; want it treated as inconclusive, not safe-to-unlink")
	}
}

func TestLiveListenerAtTrustsConnectionFailedWhenMechanismConfirmedWorking(t *testing.T) {
	// Real path: ConnectionFailed (ambiguous on its own). Scratch probe:
	// accepted, proving direct-streamlocal opens do reach a live listener on
	// this sshd in general — so the real path's ConnectionFailed genuinely
	// means nobody is listening there.
	cl := dialFakeStreamlocalServer(t, []streamlocalDecision{
		{reason: ssh.ConnectionFailed}, // real path
		{accept: true},                 // scratch probe
	})

	live, err := liveListenerAt(context.Background(), cl, "/run/user/1000/dotvault.sock")
	if err != nil {
		t.Fatalf("liveListenerAt returned an error when the scratch probe confirmed the mechanism works: %v", err)
	}
	if live {
		t.Error("liveListenerAt reported live for a path that returned ConnectionFailed")
	}
}

// TestLiveListenerAtRefusesToUnlinkWhenMechanismItselfIsBroken is the N2
// regression test: an sshd that rejects EVERY direct-streamlocal open with
// ConnectionFailed — which is exactly what OpenSSH does when
// AllowStreamLocalForwarding disallows client-initiated direct-streamlocal
// entirely, per server_input_channel_open in serverloop.c — must not have its
// real-path ConnectionFailed trusted as "nobody is listening". The
// differential probe against a scratch path must also see ConnectionFailed,
// and liveListenerAt must refuse to treat that as safe-to-unlink.
func TestLiveListenerAtRefusesToUnlinkWhenMechanismItselfIsBroken(t *testing.T) {
	cl := dialFakeStreamlocalServer(t, []streamlocalDecision{
		{reason: ssh.ConnectionFailed}, // real path — could be a live session under AllowStreamLocalForwarding remote
		{reason: ssh.ConnectionFailed}, // scratch probe — also fails: the mechanism itself doesn't work here
	})

	live, err := liveListenerAt(context.Background(), cl, "/run/user/1000/dotvault.sock")
	if live {
		t.Fatal("liveListenerAt reported live=true when the scratch probe also failed; that outcome should never happen")
	}
	if err == nil {
		t.Fatal("liveListenerAt returned nil error when its own differential probe could not confirm direct-streamlocal works; " +
			"a ConnectionFailed under AllowStreamLocalForwarding=remote or =no must not be trusted as proof of a stale socket")
	}
}

// closeTrackingConn wraps a net.Conn and records whether Close was called,
// without needing a real ssh server round trip — this is what makes
// drainPendingForward directly testable rather than only observable
// indirectly (and slowly) through the fake sshd's inability to reproduce
// sshd's self-connect-triggers-a-second-channel-open behaviour.
type closeTrackingConn struct {
	net.Conn
	closed *int32
}

func (c closeTrackingConn) Close() error {
	atomic.StoreInt32(c.closed, 1)
	return c.Conn.Close()
}

func TestDrainPendingForwardAcceptsAndClosesQueuedConnection(t *testing.T) {
	ln := newFakeListener()
	t.Cleanup(func() { ln.Close() })

	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() { clientSide.Close() })
	var closed int32
	// Sent from a goroutine: fakeListener.conns is unbuffered, and nothing
	// reads it until drainPendingForward's own internal Accept() call does.
	go func() { ln.conns <- closeTrackingConn{Conn: serverSide, closed: &closed} }()

	drainPendingForward(ln)

	if atomic.LoadInt32(&closed) == 0 {
		t.Error("drainPendingForward did not close the queued connection; the corresponding SSH channel-open would be left permanently unanswered")
	}
}

func TestDrainPendingForwardReturnsPromptlyWhenNothingIsQueued(t *testing.T) {
	ln := newFakeListener()
	t.Cleanup(func() { ln.Close() })

	start := time.Now()
	drainPendingForward(ln)
	if elapsed := time.Since(start); elapsed < drainPendingForwardTimeout {
		t.Errorf("drainPendingForward returned after %s with nothing queued; expected it to wait out the full %s bound", elapsed, drainPendingForwardTimeout)
	} else if elapsed > drainPendingForwardTimeout+time.Second {
		t.Errorf("drainPendingForward took %s, want close to the %s bound", elapsed, drainPendingForwardTimeout)
	}
}

func TestScratchProbePathStaysWithinOriginalPathLength(t *testing.T) {
	// A legitimate but long basename must not make the scratch path exceed
	// the original path's length — a suffixed name would grow with it and
	// risk ENAMETOOLONG against the sun_path budget (108 bytes on Linux, 104
	// on the BSDs); a replaced basename does not.
	longBase := "a-very-descriptive-dotvault-remote-socket-name-for-this-particular-host"
	socket := "/run/user/1000/" + longBase + ".sock"

	scratch, err := scratchProbePath(socket)
	if err != nil {
		t.Fatal(err)
	}
	if len(scratch) > len(socket) {
		t.Errorf("scratchProbePath(%q) = %q (%d bytes), longer than the original path (%d bytes)",
			socket, scratch, len(scratch), len(socket))
	}
	if path.Dir(scratch) != path.Dir(socket) {
		t.Errorf("scratchProbePath(%q) = %q, want it in the same directory (%q)", socket, scratch, path.Dir(socket))
	}
}
