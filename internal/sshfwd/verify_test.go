package sshfwd

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestVerifierFailsWithoutSigners(t *testing.T) {
	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return nil, nil },
		User:    func() (string, error) { return "me", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{} },
	})
	_, err := v.Verify(context.Background(), Remote{Host: "192.0.2.1", RemoteSocket: DefaultRemoteSocket})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("Verify() = %v, want ErrAuth when the agent has no identities", err)
	}
}

func TestVerifierPropagatesSignerError(t *testing.T) {
	want := errors.New("vault down")
	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return nil, want },
		User:    func() (string, error) { return "me", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{} },
	})
	if _, err := v.Verify(context.Background(), Remote{Host: "192.0.2.1", RemoteSocket: DefaultRemoteSocket}); !errors.Is(err, want) {
		t.Fatalf("Verify() = %v, want %v", err, want)
	}
}

func TestVerifierPropagatesUserError(t *testing.T) {
	want := errors.New("no identity")
	s, _ := testKey(t)
	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return []ssh.Signer{s}, nil },
		User:    func() (string, error) { return "", want },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{} },
	})
	if _, err := v.Verify(context.Background(), Remote{Host: "192.0.2.1", RemoteSocket: DefaultRemoteSocket}); !errors.Is(err, want) {
		t.Fatalf("Verify() = %v, want %v", err, want)
	}
}

// startFakeSSHD stands up an in-memory sshd (real TCP loopback, no external
// process) good enough for Verify's own needs: NoClientAuth (Verify's dial
// carries a real publickey offer, but nothing here needs to check it),
// "echo $HOME" over a session channel (ExpandRemotePath's "~/" probe), and
// streamlocal-forward/cancel-streamlocal-forward global requests (ListenUnix
// and its Close). It intentionally does not implement
// direct-streamlocal@openssh.com — Verify never dials the socket it binds,
// only binds and releases it — so unlike liveprobe_test.go's fake server
// this one needs no channel-open decision table.
func startFakeSSHD(t *testing.T, home string) (host string, port int, hostSigner ssh.Signer) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	signer, _ := testKey(t)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeSSHDConn(conn, signer, home)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, signer
}

func serveFakeSSHDConn(conn net.Conn, signer ssh.Signer, home string) {
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)

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

	for newCh := range chans {
		switch newCh.ChannelType() {
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
						ch.Write([]byte(home + "\n"))
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

func fakeSigners(t *testing.T) []ssh.Signer {
	t.Helper()
	s, _ := testKey(t)
	return []ssh.Signer{s}
}

// TestVerifierReturnsConfirmableResultForUnknownHostKey is the primary happy
// path Verify exists for: a host with no pin and no configured CA dials
// clean, and the result is exactly what Registry.Add needs to run its
// fingerprint-confirmation gate — a nil error, carrying the key and its
// fingerprint.
func TestVerifierReturnsConfirmableResultForUnknownHostKey(t *testing.T) {
	host, port, signer := startFakeSSHD(t, "/home/test")

	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil },
		User:    func() (string, error) { return "test", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{} },
	})

	result, err := v.Verify(context.Background(), Remote{Host: host, Port: port, RemoteSocket: DefaultRemoteSocket})
	if err != nil {
		t.Fatalf("Verify() returned an error for an unpinned host: %v", err)
	}
	wantFingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	if result.Fingerprint != wantFingerprint {
		t.Errorf("Fingerprint = %q, want %q", result.Fingerprint, wantFingerprint)
	}
	if result.HostKey == "" {
		t.Error("HostKey is empty for an unpinned host; Registry.Add has nothing to offer for confirmation")
	}
	if result.Verified {
		t.Error("Verified = true for an unconfirmed, brand-new host key; confirmation has not happened yet")
	}
}

// TestVerifierReturnsErrorForHostKeyMismatch is contract 3: every dial
// failure other than ErrHostKeyUnknown — a changed pinned key above all —
// must surface as a plain error, never as a confirmable result. If this
// came back as a VerifyResult with a nil error, a user could click through
// what might be an active MITM.
func TestVerifierReturnsErrorForHostKeyMismatch(t *testing.T) {
	host, port, _ := startFakeSSHD(t, "/home/test")

	other, _ := testKey(t)
	wrongPin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other.PublicKey())))

	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil },
		User:    func() (string, error) { return "test", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{Pinned: wrongPin} },
	})

	result, err := v.Verify(context.Background(), Remote{Host: host, Port: port, RemoteSocket: DefaultRemoteSocket})
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("Verify() = (%+v, %v), want an error wrapping ErrHostKeyMismatch", result, err)
	}
	if result != (VerifyResult{}) {
		t.Errorf("Verify() returned a non-zero result alongside a mismatch error: %+v", result)
	}
}

// TestVerifierInsecurePolicyReportsNoKeyMaterial is contract 2. Under an
// insecure policy, HostKeyPolicy.Callback records the observed key before
// its own Insecure short-circuit, so Verify is holding a fully-populated
// key with a nil dial error. That key was never authenticated, so it must
// not be reported: if it reached Registry.Add it would be persisted as a
// pin that outlives the insecure flag.
func TestVerifierInsecurePolicyReportsNoKeyMaterial(t *testing.T) {
	host, port, _ := startFakeSSHD(t, "/home/test")

	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil },
		User:    func() (string, error) { return "test", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{Insecure: true} },
	})

	result, err := v.Verify(context.Background(), Remote{Host: host, Port: port, RemoteSocket: DefaultRemoteSocket})
	if err != nil {
		t.Fatalf("Verify() returned an error under an insecure policy: %v", err)
	}
	if result.HostKey != "" {
		t.Errorf("HostKey = %q under an insecure policy, want empty: the key was never authenticated", result.HostKey)
	}
	if result.Fingerprint != "" {
		t.Errorf("Fingerprint = %q under an insecure policy, want empty: the key was never authenticated", result.Fingerprint)
	}
	if result.Verified {
		t.Error("Verified = true under an insecure policy; nothing was actually checked")
	}
}

// TestVerifierMatchedPinLeavesHostKeyEmpty is contract 4: an offered key that
// matches the stored pin reports "no change" (empty HostKey), not the pin
// echoed back, and Verified true because the pin genuinely was checked.
// Registry.Add owns the fallback to the pin already on file.
func TestVerifierMatchedPinLeavesHostKeyEmpty(t *testing.T) {
	host, port, signer := startFakeSSHD(t, "/home/test")
	pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil },
		User:    func() (string, error) { return "test", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{Pinned: pin} },
	})

	result, err := v.Verify(context.Background(), Remote{Host: host, Port: port, RemoteSocket: DefaultRemoteSocket})
	if err != nil {
		t.Fatalf("Verify() returned an error for a key matching the stored pin: %v", err)
	}
	if result.HostKey != "" {
		t.Errorf("HostKey = %q for a matched pin, want empty (\"no change\" per VerifyResult's doc comment)", result.HostKey)
	}
	if !result.Verified {
		t.Error("Verified = false for a key that matched the stored pin; the pin was genuinely checked")
	}
	if result.ResolvedSocket != "/home/test/.ssh/dotvault.sock" {
		t.Errorf("ResolvedSocket = %q, want the ~ expansion against the fake sshd's $HOME", result.ResolvedSocket)
	}
}
