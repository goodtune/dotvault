package sshfwd

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestVerifierFailsWithoutSigners(t *testing.T) {
	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return nil, nil },
		User:    func() (string, error) { return "me", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{} },
	})
	_, err := v.Verify(context.Background(), Remote{Host: "192.0.2.1", RemoteSocket: DefaultRemoteSocket}, VerifyOptions{})
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
	if _, err := v.Verify(context.Background(), Remote{Host: "192.0.2.1", RemoteSocket: DefaultRemoteSocket}, VerifyOptions{}); !errors.Is(err, want) {
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
	if _, err := v.Verify(context.Background(), Remote{Host: "192.0.2.1", RemoteSocket: DefaultRemoteSocket}, VerifyOptions{}); !errors.Is(err, want) {
		t.Fatalf("Verify() = %v, want %v", err, want)
	}
}

func TestVerifierRejectsIncompleteDeps(t *testing.T) {
	tests := []struct {
		name string
		deps Deps
	}{
		{"nil Signers", Deps{User: func() (string, error) { return "me", nil }, Policy: func(Remote) *HostKeyPolicy { return &HostKeyPolicy{} }}},
		{"nil User", Deps{Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil }, Policy: func(Remote) *HostKeyPolicy { return &HostKeyPolicy{} }}},
		{"nil Policy", Deps{Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil }, User: func() (string, error) { return "me", nil }}},
		{"zero-value Deps", Deps{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier(tt.deps)
			// The point of this test is that Verify returns an error instead
			// of panicking on a nil func call; a panic would fail the test
			// on its own, so there is nothing else to assert beyond reaching
			// this line.
			if _, err := v.Verify(context.Background(), Remote{Host: "192.0.2.1", RemoteSocket: DefaultRemoteSocket}, VerifyOptions{}); err == nil {
				t.Error("Verify() = nil error for incomplete Deps, want an error")
			}
		})
	}
}

func fakeSigners(t *testing.T) []ssh.Signer {
	t.Helper()
	s, _ := testKey(t)
	return []ssh.Signer{s}
}

// hostCertSigner builds a signed host certificate — the same shape as
// hostkey_test.go's hostCert — and wraps it in an ssh.Signer suitable for
// ssh.ServerConfig.AddHostKey (via fakeSSHDConfig.signer), so a fake sshd can
// present a certificate instead of a raw key as its host key. hostCert itself
// can't be reused directly here: it deliberately discards the host
// certificate's own private key, since hostkey_test.go only ever feeds the
// resulting *ssh.Certificate into HostKeyPolicy.Callback directly and never
// needs to sign a real handshake with it.
func hostCertSigner(t *testing.T, caSigner ssh.Signer, opts ...func(*ssh.Certificate)) ssh.Signer {
	t.Helper()
	hostSigner, hostPub := testKey(t)
	cert := &ssh.Certificate{
		Key:         hostPub,
		CertType:    ssh.HostCert,
		KeyId:       "fake-sshd",
		ValidAfter:  0,
		ValidBefore: ssh.CertTimeInfinity,
	}
	for _, opt := range opts {
		opt(cert)
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	certSigner, err := ssh.NewCertSigner(cert, hostSigner)
	if err != nil {
		t.Fatal(err)
	}
	return certSigner
}

// TestVerifierReturnsConfirmableResultForUnknownHostKey is the primary happy
// path Verify exists for: a host with no pin and no configured CA dials
// clean, and the result is exactly what Registry.Add needs to run its
// fingerprint-confirmation gate — a nil error, carrying the key and its
// fingerprint, with Verified true.
//
// Verified must be true here even though nothing has been confirmed yet:
// VerifyResult.Verified's doc comment (registry.go) defines "an actual
// check" to include reaching Add's own fingerprint-confirmation gate for a
// brand-new key. Registry.Add's switch reads Verified in the opposite sense
// — its first case, !Verified, is reserved for "nothing was checked at all"
// (the insecure policy) — so Verified: false here would make Add swallow
// the result before ErrConfirmHostKey is ever raised, silently persisting a
// brand-new host with no pin and no confirmation. This was Critical finding
// #1 in the round-1 review.
func TestVerifierReturnsConfirmableResultForUnknownHostKey(t *testing.T) {
	host, port, signer := startFakeSSHD(t, fakeSSHDConfig{home: "/home/test"})

	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil },
		User:    func() (string, error) { return "test", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{} },
	})

	result, err := v.Verify(context.Background(), Remote{Host: host, Port: port, RemoteSocket: DefaultRemoteSocket}, VerifyOptions{})
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
	if !result.Verified {
		t.Error("Verified = false for the confirmable unknown-key result; Registry.Add's !Verified case would swallow it and never raise ErrConfirmHostKey")
	}
}

// TestRegistryAddPromptsForConfirmationAgainstLiveVerifier drives a full
// Registry.Add against the live Verifier end to end — not a fake Verifier —
// against a brand-new, unpinned host. This is the exact end-to-end path the
// round-1 review used to prove Critical finding #1: with Verified left false
// on the confirmable branch, Add's `case !result.Verified` swallowed the
// result and persisted the host with an empty HostKey, no prompt ever
// raised. With the fix, Add must return ErrConfirmHostKey instead.
func TestRegistryAddPromptsForConfirmationAgainstLiveVerifier(t *testing.T) {
	host, port, _ := startFakeSSHD(t, fakeSSHDConfig{home: "/home/test"})

	deps := Deps{
		Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil },
		User:    func() (string, error) { return "test", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{} },
	}
	mgr := NewManager(context.Background(), deps)
	t.Cleanup(mgr.Close)
	reg := NewRegistry(t.TempDir()+"/ssh.yaml", mgr, NewVerifier(deps))

	_, err := reg.Add(context.Background(), Remote{Host: host, Port: port, RemoteSocket: DefaultRemoteSocket}, AddOptions{})
	var confirm *HostKeyConfirmation
	if !errors.As(err, &confirm) {
		t.Fatalf("Registry.Add() = %v, want a *HostKeyConfirmation for a brand-new host", err)
	}
	if confirm.Fingerprint == "" {
		t.Error("HostKeyConfirmation.Fingerprint is empty; nothing for the caller to echo back")
	}

	list, err := reg.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Errorf("Registry.List() = %+v after an unconfirmed Add, want no entry persisted", list)
	}
}

// TestVerifierReturnsErrorForHostKeyMismatch is contract 3: every dial
// failure other than ErrHostKeyUnknown — a changed pinned key above all —
// must surface as a plain error, never as a confirmable result. If this
// came back as a VerifyResult with a nil error, a user could click through
// what might be an active MITM.
func TestVerifierReturnsErrorForHostKeyMismatch(t *testing.T) {
	host, port, _ := startFakeSSHD(t, fakeSSHDConfig{home: "/home/test"})

	other, _ := testKey(t)
	wrongPin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other.PublicKey())))

	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil },
		User:    func() (string, error) { return "test", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{Pinned: wrongPin} },
	})

	result, err := v.Verify(context.Background(), Remote{Host: host, Port: port, RemoteSocket: DefaultRemoteSocket}, VerifyOptions{})
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("Verify() = (%+v, %v), want an error wrapping ErrHostKeyMismatch", result, err)
	}
	if result != (VerifyResult{}) {
		t.Errorf("Verify() returned a non-zero result alongside a mismatch error: %+v", result)
	}
}

// TestVerifierRejectsCertificateOnPinnedHostWithNoConfiguredCA is Critical
// finding #2 from the round-1 review, reproduced end to end: a host already
// pinned to a raw key presents a certificate instead (no configured CA can
// validate it either way). Before the hostkey.go fix, checkCert's
// len(p.CAs)==0 branch returned ErrHostKeyUnknown unconditionally — without
// even looking at the pin — turning what must be a hard ErrHostKeyMismatch
// (an attacker presenting a certificate to bypass the pinned raw key) into a
// human-clickable "new host, please confirm" prompt.
func TestVerifierRejectsCertificateOnPinnedHostWithNoConfiguredCA(t *testing.T) {
	caSigner, _ := testKey(t)
	certSigner := hostCertSigner(t, caSigner)

	host, port, _ := startFakeSSHD(t, fakeSSHDConfig{home: "/home/test", signer: certSigner})

	_, pinned := testKey(t)
	pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pinned)))

	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil },
		User:    func() (string, error) { return "test", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{Pinned: pin} }, // no CAs configured
	})

	result, err := v.Verify(context.Background(), Remote{Host: host, Port: port, RemoteSocket: DefaultRemoteSocket}, VerifyOptions{})
	if errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("Verify() reported the certificate as confirmable (wraps ErrHostKeyUnknown) on an already-pinned host: result=%+v err=%v", result, err)
	}
	if err == nil {
		t.Fatalf("Verify() = (%+v, nil), want an error: a certificate must never silently satisfy an existing raw-key pin", result)
	}
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Errorf("Verify() error does not wrap ErrHostKeyMismatch, so Classify cannot map it to ClassHostKey: %v", err)
	}
	if result != (VerifyResult{}) {
		t.Errorf("Verify() returned a non-zero result alongside an error: %+v", result)
	}
}

// TestVerifierRejectsCertificateWithNoConfiguredCA is the benign-looking half
// of Critical finding #2: an unpinned host offers a certificate, but no
// certificate_authorities are configured to validate it against. Before the
// fix this was confirmable too — any certificate was, on any deployment that
// had not configured CAs at all, which is the default. It must instead be
// refused outright: there is nothing that makes an unvalidated certificate
// safe to ask a human to confirm.
func TestVerifierRejectsCertificateWithNoConfiguredCA(t *testing.T) {
	caSigner, _ := testKey(t)
	certSigner := hostCertSigner(t, caSigner)

	host, port, _ := startFakeSSHD(t, fakeSSHDConfig{home: "/home/test", signer: certSigner})

	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil },
		User:    func() (string, error) { return "test", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{} }, // no pin, no CAs
	})

	result, err := v.Verify(context.Background(), Remote{Host: host, Port: port, RemoteSocket: DefaultRemoteSocket}, VerifyOptions{})
	if errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("Verify() reported an unvalidatable certificate as confirmable (wraps ErrHostKeyUnknown): result=%+v err=%v", result, err)
	}
	if err == nil {
		t.Fatalf("Verify() = (%+v, nil), want an error: a certificate with no configured CA to check it against must never be confirmable", result)
	}
	if result != (VerifyResult{}) {
		t.Errorf("Verify() returned a non-zero result alongside an error: %+v", result)
	}
}

// TestVerifierAcceptsCASignedCertificate is the CA-covered success shape:
// the one outcome the round-1 report itself flagged as untested. A
// certificate signed by a configured CA, with no ValidPrincipals set (valid
// for any principal — see ssh.CertChecker.CheckCert), must verify cleanly
// with Verified true and no new key to report.
func TestVerifierAcceptsCASignedCertificate(t *testing.T) {
	caSigner, caPub := testKey(t)
	certSigner := hostCertSigner(t, caSigner)

	host, port, _ := startFakeSSHD(t, fakeSSHDConfig{home: "/home/test", signer: certSigner})

	// knownhosts.hostPattern matches the host part with a glob but the port
	// exactly (see hostPattern.match); an unqualified "*" defaults to port
	// "22", so the pattern must name this fake sshd's actual (ephemeral)
	// port explicitly.
	caLine := fmt.Sprintf("@cert-authority *:%d %s", port, string(ssh.MarshalAuthorizedKey(caPub)))

	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil },
		User:    func() (string, error) { return "test", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{CAs: []string{caLine}} },
	})

	result, err := v.Verify(context.Background(), Remote{Host: host, Port: port, RemoteSocket: DefaultRemoteSocket}, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() returned an error for a CA-signed certificate: %v", err)
	}
	if !result.Verified {
		t.Error("Verified = false for a certificate covered by a configured CA")
	}
	if result.HostKey != "" {
		t.Errorf("HostKey = %q for a CA-covered host, want empty: nothing new to pin", result.HostKey)
	}
}

// TestVerifierInsecurePolicyReportsNoKeyMaterial is contract 2. Under an
// insecure policy, HostKeyPolicy.Callback records the observed key before
// its own Insecure short-circuit, so Verify is holding a fully-populated
// key with a nil dial error. That key was never authenticated, so it must
// not be reported: if it reached Registry.Add it would be persisted as a
// pin that outlives the insecure flag.
func TestVerifierInsecurePolicyReportsNoKeyMaterial(t *testing.T) {
	host, port, _ := startFakeSSHD(t, fakeSSHDConfig{home: "/home/test"})

	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil },
		User:    func() (string, error) { return "test", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{Insecure: true} },
	})

	result, err := v.Verify(context.Background(), Remote{Host: host, Port: port, RemoteSocket: DefaultRemoteSocket}, VerifyOptions{})
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
	host, port, signer := startFakeSSHD(t, fakeSSHDConfig{home: "/home/test"})
	pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil },
		User:    func() (string, error) { return "test", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{Pinned: pin} },
	})

	result, err := v.Verify(context.Background(), Remote{Host: host, Port: port, RemoteSocket: DefaultRemoteSocket}, VerifyOptions{})
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

// TestVerifierReturnsErrBindOnBindFailure proves the ListenUnix failure path
// wraps ErrBind, and that Verify does not attempt to work around the
// failure by any means other than reporting it — the fake sshd here also
// counts "exec" requests, so this doubles as a contract-5 regression test
// for the common case where the bind-failure diagnostic's own dial is
// rejected outright (not the ConnectionFailed shape —
// TestVerifierBindFailureDiagnosticNeverMutatesRemote below covers that one
// specifically, since it used to reach a mutating fallback).
func TestVerifierReturnsErrBindOnBindFailure(t *testing.T) {
	var execCount atomic.Int64
	host, port, signer := startFakeSSHD(t, fakeSSHDConfig{
		home:                     "/home/test",
		refuseStreamlocalForward: true,
		sawExec:                  &execCount,
	})
	// Pinned so the dial itself succeeds and Verify reaches the bind step —
	// this test is about ListenUnix's failure, not the host-key path.
	pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil },
		User:    func() (string, error) { return "test", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{Pinned: pin} },
	})

	result, err := v.Verify(context.Background(), Remote{Host: host, Port: port, RemoteSocket: DefaultRemoteSocket}, VerifyOptions{})
	if !errors.Is(err, ErrBind) {
		t.Fatalf("Verify() = (%+v, %v), want an error wrapping ErrBind", result, err)
	}
	if execCount.Load() != 1 {
		t.Errorf("saw %d exec requests after a bind failure, want exactly 1 (the $HOME probe); a stale-socket unlink must never run here", execCount.Load())
	}
}

// TestVerifierSkipsBindProofWhenRequested is the liveVerifier half of
// Registry.Add's SkipBindProof handling: with the flag set, a host whose
// ListenUnix would otherwise fail (simulating the running daemon's own live
// forward already occupying that exact path, which makes a fresh bind fail
// with EADDRINUSE for reasons that have nothing to do with trust) must still
// verify successfully — dial, auth, and the host-key check all still ran,
// only the bind-and-release side effect was skipped.
func TestVerifierSkipsBindProofWhenRequested(t *testing.T) {
	host, port, signer := startFakeSSHD(t, fakeSSHDConfig{
		home:                     "/home/test",
		refuseStreamlocalForward: true,
	})
	pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil },
		User:    func() (string, error) { return "test", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{Pinned: pin} },
	})

	result, err := v.Verify(context.Background(), Remote{Host: host, Port: port, RemoteSocket: DefaultRemoteSocket},
		VerifyOptions{SkipBindProof: true})
	if err != nil {
		t.Fatalf("Verify(SkipBindProof) = %v, want success despite the bind failure it was told to skip", err)
	}
	if !result.Verified {
		t.Error("Verified = false, want true: the pinned-key dial still ran and matched")
	}
}

// TestVerifierBindFailureDiagnosticNeverMutatesRemote is the round-2 review's
// regression test. Verify's bind-failure diagnostic used to call
// liveListenerAt (forward.go) to give an actionable "already forwarded"
// message. On a ConnectionFailed rejection — exactly what an sshd returns
// for "nobody is listening at this path" as well as for
// "AllowStreamLocalForwarding disallows this entirely" (see liveListenerAt's
// own doc comment) — that helper falls through to directStreamLocalWorks,
// which binds a scratch socket on the remote and rm -f's it in its own
// cleanup. That is a real mutation of a host `ssh add` has not yet been told
// to manage: exactly what contract 5 forbids, and what liveVerifier's own
// doc comment ("without ... mutating anything on the remote") promises does
// not happen. The fix replaced liveListenerAt with a single, non-mutating
// cl.DialContext probe that treats any dial error — ConnectionFailed
// included — as merely inconclusive.
//
// To exercise the path the old code actually took, this fake must let the
// full liveListenerAt→directStreamLocalWorks sequence run to completion, not
// dead-end early: the real path's streamlocal-forward bind fails (as any
// bind-failure diagnostic scenario starts), the real path's
// direct-streamlocal probe dial gets the ambiguous ConnectionFailed
// rejection, and — the part a same-shaped-for-every-call fake would get
// wrong — the *second*, scratch-path streamlocal-forward bind and its
// direct-streamlocal self-dial must both succeed, exactly as they would
// against a real sshd that permits forwarding in general but already has
// something on the real path. Only then does directStreamLocalWorks reach
// its own cleanup and attempt the rm -f this test asserts never happens.
func TestVerifierBindFailureDiagnosticNeverMutatesRemote(t *testing.T) {
	var execCount atomic.Int64
	var directCalls int32
	host, port, signer := startFakeSSHD(t, fakeSSHDConfig{
		home: "/home/test",
		// Refuses only the first (real-path) bind; the second (scratch-path)
		// bind directStreamLocalWorks issues must succeed — see
		// refuseStreamlocalForward's doc comment.
		refuseStreamlocalForward: true,
		sawExec:                  &execCount,
		onDirectStreamLocal: func(newCh ssh.NewChannel) {
			if atomic.AddInt32(&directCalls, 1) == 1 {
				// liveListenerAt's own real-path probe: ambiguous rejection,
				// the shape that makes it consult directStreamLocalWorks.
				newCh.Reject(ssh.ConnectionFailed, "nothing is listening")
				return
			}
			// directStreamLocalWorks dialling the scratch path it just
			// bound: accept, proving (falsely, from this test's point of
			// view) that the mechanism works — which is what makes the old
			// code trust the real path's ConnectionFailed as "stale" and
			// proceed to unlink it.
			ch, chReqs, err := newCh.Accept()
			if err != nil {
				return
			}
			go ssh.DiscardRequests(chReqs)
			go io.Copy(io.Discard, ch)
		},
	})
	pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return fakeSigners(t), nil },
		User:    func() (string, error) { return "test", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{Pinned: pin} },
	})

	result, err := v.Verify(context.Background(), Remote{Host: host, Port: port, RemoteSocket: DefaultRemoteSocket}, VerifyOptions{})
	if !errors.Is(err, ErrBind) {
		t.Fatalf("Verify() = (%+v, %v), want an error wrapping ErrBind", result, err)
	}
	if execCount.Load() != 1 {
		t.Errorf("saw %d exec requests after a ConnectionFailed bind diagnostic, want exactly 1 (the $HOME probe); the old liveListenerAt fallback would bind a scratch socket and rm -f it here", execCount.Load())
	}
}
