package sshfwd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type fakeVerifier struct {
	result VerifyResult
	err    error

	mu    sync.Mutex
	calls int
}

// Verify is called with no Registry lock held (Add moved the network dial
// out of its critical section — see the task-11 review's I5), so concurrent
// Adds can call it concurrently. The mutex here guards the fake's own call
// counter; it says nothing about Registry's locking, which TestConcurrentAddDoesNotLoseUpdates
// exercises separately.
func (f *fakeVerifier) Verify(ctx context.Context, r Remote, opts VerifyOptions) (VerifyResult, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return f.result, f.err
}

// capturingVerifier records the Remote (and VerifyOptions) it was called
// with, so a test can assert what Add handed to Verify — in particular,
// whether a stored pin was folded in on a re-Add (see
// TestAddPassesStoredPinToVerifierOnReAdd) or whether the bind proof was
// skipped for an already-connected host (see
// TestAddSkipsBindProofWhenAlreadyConnected).
type capturingVerifier struct {
	calls     []Remote
	optsCalls []VerifyOptions
	result    VerifyResult
	err       error
}

func (c *capturingVerifier) Verify(ctx context.Context, r Remote, opts VerifyOptions) (VerifyResult, error) {
	c.calls = append(c.calls, r)
	c.optsCalls = append(c.optsCalls, opts)
	return c.result, c.err
}

// stepVerifier returns a different VerifyResult on each successive call, so a
// test can simulate a verifier's behaviour changing between an initial Add
// and a later re-Add of the same host (e.g. "new key, needs confirmation"
// followed by "matched the pin, nothing new to report").
type stepVerifier struct {
	mu    sync.Mutex
	steps []VerifyResult
	n     int
}

func (s *stepVerifier) Verify(ctx context.Context, r Remote, opts VerifyOptions) (VerifyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.n
	if i >= len(s.steps) {
		i = len(s.steps) - 1
	}
	s.n++
	return s.steps[i], nil
}

// testHostKey generates a fresh, self-consistent (authorized-key, SHA256
// fingerprint) pair. Add now independently re-derives a reported key's
// fingerprint and refuses to pin if the two disagree, so any test whose
// VerifyResult carries a real HostKey needs a real, matching Fingerprint —
// a placeholder string like "k" no longer parses.
func testHostKey(t *testing.T) (key, fingerprint string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), ssh.FingerprintSHA256(pub)
}

func newTestRegistry(t *testing.T, v Verifier) (*Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh.yaml")
	m := NewManager(context.Background(), Deps{})
	m.newRunner = func(string) func(context.Context) {
		return func(ctx context.Context) { <-ctx.Done() }
	}
	t.Cleanup(m.Close)
	return NewRegistry(path, m, v), path
}

func TestAddRequiresFingerprintConfirmation(t *testing.T) {
	key, fp := testHostKey(t)
	v := &fakeVerifier{result: VerifyResult{
		Verified:       true,
		HostKey:        key,
		Fingerprint:    fp,
		ResolvedSocket: "/home/me/.ssh/dotvault.sock",
	}}
	g, path := newTestRegistry(t, v)

	_, err := g.Add(context.Background(), Remote{Host: "foo.example.com"}, AddOptions{})
	if !errors.Is(err, ErrConfirmHostKey) {
		t.Fatalf("Add() without confirmation = %v, want ErrConfirmHostKey", err)
	}

	f, loadErr := Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(f.Remotes) != 0 {
		t.Fatalf("Add() persisted %d remotes before confirmation, want 0", len(f.Remotes))
	}
}

func TestAddCommitsWhenFingerprintEchoed(t *testing.T) {
	key, fp := testHostKey(t)
	v := &fakeVerifier{result: VerifyResult{
		Verified:       true,
		HostKey:        key,
		Fingerprint:    fp,
		ResolvedSocket: "/home/me/.ssh/dotvault.sock",
	}}
	g, path := newTestRegistry(t, v)

	got, err := g.Add(context.Background(), Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: fp})
	if err != nil {
		t.Fatalf("Add() = %v", err)
	}
	if got.HostKey != key {
		t.Errorf("stored host key = %q, want the verified key", got.HostKey)
	}
	if got.RemoteSocket != DefaultRemoteSocket {
		t.Errorf("remote_socket = %q, want the default %q stored unexpanded", got.RemoteSocket, DefaultRemoteSocket)
	}

	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Remotes) != 1 {
		t.Fatalf("persisted %d remotes, want 1", len(f.Remotes))
	}
}

func TestAddRejectsWrongFingerprint(t *testing.T) {
	key, fp := testHostKey(t)
	v := &fakeVerifier{result: VerifyResult{Verified: true, Fingerprint: fp, HostKey: key}}
	g, _ := newTestRegistry(t, v)
	_, err := g.Add(context.Background(), Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: "SHA256:wrong"})
	if err == nil || errors.Is(err, ErrConfirmHostKey) {
		t.Fatalf("Add() with a mismatched fingerprint = %v, want a rejection", err)
	}
}

func TestAddDoesNotPersistWhenVerificationFails(t *testing.T) {
	want := errors.New("AllowStreamLocalForwarding is off")
	v := &fakeVerifier{err: want}
	g, path := newTestRegistry(t, v)

	if _, err := g.Add(context.Background(), Remote{Host: "foo.example.com"}, AddOptions{}); !errors.Is(err, want) {
		t.Fatalf("Add() = %v, want %v", err, want)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Remotes) != 0 {
		t.Fatal("Add() persisted an entry it could not verify")
	}
}

func TestAddForceSkipsVerification(t *testing.T) {
	v := &fakeVerifier{err: errors.New("host is offline")}
	g, path := newTestRegistry(t, v)

	if _, err := g.Add(context.Background(), Remote{Host: "foo.example.com"}, AddOptions{Force: true}); err != nil {
		t.Fatalf("Add(force) = %v", err)
	}
	if v.calls != 0 {
		t.Errorf("verifier called %d times under --force, want 0", v.calls)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Remotes) != 1 {
		t.Fatalf("persisted %d remotes, want 1", len(f.Remotes))
	}
}

func TestAddIsIdempotentOnHost(t *testing.T) {
	key, fp := testHostKey(t)
	v := &fakeVerifier{result: VerifyResult{Verified: true, Fingerprint: fp, HostKey: key}}
	g, path := newTestRegistry(t, v)
	ctx := context.Background()
	opts := AddOptions{AcceptFingerprint: fp}

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Add(ctx, Remote{Host: "foo.example.com", Port: 2222}, opts); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Remotes) != 1 {
		t.Fatalf("second Add created a duplicate: %d remotes", len(f.Remotes))
	}
	if f.Remotes[0].Port != 2222 {
		t.Errorf("second Add did not update the entry: %+v", f.Remotes[0])
	}
}

func TestRegistryRemove(t *testing.T) {
	key, fp := testHostKey(t)
	v := &fakeVerifier{result: VerifyResult{Verified: true, Fingerprint: fp, HostKey: key}}
	g, _ := newTestRegistry(t, v)
	ctx := context.Background()

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: fp}); err != nil {
		t.Fatal(err)
	}
	removed, err := g.Remove(ctx, "foo.example.com")
	if err != nil {
		t.Fatalf("Remove() = %v", err)
	}
	if !removed {
		t.Error("Remove() = false, want true")
	}
	removed, err = g.Remove(ctx, "foo.example.com")
	if err != nil {
		t.Fatalf("second Remove() = %v", err)
	}
	if removed {
		t.Error("second Remove() = true, want false (idempotent)")
	}
}

func TestPatchTogglesEnabled(t *testing.T) {
	key, fp := testHostKey(t)
	v := &fakeVerifier{result: VerifyResult{Verified: true, Fingerprint: fp, HostKey: key}}
	g, path := newTestRegistry(t, v)
	ctx := context.Background()

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: fp}); err != nil {
		t.Fatal(err)
	}
	off := false
	if _, err := g.Patch(ctx, "foo.example.com", Patch{Enabled: &off}); err != nil {
		t.Fatalf("Patch() = %v", err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Remotes[0].EnabledOrDefault() {
		t.Error("Patch() did not disable the remote")
	}
}

// TestPatchRejectsInvalidSocket asserts not merely that Patch returns an
// error for a bad remote_socket, but that ssh.yaml is left byte-for-byte
// unchanged. An earlier version of this test only checked for a non-nil
// error, which also passes if Patch's own validation is deleted and the
// error instead comes from Manager.Reconcile after the bad value was
// already written to disk — see the task-11 review's I6.
func TestPatchRejectsInvalidSocket(t *testing.T) {
	key, fp := testHostKey(t)
	v := &fakeVerifier{result: VerifyResult{Verified: true, Fingerprint: fp, HostKey: key}}
	g, path := newTestRegistry(t, v)
	ctx := context.Background()
	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: fp}); err != nil {
		t.Fatal(err)
	}

	before, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	bad := "relative/path.sock"
	if _, err := g.Patch(ctx, "foo.example.com", Patch{RemoteSocket: &bad}); err == nil {
		t.Fatal("Patch() accepted an invalid remote_socket")
	}

	after, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Remotes) != 1 || after.Remotes[0].RemoteSocket != before.Remotes[0].RemoteSocket {
		t.Fatalf("Patch() persisted an invalid remote_socket: before %+v, after %+v", before.Remotes, after.Remotes)
	}
}

func TestPatchUnknownHost(t *testing.T) {
	g, _ := newTestRegistry(t, &fakeVerifier{})
	off := false
	if _, err := g.Patch(context.Background(), "nope.example.com", Patch{Enabled: &off}); err == nil {
		t.Fatal("Patch() on an unknown host succeeded; want an error")
	}
}

// --- Security-contract tests not covered by the brief's literal test list ---

// TestAddRejectsWrongFingerprintEvenIfVerifyErrorsMismatch documents contract
// 1: ErrHostKeyMismatch (surfaced here as a plain error from Verify, per the
// Verifier contract) must never be confirmable, even if the caller happens
// to echo back exactly the fingerprint the verifier offered. Only the
// "unknown, unpinned" case — a nil error from Verify with a Fingerprint set
// — is confirmable.
func TestAddRejectsWrongFingerprintEvenIfVerifyErrorsMismatch(t *testing.T) {
	mismatch := errors.New("host key for foo.example.com changed: possible MITM: host key or certificate rejected")
	v := &fakeVerifier{
		result: VerifyResult{Fingerprint: "SHA256:abc", HostKey: "k"},
		err:    mismatch,
	}
	g, path := newTestRegistry(t, v)

	_, err := g.Add(context.Background(), Remote{Host: "foo.example.com"},
		AddOptions{AcceptFingerprint: "SHA256:abc"})
	if err == nil {
		t.Fatal("Add() with a Verify error = nil, want the mismatch surfaced")
	}
	if errors.Is(err, ErrConfirmHostKey) {
		t.Fatalf("Add() = %v, must not be confirmable even with a matching AcceptFingerprint", err)
	}
	if !errors.Is(err, mismatch) {
		t.Fatalf("Add() = %v, want the verifier's error wrapped through", err)
	}

	f, loadErr := Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(f.Remotes) != 0 {
		t.Fatal("Add() persisted an entry despite a verification error")
	}
}

// TestAddInsecurePolicyDoesNotPinAKey documents contract 2: a Verifier
// running under an insecure policy reports Verified: false — even though it
// may still carry a fully-formed, self-consistent HostKey/Fingerprint pair,
// because HostKeyPolicy.Callback observes the key before its own Insecure
// short-circuit (see hostkey.go). Add must blank the pin in that case
// regardless of what HostKey/Fingerprint say, not merely when they are
// empty — the shape a careless Verifier is most likely to produce.
func TestAddInsecurePolicyDoesNotPinAKey(t *testing.T) {
	key, fp := testHostKey(t)
	v := &fakeVerifier{result: VerifyResult{Verified: false, HostKey: key, Fingerprint: fp}}
	g, path := newTestRegistry(t, v)

	got, err := g.Add(context.Background(), Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: fp})
	if err != nil {
		t.Fatalf("Add() = %v, want success with the pin blanked, not an error", err)
	}
	if got.HostKey != "" {
		t.Fatalf("Add() pinned HostKey %q from an unverified result, want empty", got.HostKey)
	}

	f, loadErr := Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(f.Remotes) != 1 || f.Remotes[0].HostKey != "" {
		t.Fatalf("persisted entry = %+v, want one entry with no host_key", f.Remotes)
	}
}

// TestAddForceNeverCallsVerifier documents contract 3's Force half: Force
// must skip verification outright, not merely ignore its result.
func TestAddForceNeverCallsVerifier(t *testing.T) {
	v := &fakeVerifier{result: VerifyResult{Fingerprint: "SHA256:abc", HostKey: "k"}}
	g, _ := newTestRegistry(t, v)

	if _, err := g.Add(context.Background(), Remote{Host: "foo.example.com"}, AddOptions{Force: true}); err != nil {
		t.Fatalf("Add(force) = %v", err)
	}
	if v.calls != 0 {
		t.Fatalf("verifier called %d times under --force, want 0", v.calls)
	}
}

// --- Fix-round tests (task-11 review: C1, I2, I3, I4, I6) ---

// TestAddRefusesKeyWithoutFingerprint is C1's targeted test: a HostKey with
// no accompanying Fingerprint must never be pinned, and must not be
// confirmable — it is refused outright, since there is nothing for a caller
// to confirm against.
func TestAddRefusesKeyWithoutFingerprint(t *testing.T) {
	key, _ := testHostKey(t)
	v := &fakeVerifier{result: VerifyResult{Verified: true, HostKey: key, Fingerprint: ""}}
	g, path := newTestRegistry(t, v)

	_, err := g.Add(context.Background(), Remote{Host: "foo.example.com"}, AddOptions{})
	if err == nil {
		t.Fatal("Add() with a host key but no fingerprint succeeded; want a refusal")
	}
	if errors.Is(err, ErrConfirmHostKey) {
		t.Fatalf("Add() = %v, must not be confirmable", err)
	}

	f, loadErr := Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(f.Remotes) != 0 {
		t.Fatal("Add() persisted an unconfirmed key")
	}
}

// TestAddRefusesFingerprintNotMatchingKey is C1's other half: a Fingerprint
// that does not actually correspond to the reported HostKey must be refused,
// not treated as if it matched.
func TestAddRefusesFingerprintNotMatchingKey(t *testing.T) {
	key, _ := testHostKey(t)
	v := &fakeVerifier{result: VerifyResult{
		Verified:    true,
		HostKey:     key,
		Fingerprint: "SHA256:not-the-real-fingerprint",
	}}
	g, path := newTestRegistry(t, v)

	_, err := g.Add(context.Background(), Remote{Host: "foo.example.com"},
		AddOptions{AcceptFingerprint: "SHA256:not-the-real-fingerprint"})
	if err == nil {
		t.Fatal("Add() with a fingerprint that does not match the reported key succeeded; want a refusal")
	}
	if errors.Is(err, ErrConfirmHostKey) {
		t.Fatalf("Add() = %v, must not be confirmable", err)
	}

	f, loadErr := Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(f.Remotes) != 0 {
		t.Fatal("Add() persisted a key/fingerprint pair that does not match")
	}
}

// TestAddPassesStoredPinToVerifierOnReAdd is I2's test: a re-Add of an
// already-pinned host must hand Verify the stored pin, not a blank one, so a
// changed key surfaces as a rejected mismatch rather than a fresh,
// confirmable "first use" prompt.
func TestAddPassesStoredPinToVerifierOnReAdd(t *testing.T) {
	key, fp := testHostKey(t)
	v := &capturingVerifier{result: VerifyResult{Verified: true, HostKey: key, Fingerprint: fp}}
	g, _ := newTestRegistry(t, v)
	ctx := context.Background()
	opts := AddOptions{AcceptFingerprint: fp}

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Add(ctx, Remote{Host: "foo.example.com", Port: 2222}, opts); err != nil {
		t.Fatal(err)
	}

	if len(v.calls) != 2 {
		t.Fatalf("verifier called %d times, want 2", len(v.calls))
	}
	if v.calls[1].HostKey != key {
		t.Fatalf("second Verify call saw HostKey %q, want the stored pin %q", v.calls[1].HostKey, key)
	}
}

// TestAddForcePreservesExistingPin is I3's test: --force changes
// configuration, not trust. Re-adding an already-pinned host with Force and
// no explicit HostKey must not blank the stored pin.
func TestAddForcePreservesExistingPin(t *testing.T) {
	key, fp := testHostKey(t)
	v := &fakeVerifier{result: VerifyResult{Verified: true, HostKey: key, Fingerprint: fp}}
	g, path := newTestRegistry(t, v)
	ctx := context.Background()

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: fp}); err != nil {
		t.Fatal(err)
	}

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com", Port: 2222}, AddOptions{Force: true}); err != nil {
		t.Fatalf("Add(force) = %v", err)
	}

	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Remotes) != 1 || f.Remotes[0].HostKey != key {
		t.Fatalf("Force re-add did not preserve the existing pin: %+v", f.Remotes)
	}
	if f.Remotes[0].Port != 2222 {
		t.Fatalf("Force re-add did not apply the config change: %+v", f.Remotes)
	}
}

// TestAddPreservesStoredPinWhenVerifyReportsNoKey is R1's test: the everyday
// re-Add path, not just Force, must not unpin an already-trusted host when
// Verify reports success with no HostKey — the natural shape for "the
// offered key matched the pin you handed me, nothing new to confirm" (see
// VerifyResult.HostKey's doc comment).
func TestAddPreservesStoredPinWhenVerifyReportsNoKey(t *testing.T) {
	key, fp := testHostKey(t)
	v := &stepVerifier{steps: []VerifyResult{
		{Verified: true, HostKey: key, Fingerprint: fp}, // initial Add: new key, needs confirmation
		{Verified: true}, // re-Add: matched the stored pin, nothing new
	}}
	g, path := newTestRegistry(t, v)
	ctx := context.Background()

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: fp}); err != nil {
		t.Fatal(err)
	}

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com", Port: 2222}, AddOptions{}); err != nil {
		t.Fatalf("re-Add() = %v", err)
	}

	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Remotes) != 1 || f.Remotes[0].HostKey != key {
		t.Fatalf("re-Add unpinned an already-trusted host: %+v", f.Remotes)
	}
	if f.Remotes[0].Port != 2222 {
		t.Fatalf("re-Add did not apply the config change: %+v", f.Remotes)
	}
}

// TestPartialFailureReportsSaveSucceededButReconcileFailed is I4's test: when
// Save succeeds but Reconcile fails, the caller must be told the file
// already changed, and get back the committed value — not an error
// indistinguishable from "nothing happened".
func TestPartialFailureReportsSaveSucceededButReconcileFailed(t *testing.T) {
	key, fp := testHostKey(t)
	v := &fakeVerifier{result: VerifyResult{Verified: true, HostKey: key, Fingerprint: fp}}
	g, path := newTestRegistry(t, v)
	ctx := context.Background()

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: fp}); err != nil {
		t.Fatal(err)
	}

	// Sabotage the file behind Registry's back with an entry Reconcile will
	// reject (an out-of-range port), simulating a hand-edited or
	// legacy-invalid ssh.yaml.
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Remotes = append(f.Remotes, Remote{Host: "bad.example.com", Port: -1, RemoteSocket: DefaultRemoteSocket})
	if err := Save(path, f); err != nil {
		t.Fatal(err)
	}

	off := false
	got, err := g.Patch(ctx, "foo.example.com", Patch{Enabled: &off})
	if err == nil {
		t.Fatal("Patch() succeeded despite an unreconcilable file; want the Reconcile failure surfaced")
	}
	if got == nil || got.EnabledOrDefault() {
		t.Fatalf("Patch() = (%+v, %v), want the committed remote reflecting the change even though Reconcile failed", got, err)
	}

	f2, loadErr := Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	i, ok := f2.Find("foo.example.com")
	if !ok || f2.Remotes[i].EnabledOrDefault() {
		t.Fatal("Patch() reported the change was saved, but the file does not reflect it")
	}
}

// TestAddReconcilesManager is part of I6: nothing in the brief's own tests
// asserted that Add actually reconciles the Manager, as opposed to merely
// writing the file.
func TestAddReconcilesManager(t *testing.T) {
	key, fp := testHostKey(t)
	v := &fakeVerifier{result: VerifyResult{Verified: true, HostKey: key, Fingerprint: fp}}
	g, _ := newTestRegistry(t, v)
	ctx := context.Background()

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: fp}); err != nil {
		t.Fatal(err)
	}

	statuses := g.mgr.Status()
	if len(statuses) != 1 || statuses[0].Host != "foo.example.com" {
		t.Fatalf("Manager.Status() = %+v, want the added remote reconciled into the running set", statuses)
	}
}

// TestAddSkipsBindProofWhenAlreadyConnected: a re-Add of a host the running
// Manager already reports connected must tell Verify to skip the bind proof
// (VerifyOptions.SkipBindProof) — binding the remote socket again would race
// the daemon's own live listener and fail with EADDRINUSE, a false
// verification failure on a perfectly healthy host. The very first Add, with
// nothing yet running, must still request the full check.
func TestAddSkipsBindProofWhenAlreadyConnected(t *testing.T) {
	key, fp := testHostKey(t)
	v := &capturingVerifier{result: VerifyResult{Verified: true, HostKey: key, Fingerprint: fp}}
	g, _ := newTestRegistry(t, v)
	ctx := context.Background()
	opts := AddOptions{AcceptFingerprint: fp}

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, opts); err != nil {
		t.Fatal(err)
	}
	if len(v.optsCalls) != 1 || v.optsCalls[0].SkipBindProof {
		t.Fatalf("initial Add() requested SkipBindProof = %+v, want false (nothing running yet)", v.optsCalls)
	}

	// Mark the reconciled remote as connected, the way the running Manager
	// would once ServeForward actually establishes the connection.
	mr := g.mgr.remotes[normalizeHost("foo.example.com")]
	if mr == nil {
		t.Fatal("Add() did not reconcile a managed remote for foo.example.com")
	}
	mr.setState(StateConnected, nil)

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com", Port: 2222}, opts); err != nil {
		t.Fatalf("re-Add() = %v", err)
	}
	if len(v.optsCalls) != 2 || !v.optsCalls[1].SkipBindProof {
		t.Fatalf("re-Add() of a connected host requested SkipBindProof = %+v, want true", v.optsCalls)
	}
}

// TestConcurrentAddDoesNotLoseUpdates is part of I6: the mutex exists
// specifically to serialise concurrent web requests, but nothing exercised
// that concurrently before this.
func TestConcurrentAddDoesNotLoseUpdates(t *testing.T) {
	key, fp := testHostKey(t)
	v := &fakeVerifier{result: VerifyResult{Verified: true, HostKey: key, Fingerprint: fp}}
	g, path := newTestRegistry(t, v)
	ctx := context.Background()
	opts := AddOptions{AcceptFingerprint: fp}

	hosts := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"}
	var wg sync.WaitGroup
	for _, h := range hosts {
		h := h
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := g.Add(ctx, Remote{Host: h}, opts); err != nil {
				t.Errorf("Add(%s) = %v", h, err)
			}
		}()
	}
	wg.Wait()

	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Remotes) != len(hosts) {
		t.Fatalf("persisted %d remotes, want %d (lost update under concurrency)", len(f.Remotes), len(hosts))
	}
}

// TestAddUnderInsecurePolicyPreservesExistingPin is S1's test. Under
// insecure_ignore_host_key the verifier reports Verified:false, and Add used
// to blank the stored key — so an ordinary re-Add destroyed a pin that had
// been properly verified earlier. Turning the flag back off would then leave
// the host unpinned, and an active MITM would meet a confirmable first-use
// prompt instead of ErrHostKeyMismatch.
func TestAddUnderInsecurePolicyPreservesExistingPin(t *testing.T) {
	key, fp := testHostKey(t)
	v := &stepVerifier{steps: []VerifyResult{
		{Verified: true, HostKey: key, Fingerprint: fp}, // initial Add: pins the key
		{Verified: false}, // re-Add under an insecure policy
	}}
	g, path := newTestRegistry(t, v)
	ctx := context.Background()

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: fp}); err != nil {
		t.Fatal(err)
	}

	got, err := g.Add(ctx, Remote{Host: "foo.example.com", Port: 2222}, AddOptions{})
	if err != nil {
		t.Fatalf("re-Add under an insecure policy = %v", err)
	}
	if got.HostKey != key {
		t.Errorf("returned entry lost its pin: HostKey = %q, want %q", got.HostKey, key)
	}

	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Remotes) != 1 || f.Remotes[0].HostKey != key {
		t.Fatalf("re-Add under an insecure policy destroyed the stored pin: %+v", f.Remotes)
	}
}

// TestAddRefusesWhenPinChangedDuringVerification is the R2 TOCTOU test. Add
// reads the stored pin before its network dial, deliberately outside the
// transaction so a slow host cannot wedge every other mutation. A re-pin
// committed by another caller during that dial must not be silently reverted
// by this Add: it must refuse and tell the caller to retry.
//
// The concurrent commit is staged from inside the verifier — the one seam
// that runs at exactly the right moment — rather than by racing two
// goroutines and hoping for the interleaving.
func TestAddRefusesWhenPinChangedDuringVerification(t *testing.T) {
	key, fp := testHostKey(t)
	otherKey, _ := testHostKey(t)

	var g *Registry
	var path string
	v := &fakeVerifierFunc{fn: func(ctx context.Context, r Remote, _ VerifyOptions) (VerifyResult, error) {
		// Stand in for another request committing a re-pin while this
		// Add's dial is in flight.
		f, err := Load(path)
		if err != nil {
			return VerifyResult{}, err
		}
		f.Upsert(Remote{Host: r.Host, RemoteSocket: DefaultRemoteSocket, HostKey: otherKey})
		if err := Save(path, f); err != nil {
			return VerifyResult{}, err
		}
		return VerifyResult{Verified: true, HostKey: key, Fingerprint: fp}, nil
	}}
	g, path = newTestRegistry(t, v)

	_, err := g.Add(context.Background(), Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: fp})
	if err == nil {
		t.Fatal("Add() succeeded despite a concurrent re-pin; want a retry error")
	}
	if !strings.Contains(err.Error(), "changed concurrently") {
		t.Fatalf("Add() = %v, want a 'changed concurrently' retry error", err)
	}

	f, loadErr := Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(f.Remotes) != 1 || f.Remotes[0].HostKey != otherKey {
		t.Fatalf("the concurrent re-pin was clobbered: %+v", f.Remotes)
	}
}

// fakeVerifierFunc adapts a func to Verifier for tests that need to act at
// the exact moment verification runs.
type fakeVerifierFunc struct {
	fn func(context.Context, Remote, VerifyOptions) (VerifyResult, error)
}

func (f *fakeVerifierFunc) Verify(ctx context.Context, r Remote, o VerifyOptions) (VerifyResult, error) {
	return f.fn(ctx, r, o)
}

// socketOf returns the RemoteSocket and state the running Manager currently
// has for host, or empty strings when it has no entry. It goes through Status
// rather than reaching into m.remotes because a deferred reconcile mutates
// that map from its own goroutine.
func socketOf(g *Registry, host string) (socket, state string) {
	for _, st := range g.mgr.Status() {
		if strings.EqualFold(st.Host, host) {
			return st.RemoteSocket, st.State
		}
	}
	return "", ""
}

func waitForSocket(t *testing.T, g *Registry, host, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ := socketOf(g, host); got == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	got, _ := socketOf(g, host)
	t.Fatalf("running set socket = %q, want %q within the deferred window", got, want)
}

// TestPatchDeferredReconcileReturnsBeforeReconciling is the whole point of
// ReconcileDelay: the caller — a migration reached through the very forward
// being changed — must have its response before the running set moves.
func TestPatchDeferredReconcileReturnsBeforeReconciling(t *testing.T) {
	g, _ := newTestRegistry(t, &fakeVerifier{result: VerifyResult{Verified: true}})
	ctx := context.Background()

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{}); err != nil {
		t.Fatal(err)
	}
	if before, _ := socketOf(g, "foo.example.com"); before != DefaultRemoteSocket {
		t.Fatalf("seeded running socket = %q, want %q", before, DefaultRemoteSocket)
	}

	want := "/tmp/dotvault-deferred.sock"
	// 400ms, not a handful: the assertion immediately below is a negative one
	// ("has not reconciled yet"), and a window measured in tens of
	// milliseconds is one scheduling hiccup away from a false pass. The
	// positive half polls with its own deadline, so the larger delay costs
	// the test nothing.
	got, err := g.Patch(ctx, "foo.example.com", Patch{RemoteSocket: &want, ReconcileDelay: 400 * time.Millisecond})
	if err != nil {
		t.Fatalf("Patch() = %v", err)
	}
	if got.RemoteSocket != want {
		t.Errorf("Patch() returned socket %q, want %q", got.RemoteSocket, want)
	}
	if live, _ := socketOf(g, "foo.example.com"); live != DefaultRemoteSocket {
		t.Fatalf("running set already reconciled to %q before Patch returned; the delay did nothing", live)
	}

	// The file is durable immediately, whatever the running set is doing.
	f, err := Load(g.path)
	if err != nil {
		t.Fatal(err)
	}
	if i, ok := f.Find("foo.example.com"); !ok || f.Remotes[i].RemoteSocket != want {
		t.Fatalf("ssh.yaml = %+v, want the patch saved before the reconcile", f.Remotes)
	}

	waitForSocket(t, g, "foo.example.com", want)
}

// TestPatchDeferredReconcileUsesLatestFile: the deferred reconcile re-reads
// ssh.yaml rather than replaying the entry its own Patch committed, so an edit
// that lands inside the window is not silently reverted by a stale snapshot
// firing late.
func TestPatchDeferredReconcileUsesLatestFile(t *testing.T) {
	g, _ := newTestRegistry(t, &fakeVerifier{result: VerifyResult{Verified: true}})
	ctx := context.Background()

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{}); err != nil {
		t.Fatal(err)
	}

	const deferred = 400 * time.Millisecond
	want := "/tmp/dotvault-latest.sock"
	if _, err := g.Patch(ctx, "foo.example.com", Patch{RemoteSocket: &want, ReconcileDelay: deferred}); err != nil {
		t.Fatalf("deferred Patch() = %v", err)
	}

	// A second, ordinary mutation inside the deferred window. If the deferred
	// reconcile replayed the list it saw, this would be undone and the remote
	// would come back up enabled.
	off := false
	if _, err := g.Patch(ctx, "foo.example.com", Patch{Enabled: &off}); err != nil {
		t.Fatalf("synchronous Patch() = %v", err)
	}
	if _, state := socketOf(g, "foo.example.com"); state != string(StateDisabled) {
		t.Fatalf("running state = %q after the synchronous patch, want %q", state, StateDisabled)
	}

	// Polled across the window rather than sampled once after a fixed sleep.
	// A correct deferred pass converges on the state the synchronous patch
	// already produced, so there is nothing new to wait *for* — the property
	// is that the earlier snapshot is never replayed, and checking
	// continuously catches a revert that a single late sample could miss
	// (a resurrected runner moves through several states of its own).
	deadline := time.Now().Add(deferred + time.Second)
	for time.Now().Before(deadline) {
		socket, state := socketOf(g, "foo.example.com")
		if state != string(StateDisabled) {
			t.Fatalf("running state = %q, want %q: the deferred reconcile reverted a later edit", state, StateDisabled)
		}
		if socket != want {
			t.Fatalf("running socket = %q, want %q: both changes should be present throughout", socket, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestPatchRejectsOutOfRangeReconcileDelay: an unusable delay is a malformed
// request, so nothing is written — the file must be untouched, not saved with
// the reconcile quietly skipped.
func TestPatchRejectsOutOfRangeReconcileDelay(t *testing.T) {
	g, path := newTestRegistry(t, &fakeVerifier{result: VerifyResult{Verified: true}})
	ctx := context.Background()

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{}); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name  string
		delay time.Duration
	}{
		{"above the cap", MaxReconcileDelay + time.Second},
		{"negative", -time.Second},
	} {
		want := "/tmp/dotvault-rejected.sock"
		got, err := g.Patch(ctx, "foo.example.com", Patch{RemoteSocket: &want, ReconcileDelay: c.delay})
		if err == nil {
			t.Fatalf("%s: Patch() = (%+v, nil), want a validation error", c.name, got)
		}
		if !strings.Contains(err.Error(), "reconcile delay") {
			t.Errorf("%s: Patch() = %v, want an error naming the reconcile delay", c.name, err)
		}
		f, loadErr := Load(path)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if i, ok := f.Find("foo.example.com"); !ok || f.Remotes[i].RemoteSocket == want {
			t.Errorf("%s: ssh.yaml = %+v, want it untouched", c.name, f.Remotes)
		}
	}
}
