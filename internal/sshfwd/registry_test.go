package sshfwd

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

type fakeVerifier struct {
	result VerifyResult
	err    error
	calls  int
}

func (f *fakeVerifier) Verify(ctx context.Context, r Remote) (VerifyResult, error) {
	f.calls++
	return f.result, f.err
}

func newTestRegistry(t *testing.T, v Verifier) (*Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh.yaml")
	m := NewManager(Deps{})
	m.newRunner = func(string) func(context.Context) {
		return func(ctx context.Context) { <-ctx.Done() }
	}
	t.Cleanup(m.Close)
	return NewRegistry(path, m, v), path
}

func TestAddRequiresFingerprintConfirmation(t *testing.T) {
	v := &fakeVerifier{result: VerifyResult{
		HostKey:        "ssh-ed25519 AAAAC3Nz",
		Fingerprint:    "SHA256:abc",
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
	v := &fakeVerifier{result: VerifyResult{
		HostKey:        "ssh-ed25519 AAAAC3Nz",
		Fingerprint:    "SHA256:abc",
		ResolvedSocket: "/home/me/.ssh/dotvault.sock",
	}}
	g, path := newTestRegistry(t, v)

	got, err := g.Add(context.Background(), Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: "SHA256:abc"})
	if err != nil {
		t.Fatalf("Add() = %v", err)
	}
	if got.HostKey != "ssh-ed25519 AAAAC3Nz" {
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
	v := &fakeVerifier{result: VerifyResult{Fingerprint: "SHA256:abc", HostKey: "k"}}
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
	v := &fakeVerifier{result: VerifyResult{Fingerprint: "SHA256:abc", HostKey: "k"}}
	g, path := newTestRegistry(t, v)
	ctx := context.Background()
	opts := AddOptions{AcceptFingerprint: "SHA256:abc"}

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
	v := &fakeVerifier{result: VerifyResult{Fingerprint: "SHA256:abc", HostKey: "k"}}
	g, _ := newTestRegistry(t, v)
	ctx := context.Background()

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: "SHA256:abc"}); err != nil {
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
	v := &fakeVerifier{result: VerifyResult{Fingerprint: "SHA256:abc", HostKey: "k"}}
	g, path := newTestRegistry(t, v)
	ctx := context.Background()

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: "SHA256:abc"}); err != nil {
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

func TestPatchRejectsInvalidSocket(t *testing.T) {
	v := &fakeVerifier{result: VerifyResult{Fingerprint: "SHA256:abc", HostKey: "k"}}
	g, _ := newTestRegistry(t, v)
	ctx := context.Background()
	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: "SHA256:abc"}); err != nil {
		t.Fatal(err)
	}
	bad := "relative/path.sock"
	if _, err := g.Patch(ctx, "foo.example.com", Patch{RemoteSocket: &bad}); err == nil {
		t.Fatal("Patch() accepted an invalid remote_socket")
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
// running under an insecure policy reports success with no HostKey/
// Fingerprint (per the Verifier doc comment), and Add must not invent a pin
// from nothing — the persisted entry's HostKey stays empty.
func TestAddInsecurePolicyDoesNotPinAKey(t *testing.T) {
	v := &fakeVerifier{result: VerifyResult{}} // insecure: nothing observed, nil error
	g, path := newTestRegistry(t, v)

	got, err := g.Add(context.Background(), Remote{Host: "foo.example.com"}, AddOptions{})
	if err != nil {
		t.Fatalf("Add() = %v, want success with no confirmation required", err)
	}
	if got.HostKey != "" {
		t.Fatalf("Add() pinned HostKey %q under an insecure policy, want empty", got.HostKey)
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
