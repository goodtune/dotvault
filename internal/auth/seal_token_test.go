package auth

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSealTokenAtRest(t *testing.T) {
	cases := map[string]bool{
		"oidc":     false,
		"ldap":     false,
		"token":    false,
		"mtls":     false,
		"oidc+tpm": true,
		"ldap+tpm": true,
		"mtls+tpm": true,
		"":         false,
	}
	for method, want := range cases {
		if got := SealTokenAtRest(method); got != want {
			t.Errorf("SealTokenAtRest(%q) = %v, want %v", method, got, want)
		}
	}
}

func TestBaseMethod(t *testing.T) {
	cases := map[string]string{
		"oidc":     "oidc",
		"oidc+tpm": "oidc",
		"ldap+tpm": "ldap",
		"mtls+tpm": "mtls",
		"token":    "token",
	}
	for method, want := range cases {
		if got := BaseMethod(method); got != want {
			t.Errorf("BaseMethod(%q) = %q, want %q", method, got, want)
		}
	}
}

// The tests below swap the package-level sealData/unsealData/hardwareAvailable
// hooks and restore them via t.Cleanup. They must therefore run serially — do
// NOT add t.Parallel() to these tests or their subtests, or the shared hooks
// would race.
//
// fakeSeal/fakeUnseal are a reversible stand-in for the TPM so the envelope
// format and call-site policy can be exercised without hardware.
func fakeSeal(b []byte) ([]byte, error) { return append([]byte("SEALED:"), b...), nil }
func fakeUnseal(h []byte) ([]byte, error) {
	rest, ok := bytes.CutPrefix(h, []byte("SEALED:"))
	if !ok {
		return nil, errors.New("not a fake-sealed blob")
	}
	return rest, nil
}

func withFakeSealer(t *testing.T) {
	t.Helper()
	prevSeal, prevUnseal := sealData, unsealData
	sealData, unsealData = fakeSeal, fakeUnseal
	t.Cleanup(func() { sealData, unsealData = prevSeal, prevUnseal })
}

func TestWriteReadSealedTokenRoundTrip(t *testing.T) {
	withFakeSealer(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".dotvault-token")

	if err := WriteTokenFile(path, "hvs.secret-token", true); err != nil {
		t.Fatalf("WriteTokenFile(seal): %v", err)
	}

	raw, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(raw), sealedTokenPrefix) {
		t.Fatalf("sealed file missing prefix; got %q", raw)
	}
	if strings.Contains(string(raw), "hvs.secret-token") {
		t.Fatalf("plaintext token leaked into sealed file: %q", raw)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0600 {
		t.Errorf("permissions = %o, want 0600", info.Mode().Perm())
	}

	got, err := ReadTokenFile(path)
	if err != nil {
		t.Fatalf("ReadTokenFile: %v", err)
	}
	if got != "hvs.secret-token" {
		t.Errorf("round-trip token = %q, want %q", got, "hvs.secret-token")
	}
}

// An empty token must round-trip cleanly through sealing (harmless: an empty
// token is rejected Vault-side anyway, but WriteTokenFile must not choke on
// it, and ReadTokenFile must return "" rather than mis-detecting the prefix).
func TestWriteReadSealedEmptyToken(t *testing.T) {
	withFakeSealer(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".dotvault-token")

	if err := WriteTokenFile(path, "", true); err != nil {
		t.Fatalf("WriteTokenFile(seal, empty): %v", err)
	}
	got, err := ReadTokenFile(path)
	if err != nil {
		t.Fatalf("ReadTokenFile: %v", err)
	}
	if got != "" {
		t.Errorf("round-trip empty token = %q, want empty", got)
	}
}

// A plaintext token file written by an older dotvault (or under a non-+tpm
// method) must still read back verbatim — auto-detection makes migration free.
func TestReadPlaintextTokenStillWorks(t *testing.T) {
	withFakeSealer(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".dotvault-token")
	os.WriteFile(path, []byte("hvs.plaintext\n"), 0600)

	got, err := ReadTokenFile(path)
	if err != nil {
		t.Fatalf("ReadTokenFile: %v", err)
	}
	if got != "hvs.plaintext" {
		t.Errorf("token = %q, want %q", got, "hvs.plaintext")
	}
}

func TestWriteSealedTokenSealerError(t *testing.T) {
	prevSeal := sealData
	sealData = func([]byte) ([]byte, error) { return nil, errors.New("no tpm") }
	t.Cleanup(func() { sealData = prevSeal })

	dir := t.TempDir()
	path := filepath.Join(dir, ".dotvault-token")
	if err := WriteTokenFile(path, "hvs.secret", true); err == nil {
		t.Fatal("WriteTokenFile(seal) should error when sealing fails")
	}
	// Crucially, no plaintext fallback file is written.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		raw, _ := os.ReadFile(path)
		t.Fatalf("a token file was written despite seal failure: %q", raw)
	}
}

func TestReadSealedTokenUnsealError(t *testing.T) {
	withFakeSealer(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".dotvault-token")
	// A sealed envelope whose body is valid base64 but not a fake-sealed blob.
	os.WriteFile(path, []byte(sealedTokenPrefix+"aGVsbG8="), 0600)

	got, err := ReadTokenFile(path)
	if err == nil {
		t.Fatal("ReadTokenFile should error when unseal fails")
	}
	if got != "" {
		t.Errorf("token = %q, want empty on unseal failure", got)
	}
	// ResolveToken swallows the error and yields "" → caller re-authenticates.
	t.Setenv("DOTVAULT_TOKEN", "")
	if tok := ResolveToken(path); tok != "" {
		t.Errorf("ResolveToken = %q, want empty on unseal failure", tok)
	}
}

// A sealed-prefixed file whose body is not valid base64 must surface a decode
// error before any unseal is attempted — covers the base64 branch in
// ReadTokenFile distinctly from an unseal failure.
func TestReadSealedTokenBadBase64(t *testing.T) {
	unsealCalled := false
	prev := unsealData
	unsealData = func([]byte) ([]byte, error) { unsealCalled = true; return nil, nil }
	t.Cleanup(func() { unsealData = prev })

	dir := t.TempDir()
	path := filepath.Join(dir, ".dotvault-token")
	os.WriteFile(path, []byte(sealedTokenPrefix+"not!valid!base64!"), 0600)

	got, err := ReadTokenFile(path)
	if err == nil {
		t.Fatal("ReadTokenFile should error on a non-base64 sealed body")
	}
	if got != "" {
		t.Errorf("token = %q, want empty", got)
	}
	if unsealCalled {
		t.Error("unseal was attempted despite a base64 decode failure")
	}
}

func TestLoginTPMPreflight(t *testing.T) {
	ctx := context.Background()

	// Non-"+tpm" method: preflight must be skipped entirely.
	t.Run("skipped for non-tpm method", func(t *testing.T) {
		called := false
		prev := hardwareAvailable
		hardwareAvailable = func() error { called = true; return errors.New("no tpm") }
		t.Cleanup(func() { hardwareAvailable = prev })

		m := &Manager{AuthMethod: "token", TokenFilePath: "/nope"}
		if err := m.Login(ctx); err == nil {
			t.Fatal("token Login should error (no token)")
		}
		if called {
			t.Error("hardware preflight ran for a non-+tpm method")
		}
	})

	// "+tpm" with no hardware: fail fast with a clear, method-named error,
	// before reaching the auth flow.
	t.Run("fails fast without hardware", func(t *testing.T) {
		prev := hardwareAvailable
		hardwareAvailable = func() error { return errors.New("no tpm device") }
		t.Cleanup(func() { hardwareAvailable = prev })

		m := &Manager{AuthMethod: "token+tpm", TokenFilePath: "/nope"}
		err := m.Login(ctx)
		if err == nil || !strings.Contains(err.Error(), "TPM") {
			t.Fatalf("Login err = %v, want a TPM-availability error", err)
		}
	})

	// "+tpm" with hardware present: preflight passes, flow proceeds (the
	// "token" branch errors without any network call).
	t.Run("proceeds with hardware", func(t *testing.T) {
		called := false
		prev := hardwareAvailable
		hardwareAvailable = func() error { called = true; return nil }
		t.Cleanup(func() { hardwareAvailable = prev })

		m := &Manager{AuthMethod: "token+tpm", TokenFilePath: "/nope"}
		err := m.Login(ctx)
		if !called {
			t.Error("hardware preflight did not run for a +tpm method")
		}
		if err == nil || strings.Contains(err.Error(), "TPM") {
			t.Fatalf("Login err = %v, want the downstream token error (preflight passed)", err)
		}
	})
}
