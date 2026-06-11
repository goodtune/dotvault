package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/paths"
)

// minimalConfigYAML is a config body that passes config validation.
const minimalConfigYAML = `vault:
  address: "https://vault.example.com:8200"
rules:
  - name: r
    vault_key: r
    target:
      path: "~/.dotvault/r"
      format: text
`

// TestResolveConfigSourceOverridePolicy exercises the --config override gate:
// when a system-wide config is present, the override is refused unless that
// config sets bypass_system_config: true. The test stands up a fake system
// config via XDG_CONFIG_DIRS (a Linux-only mechanism, so it is skipped
// elsewhere) so paths.SystemConfigPath resolves to a file under our control.
func TestResolveConfigSourceOverridePolicy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("relies on XDG_CONFIG_DIRS to plant a system config; Linux-only")
	}

	origFlag := flagConfig
	t.Cleanup(func() { flagConfig = origFlag })

	planSystemConfig := func(t *testing.T, body string) {
		t.Helper()
		dir := t.TempDir()
		cfgDir := filepath.Join(dir, "dotvault")
		if err := os.MkdirAll(cfgDir, 0755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(cfgDir, "config.yaml"), []byte(body), 0644); err != nil {
			t.Fatalf("write system config: %v", err)
		}
		t.Setenv("XDG_CONFIG_DIRS", dir)
	}
	writeOverride := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "override.yaml")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatalf("write override: %v", err)
		}
		return path
	}

	t.Run("refused when system config present without bypass", func(t *testing.T) {
		planSystemConfig(t, minimalConfigYAML)
		flagConfig = writeOverride(t, minimalConfigYAML)
		if _, _, err := resolveConfigSource(); err == nil {
			t.Fatal("expected --config override to be refused")
		} else if !strings.Contains(err.Error(), "is refused") {
			t.Errorf("error = %v, want it to explain the override is refused", err)
		}
	})

	t.Run("allowed when system config opts in", func(t *testing.T) {
		planSystemConfig(t, minimalConfigYAML+"bypass_system_config: true\n")
		override := writeOverride(t, minimalConfigYAML)
		flagConfig = override

		load, path, err := resolveConfigSource()
		if err != nil {
			t.Fatalf("resolveConfigSource: %v", err)
		}
		if path != override {
			t.Errorf("path = %q, want override path %q", path, override)
		}
		cfg, err := load()
		if err != nil {
			t.Fatalf("load override: %v", err)
		}
		if cfg.Vault.Address != "https://vault.example.com:8200" {
			t.Errorf("override config did not load: Vault.Address = %q", cfg.Vault.Address)
		}

		// The loader closure must close over the resolved override path, not
		// the mutable global: mutating flagConfig after resolution must not
		// redirect a subsequent (reload-loop) load.
		flagConfig = filepath.Join(t.TempDir(), "nonexistent.yaml")
		if _, err := load(); err != nil {
			t.Errorf("loader followed mutated flagConfig instead of the captured override path: %v", err)
		}
	})

	t.Run("allowed when no system config exists", func(t *testing.T) {
		// Point XDG_CONFIG_DIRS at an empty dir so SystemConfigPath finds no
		// per-XDG file and falls back to /etc/xdg/dotvault/config.yaml. If that
		// fixed fallback happens to exist on this host, the "no system config"
		// state is unreachable — skip rather than assert a false negative.
		t.Setenv("XDG_CONFIG_DIRS", t.TempDir())
		if _, err := os.Stat(paths.SystemConfigPath()); err == nil {
			t.Skipf("system config %s exists on this host; cannot exercise the no-config path", paths.SystemConfigPath())
		}
		override := writeOverride(t, minimalConfigYAML)
		flagConfig = override

		load, path, err := resolveConfigSource()
		if err != nil {
			t.Fatalf("resolveConfigSource: %v", err)
		}
		if path != override {
			t.Errorf("path = %q, want override path %q", path, override)
		}
		cfg, err := load()
		if err != nil {
			t.Fatalf("load override: %v", err)
		}
		if cfg.Vault.Address != "https://vault.example.com:8200" {
			t.Errorf("override config did not load: Vault.Address = %q", cfg.Vault.Address)
		}
	})
}

func TestIsGUIBinary(t *testing.T) {
	tests := []struct {
		arg0 string
		want bool
	}{
		{"dotvault", false},
		{"./dotvault", false},
		{"/usr/local/bin/dotvault", false},
		{"dotvault.exe", false},
		{`C:\Program Files\dotvault\dotvault.exe`, false},
		{"dotvaultw", true},
		{"dotvaultw.exe", true},
		{"DotVaultW.exe", true},
		{`C:\Program Files\dotvault\dotvaultw.exe`, true},
		{"./dotvaultw", true},
		{"dotvault-windows-amd64.exe", false},
		{"dotvaultw-windows-amd64.exe", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.arg0, func(t *testing.T) {
			if got := isGUIBinary(tc.arg0); got != tc.want {
				t.Errorf("isGUIBinary(%q) = %v, want %v", tc.arg0, got, tc.want)
			}
		})
	}
}

// TestPrintLoginNotice exercises the happy paths for the explanation
// message printed before login-check drops into an interactive auth
// prompt. The colour gate is exercised by writing to a *bytes.Buffer
// (not os.Stderr), which forces plain-text output regardless of the
// surrounding test environment's TTY state — covering both the
// content of the message and the fact that ANSI escapes are gated
// on the writer identity rather than emitted unconditionally.
func TestPrintLoginNotice(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		want   string
	}{
		{
			name:   "missing token",
			reason: "no cached Vault token was found",
			want:   "dotvault: no cached Vault token was found — starting Vault login flow...\n",
		},
		{
			name:   "expired token",
			reason: "the cached Vault token has expired",
			want:   "dotvault: the cached Vault token has expired — starting Vault login flow...\n",
		},
		{
			name:   "revoked token",
			reason: "the cached Vault token is no longer valid",
			want:   "dotvault: the cached Vault token is no longer valid — starting Vault login flow...\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			printLoginNotice(&buf, tc.reason)
			if got := buf.String(); got != tc.want {
				t.Errorf("printLoginNotice() = %q, want %q", got, tc.want)
			}
			// Defensive: a buffer is not os.Stderr, so the helper must
			// never emit ANSI colour through it. Catches a future
			// regression where the gate is widened without intent.
			if strings.Contains(buf.String(), "\x1b[") {
				t.Errorf("printLoginNotice() leaked ANSI escape into non-stderr writer: %q", buf.String())
			}
		})
	}
}

// TestStderrSupportsColour verifies the cheap branch of the gating
// logic used by printLoginNotice — NO_COLOR forces false even against
// a real terminal. The "stderr is a TTY" branch can't be exercised
// portably in a unit test (the surrounding test harness drives stderr
// to a pipe), so we accept that gap; the test still pins NO_COLOR
// behaviour, which is the more frequently-broken half.
func TestStderrSupportsColour(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if stderrSupportsColour() {
		t.Error("stderrSupportsColour() with NO_COLOR set = true, want false")
	}
}

// TestRenewTokenWithProgress exercises the single-line progress output of
// the login-check renewal helper. Writing to a *bytes.Buffer (not
// os.Stderr) forces the non-animated branch, so the output is
// deterministic: prefix + static "..." ellipsis + outcome. The renew
// function is injected, so no Vault is needed.
func TestRenewTokenWithProgress(t *testing.T) {
	tests := []struct {
		name    string
		ctx     func() (context.Context, context.CancelFunc)
		renew   func(context.Context) error
		wantErr bool
		wantOut string
	}{
		{
			name:    "success",
			ctx:     func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			renew:   func(context.Context) error { return nil },
			wantErr: false,
			wantOut: "Vault token needs extending... renewed.\n",
		},
		{
			name:    "failure surfaces the error inline",
			ctx:     func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			renew:   func(context.Context) error { return errors.New("permission denied") },
			wantErr: true,
			wantOut: "Vault token needs extending... failed: permission denied\n",
		},
		{
			name: "cancellation writes no outcome",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel() // already cancelled — mimics the SIGINT handler
				return ctx, cancel
			},
			renew:   func(context.Context) error { return context.Canceled },
			wantErr: true,
			// Only the prefix + ellipsis; the SIGINT handler owns the
			// terminating newline, so no " renewed."/" failed:" suffix.
			wantOut: "Vault token needs extending...",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := tc.ctx()
			defer cancel()
			var buf bytes.Buffer
			err := renewTokenWithProgress(ctx, tc.renew, &buf)
			if (err != nil) != tc.wantErr {
				t.Errorf("renewTokenWithProgress() err = %v, wantErr %v", err, tc.wantErr)
			}
			if got := buf.String(); got != tc.wantOut {
				t.Errorf("renewTokenWithProgress() output = %q, want %q", got, tc.wantOut)
			}
		})
	}
}

// TestLoginCheckQuietFlagRegistered locks in the --quiet flag wiring on
// the login-check command. The flag is the user-visible escape hatch
// for the new login notice; deleting it (or renaming it) would silently
// break callers that pass --quiet in their shell wrapper. A subprocess
// test exercising the full flag flow would need a stub Vault server to
// reach the notice branch — out of scope here; this assertion catches
// the regression that matters most cheaply.
func TestLoginCheckQuietFlagRegistered(t *testing.T) {
	cmd := newLoginCheckCmd()
	flag := cmd.Flags().Lookup("quiet")
	if flag == nil {
		t.Fatal("--quiet flag not registered on login-check command")
	}
	if flag.Value.Type() != "bool" {
		t.Errorf("--quiet flag type = %q, want bool", flag.Value.Type())
	}
	if flag.DefValue != "false" {
		t.Errorf("--quiet flag default = %q, want false", flag.DefValue)
	}
}

// TestLoginCheckNoPasswdFlagRegistered locks in the --no-passwd flag
// wiring on the login-check command, for the same reason as the --quiet
// assertion above: fleet profile.d scripts pass it unconditionally, so
// renaming or dropping it would break every deployed wrapper at shell
// startup.
func TestLoginCheckNoPasswdFlagRegistered(t *testing.T) {
	cmd := newLoginCheckCmd()
	flag := cmd.Flags().Lookup("no-passwd")
	if flag == nil {
		t.Fatal("--no-passwd flag not registered on login-check command")
	}
	if flag.Value.Type() != "bool" {
		t.Errorf("--no-passwd flag type = %q, want bool", flag.Value.Type())
	}
	if flag.DefValue != "false" {
		t.Errorf("--no-passwd flag default = %q, want false", flag.DefValue)
	}
}

// TestLoginCheckNoPasswd_Subprocess exercises the --no-passwd early
// exit end-to-end. Both cases run with a deliberately missing --config:
// when the current user appears in the (overridden) passwd file the
// command must exit 0 silently *before* config load is ever reached;
// when the user is absent it must fall through to the normal flow and
// fail at config load like any other invocation.
func TestLoginCheckNoPasswd_Subprocess(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess test")
	}
	if runtime.GOOS == "windows" {
		// --no-passwd is ignored on Windows; the flag-registration test
		// above covers the wiring there.
		t.Skip("subprocess test exercises POSIX passwd semantics")
	}

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "dotvault")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build: %v", err)
	}

	u, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}

	workDir := t.TempDir()
	missingConfig := filepath.Join(workDir, "does-not-exist.yaml")
	baseEnv := append(os.Environ(), "DOTVAULT_SUPPRESS_HOURS=6")

	t.Run("local user exits silently before config load", func(t *testing.T) {
		passwdFile := filepath.Join(workDir, "passwd-with-user")
		entry := u.Username + ":x:1000:1000::/home/" + u.Username + ":/bin/bash\n"
		if err := os.WriteFile(passwdFile, []byte(entry), 0o644); err != nil {
			t.Fatal(err)
		}
		markerPath := filepath.Join(workDir, "marker-local")

		check := exec.Command(binPath, "--config", missingConfig, "login-check", "--no-passwd")
		check.Env = append(baseEnv,
			"DOTVAULT_SUPPRESS_MARKER="+markerPath,
			"DOTVAULT_PASSWD_FILE="+passwdFile,
		)
		check.Stdin = nil
		out, err := check.CombinedOutput()
		if err != nil {
			t.Fatalf("expected silent exit 0 for local user: %v\noutput:\n%s", err, out)
		}
		if len(out) != 0 {
			t.Errorf("expected no output, got: %q", out)
		}
		// The early exit happens past the freshness check, so the
		// marker contract applies: subsequent shells in the window must
		// be silenced without re-parsing the passwd file.
		if _, err := os.Stat(markerPath); err != nil {
			t.Errorf("marker not refreshed on --no-passwd early exit: %v", err)
		}
	})

	t.Run("directory user falls through to normal flow", func(t *testing.T) {
		// The fixture entry is derived from the real username so it can
		// never collide with whoever runs the tests (root in CI, a
		// developer locally).
		passwdFile := filepath.Join(workDir, "passwd-without-user")
		entry := "not-" + u.Username + ":x:0:0::/root:/bin/bash\n"
		if err := os.WriteFile(passwdFile, []byte(entry), 0o644); err != nil {
			t.Fatal(err)
		}
		markerPath := filepath.Join(workDir, "marker-directory")

		check := exec.Command(binPath, "--config", missingConfig, "login-check", "--no-passwd")
		check.Env = append(baseEnv,
			"DOTVAULT_SUPPRESS_MARKER="+markerPath,
			"DOTVAULT_PASSWD_FILE="+passwdFile,
		)
		check.Stdin = nil
		out, err := check.CombinedOutput()
		if err == nil {
			t.Fatalf("expected config-load failure when user absent from passwd file, got exit 0\noutput:\n%s", out)
		}
	})
}

// TestLoginCheckSuppression_SubprocessRoundTrip exercises the spec's
// "Immediate Re-Invocation" integration test: two back-to-back binary
// invocations where the second must observe the marker the first wrote
// and exit silently without a vault call. Uses a non-existent --config
// path so the first invocation fails fast at config load (well before
// the Vault client is constructed) and the test does not require a
// running daemon or Vault instance.
func TestLoginCheckSuppression_SubprocessRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess test")
	}
	if runtime.GOOS == "windows" {
		// PATH and stdio semantics under a go-built test binary differ
		// enough on Windows that the test deserves its own treatment;
		// the unit tests in internal/loginsuppress already cover the
		// platform-independent suppression logic.
		t.Skip("subprocess test exercises POSIX shell-startup semantics")
	}

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "dotvault")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build: %v", err)
	}

	workDir := t.TempDir()
	markerPath := filepath.Join(workDir, "marker")
	missingConfig := filepath.Join(workDir, "does-not-exist.yaml")

	env := append(os.Environ(),
		"DOTVAULT_SUPPRESS_MARKER="+markerPath,
		// Reset the suppression window to the default so the test does
		// not inherit any DOTVAULT_SUPPRESS_HOURS set in the surrounding
		// shell.
		"DOTVAULT_SUPPRESS_HOURS=6",
	)

	first := exec.Command(binPath, "--config", missingConfig, "login-check")
	first.Env = env
	first.Stdin = nil
	if out, err := first.CombinedOutput(); err == nil {
		t.Logf("first invocation output:\n%s", out)
		// First invocation should fail because the config doesn't exist
		// (exit 1 via cobra error). If it succeeded, something is wrong
		// with the test setup, not the suppression logic.
		t.Fatal("first invocation unexpectedly succeeded; test setup is wrong")
	} else {
		t.Logf("first invocation exited (expected): %v\noutput:\n%s", err, out)
	}

	info, err := os.Stat(markerPath)
	if err != nil {
		t.Fatalf("marker not created after first invocation: %v", err)
	}
	mtime1 := info.ModTime()

	// Brief sleep so a missed-suppression path (which would refresh the
	// marker) would produce a visibly different mtime.
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	second := exec.Command(binPath, "--config", missingConfig, "login-check")
	second.Env = env
	second.Stdin = nil
	out2, err := second.CombinedOutput()
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("second invocation failed (should be silent exit 0): %v\noutput:\n%s", err, out2)
	}
	if len(out2) != 0 {
		t.Errorf("second invocation should produce no output, got: %q", out2)
	}
	// Second invocation must be near-instant — well under the time a
	// real vault call would take. 5s is generous to absorb CI noise
	// while still catching accidental network calls.
	if elapsed > 5*time.Second {
		t.Errorf("second invocation took %v, want <5s", elapsed)
	}

	info2, err := os.Stat(markerPath)
	if err != nil {
		t.Fatalf("stat marker after second invocation: %v", err)
	}
	if !info2.ModTime().Equal(mtime1) {
		t.Errorf("suppressed second invocation should not touch marker mtime: was %v, now %v",
			mtime1, info2.ModTime())
	}
}
