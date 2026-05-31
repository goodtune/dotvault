package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

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
