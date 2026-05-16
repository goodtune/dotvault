package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
