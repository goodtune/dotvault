package main

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// buildTestBinary builds the dotvault binary for a subprocess test, with the
// system config path relocated to a directory that does not exist.
//
// Tests that pass --config are otherwise refused on any machine where dotvault
// is actually installed: --config is rejected whenever a system-wide config
// exists without bypass_system_config, and macOS hardcodes
// /Library/Application Support/dotvault/config.yaml. That made these tests pass
// on CI (nothing installed) and fail on every developer machine that runs the
// product — a difference in the developer's environment, not in the code.
//
// Relocating at build time rather than via an environment variable is
// deliberate: the bypass gate exists to stop a user overriding managed config,
// and env is user-controlled. See internal/paths.systemConfigOverride.
func buildTestBinary(t *testing.T, binPath string) {
	t.Helper()
	// Inside t.TempDir(), so it is guaranteed absent and cleaned up with the test.
	absent := filepath.Join(t.TempDir(), "no-system-config", "config.yaml")
	build := exec.Command("go", "build",
		"-ldflags", "-X github.com/goodtune/dotvault/internal/paths.systemConfigOverride="+absent,
		"-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build test binary: %v\n%s", err, out)
	}
}
