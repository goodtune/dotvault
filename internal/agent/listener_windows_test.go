//go:build windows

package agent

import (
	"regexp"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// TestPageantPipeNameShape confirms the derived Pageant pipe matches PuTTY's
// \\.\pipe\pageant.<user>.<64-hex> convention and that the suffix is a stable
// 64-char hex SHA-256 digest.
func TestPageantPipeNameShape(t *testing.T) {
	name, err := pageantPipeName()
	if err != nil {
		t.Fatalf("pageantPipeName: %v", err)
	}
	re := regexp.MustCompile(`^\\\\\.\\pipe\\pageant\.[^.]+\.[0-9a-f]{64}$`)
	if !re.MatchString(name) {
		t.Errorf("pageant pipe %q does not match expected shape", name)
	}
}

// TestCapiObfuscateStringStable confirms the obfuscation is deterministic
// within a boot session: PuTTY and dotvault must agree on the suffix for the
// same process to find the same pipe.
func TestCapiObfuscateStringStable(t *testing.T) {
	a, err := capiObfuscateString(pageantClassName)
	if err != nil {
		t.Fatalf("capiObfuscateString: %v", err)
	}
	b, err := capiObfuscateString(pageantClassName)
	if err != nil {
		t.Fatalf("capiObfuscateString: %v", err)
	}
	if a != b {
		t.Errorf("obfuscation not stable within a session: %q != %q", a, b)
	}
	if len(a) != 64 {
		t.Errorf("hex digest len = %d, want 64", len(a))
	}
}

// TestResolveServeEndpointsPuttyDisabled confirms that turning putty off leaves
// only the primary pipe on Windows.
func TestResolveServeEndpointsPuttyDisabled(t *testing.T) {
	off := false
	cfg := config.AgentConfig{Enabled: true, Windows: config.AgentWindowsConfig{Putty: &off}}
	got := resolveServeEndpoints(cfg, `\\.\pipe\dotvault-agent`)
	if len(got) != 1 || got[0] != `\\.\pipe\dotvault-agent` {
		t.Errorf("putty=false endpoints = %v, want single primary", got)
	}
}

// TestResolveServeEndpointsPuttyDefault confirms the default (unset) serves both
// the primary pipe and the Pageant pipe on Windows. If CryptProtectMemory is
// unavailable in a constrained CI sandbox the production path degrades to
// primary-only (logged + skipped); the test mirrors that fallback rather than
// hard-failing on it, since the degraded path is the documented behaviour.
func TestResolveServeEndpointsPuttyDefault(t *testing.T) {
	cfg := config.AgentConfig{Enabled: true} // Putty unset => default true
	got := resolveServeEndpoints(cfg, `\\.\pipe\dotvault-agent`)
	if len(got) < 1 || got[0] != `\\.\pipe\dotvault-agent` {
		t.Fatalf("primary must be present and first, got %v", got)
	}
	if _, err := pageantPipeName(); err != nil {
		t.Skipf("pageant pipe unavailable in this environment (%v); production degrades to primary-only", err)
	}
	if len(got) != 2 {
		t.Fatalf("default putty endpoints = %v, want primary + pageant", got)
	}
}
