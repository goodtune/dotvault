package agent

import (
	"runtime"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// TestResolveServeEndpointsNonWindows confirms that off Windows the agent only
// ever serves the primary endpoint — the Pageant pipe is a Windows-only
// concept and PuttyEnabled() must not introduce a phantom second listener.
func TestResolveServeEndpointsNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-windows behaviour")
	}
	cfg := config.AgentConfig{Enabled: true} // Putty unset => PuttyEnabled() true
	got := resolveServeEndpoints(cfg, "/run/user/1000/dotvault/agent.sock")
	if len(got) != 1 || got[0] != "/run/user/1000/dotvault/agent.sock" {
		t.Errorf("non-windows endpoints = %v, want single primary", got)
	}
}

// TestResolveServeEndpointsPrimaryAlwaysPresent confirms the primary endpoint
// is always first regardless of platform/putty resolution.
func TestResolveServeEndpointsPrimaryAlwaysPresent(t *testing.T) {
	cfg := config.AgentConfig{Enabled: true}
	got := resolveServeEndpoints(cfg, "primary-endpoint")
	if len(got) < 1 || got[0] != "primary-endpoint" {
		t.Errorf("primary endpoint must be present and first, got %v", got)
	}
}
