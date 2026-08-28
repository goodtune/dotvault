package agent

import (
	"runtime"
	"testing"
	"time"

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

// TestNewServiceWiresTokenProbe pins the wiring that makes serving the agent
// before authentication safe. NewService must bind the backend's token probe
// to the Vault client, so a daemon that is listening but has not authenticated
// answers an empty list without a Vault round trip. Without this, the listener
// starting early would put doomed calls on the pre-auth path — the whole point
// of the probe — and nothing else in the package would notice.
func TestNewServiceWiresTokenProbe(t *testing.T) {
	vc := testVaultClient(t)
	cfg := config.AgentConfig{
		Enabled: true,
		Keys:    []config.AgentKeySource{{Source: "kv", PathPrefix: "ssh/"}},
	}
	svc, err := NewService(cfg, vc, "kv", "users/", "me", nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	// No token: the probe must short-circuit before any source is consulted.
	// The client points at a closed port, so a source that were consulted
	// would block on a dial rather than answering — which is exactly the
	// stall the probe exists to prevent.
	done := make(chan int, 1)
	go func() {
		keys, err := svc.Backend.List()
		if err != nil {
			t.Errorf("List: %v", err)
		}
		done <- len(keys)
	}()
	select {
	case n := <-done:
		if n != 0 {
			t.Errorf("want no identities without a token, got %d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("List consulted Vault without a token; the probe is not wired")
	}

	if svc.Backend.haveToken() {
		t.Error("haveToken() true with an empty client token; the probe is not bound to the client")
	}
	vc.SetToken("s.fake")
	if !svc.Backend.haveToken() {
		t.Error("haveToken() false after SetToken; the probe is not reading the live client")
	}
}
