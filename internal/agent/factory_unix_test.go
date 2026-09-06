//go:build !windows

package agent

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

func TestNewSourcesUpstreamAgentAutoDetects(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket resolution")
	}
	// An `agent` source with no socket configured auto-detects: it finds the
	// agent this user is actually running rather than a path someone wrote
	// down. Standing a real agent up at the systemd-convention location under
	// a temp XDG_RUNTIME_DIR is the whole contract in one assertion.
	rt := isolateDiscovery(t)
	priv, pub := genUpstreamKey(t)
	serveUpstreamAgentAt(t, filepath.Join(rt, "ssh-agent.socket"), priv)

	vc := testVaultClient(t)
	cfg := config.AgentConfig{
		Enabled: true,
		Keys: []config.AgentKeySource{
			{Source: "kv", PathPrefix: "ssh/"},
			{Source: "agent"}, // empty socket -> auto-detect
		},
	}
	sources, err := NewSourcesFromConfig(cfg, vc, "kv", "users/", "me")
	if err != nil {
		t.Fatalf("NewSourcesFromConfig: %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("want 2 sources, got %d", len(sources))
	}
	if sources[1].Type() != "agent" {
		t.Errorf("source[1] type = %q, want agent", sources[1].Type())
	}
	ids, err := sources[1].Identities(context.Background())
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if len(ids) != 1 || !keyEqual(ids[0].PubKey, pub) {
		t.Fatalf("auto-detect did not surface the running agent's key (got %d identities)", len(ids))
	}
	if eps := sources[1].(*upstreamSource).Endpoints(); len(eps) != 1 || eps[0] != filepath.Join(rt, "ssh-agent.socket") {
		t.Errorf("Endpoints() = %v, want the discovered socket", eps)
	}
}

func TestNewSourcesUpstreamAgentExplicitSocketPinsIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket resolution")
	}
	// An explicit socket disables detection and pins the source to exactly
	// that endpoint — the escape hatch for an agent at a path the candidate
	// list does not know.
	rt := isolateDiscovery(t)
	priv, pub := genUpstreamKey(t)
	explicit := filepath.Join(t.TempDir(), "elsewhere.sock")
	serveUpstreamAgentAt(t, explicit, priv)
	// A decoy at the auto-detect location, which must NOT be consulted.
	decoyPriv, _ := genUpstreamKey(t)
	serveUpstreamAgentAt(t, filepath.Join(rt, "ssh-agent.socket"), decoyPriv)

	vc := testVaultClient(t)
	cfg := config.AgentConfig{
		Enabled: true,
		Keys:    []config.AgentKeySource{{Source: "agent", Socket: explicit}},
	}
	sources, err := NewSourcesFromConfig(cfg, vc, "kv", "users/", "me")
	if err != nil {
		t.Fatalf("NewSourcesFromConfig: %v", err)
	}
	ids, err := sources[0].Identities(context.Background())
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if len(ids) != 1 || !keyEqual(ids[0].PubKey, pub) {
		t.Fatalf("explicit socket should serve only its own key, got %d identities", len(ids))
	}
}
