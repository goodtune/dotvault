package agent

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
)

func testVaultClient(t *testing.T) *vault.Client {
	t.Helper()
	vc, err := vault.NewClient(vault.Config{Address: "http://127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	return vc
}

func TestNewSourcesFromConfig(t *testing.T) {
	vc := testVaultClient(t)
	cfg := config.AgentConfig{
		Enabled: true,
		Keys: []config.AgentKeySource{
			{Source: "kv", PathPrefix: "ssh/"},
			{Source: "vault-ca", Mount: "ssh-client-signer", Role: "dotvault-user", EphemeralKey: true},
			{Source: "bogus"},
		},
	}
	sources, err := NewSourcesFromConfig(cfg, vc, "kv", "users/", "me")
	if err != nil {
		t.Fatalf("NewSourcesFromConfig: %v", err)
	}
	if len(sources) != 3 {
		t.Fatalf("want 3 sources, got %d", len(sources))
	}
	if sources[0].Type() != "kv" {
		t.Errorf("source[0] type = %q, want kv", sources[0].Type())
	}
	if sources[1].Type() != "vault-ca" {
		t.Errorf("source[1] type = %q, want vault-ca", sources[1].Type())
	}
	// Unknown source becomes an errSource reporting via Identities.
	if _, err := sources[2].Identities(context.Background()); err == nil {
		t.Errorf("unknown source should report an error from Identities")
	}
}

func TestResolveEndpointUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix path resolution")
	}
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1234")
	got := resolveEndpoint(config.AgentConfig{})
	want := filepath.Join("/run/user/1234", "dotvault", "agent.sock")
	if got != want {
		t.Errorf("resolveEndpoint = %q, want %q", got, want)
	}

	got = resolveEndpoint(config.AgentConfig{Unix: config.AgentUnixConfig{Path: "/tmp/custom.sock"}})
	if got != "/tmp/custom.sock" {
		t.Errorf("explicit path = %q", got)
	}
}
