//go:build windows

package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
)

func testVaultClientWin(t *testing.T) *vault.Client {
	t.Helper()
	vc, err := vault.NewClient(vault.Config{Address: "http://127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	return vc
}

// TestResolveUpstreamEndpointWindowsDefault confirms an unset pipe falls back
// to the built-in OpenSSH agent pipe.
func TestResolveUpstreamEndpointWindowsDefault(t *testing.T) {
	got, err := resolveUpstreamEndpoint(config.AgentKeySource{Source: "agent"}, "alice", "S-1-5-21-1")
	if err != nil {
		t.Fatalf("resolveUpstreamEndpoint: %v", err)
	}
	if got != defaultWindowsUpstreamPipe {
		t.Errorf("endpoint = %q, want %q", got, defaultWindowsUpstreamPipe)
	}
}

// TestResolveUpstreamEndpointWindowsTemplate confirms {{.username}} expands in
// a Windows pipe name.
func TestResolveUpstreamEndpointWindowsTemplate(t *testing.T) {
	got, err := resolveUpstreamEndpoint(
		config.AgentKeySource{Source: "agent", Pipe: `\\.\pipe\agent-{{.username}}`},
		"alice", "",
	)
	if err != nil {
		t.Fatalf("resolveUpstreamEndpoint: %v", err)
	}
	if want := `\\.\pipe\agent-alice`; got != want {
		t.Errorf("endpoint = %q, want %q", got, want)
	}
}

// TestNewSourcesUpstreamSelfReferenceWindows confirms the loop guard trips when
// an upstream pipe matches dotvault's own pipe, case-insensitively.
func TestNewSourcesUpstreamSelfReferenceWindows(t *testing.T) {
	vc := testVaultClientWin(t)
	cfg := config.AgentConfig{
		Enabled: true,
		Windows: config.AgentWindowsConfig{Pipe: `\\.\pipe\dotvault-agent`, Putty: boolPtrWin(false)},
		Keys: []config.AgentKeySource{
			// Same pipe, different case — the namespace is case-insensitive.
			{Source: "agent", Pipe: `\\.\PIPE\DOTVAULT-AGENT`},
		},
	}
	sources, err := NewSourcesFromConfig(cfg, vc, "kv", "users/", "me")
	if err != nil {
		t.Fatalf("NewSourcesFromConfig: %v", err)
	}
	if _, err := sources[0].Identities(context.Background()); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Errorf("case-insensitive self-reference should report a loop error, got %v", err)
	}
}

func boolPtrWin(b bool) *bool { return &b }
