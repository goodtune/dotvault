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

// TestResolveRelayEndpointWindowsEmptyRejected pins the resolver's contract
// after auto-detection took over the empty case: this function is only ever
// reached for an endpoint the operator named explicitly, so an empty pipe is a
// caller bug and is rejected rather than quietly resolving to a default.
//
// The built-in OpenSSH pipe is still the first thing tried when no pipe is
// configured — it is simply candidateEndpoints' job now, not this resolver's
// (see TestWindowsCandidatesIncludeOpenSSHPipe).
func TestResolveRelayEndpointWindowsEmptyRejected(t *testing.T) {
	if _, err := resolveRelayEndpoint(config.AgentConfig{Enabled: true}, "alice", "S-1-5-21-1"); err == nil {
		t.Fatal("an empty pipe should be rejected by the explicit-endpoint resolver, got nil")
	}
}

// TestWindowsCandidatesIncludeOpenSSHPipe confirms the default that moved: the
// built-in OpenSSH agent pipe is offered by auto-detection. The pipe only
// appears when it actually exists, so this asserts the candidate list is
// *derived from* that name rather than asserting the name is always present.
func TestWindowsCandidatesIncludeOpenSSHPipe(t *testing.T) {
	names, ok := existingPipes()
	if !ok {
		t.Skip("pipe namespace not enumerable in this environment")
	}
	want := names[pipeLeafName(defaultWindowsUpstreamPipe)]
	got := false
	for _, ep := range candidateEndpoints() {
		if strings.EqualFold(ep, defaultWindowsUpstreamPipe) {
			got = true
			break
		}
	}
	if got != want {
		t.Errorf("openssh pipe in candidates = %v, want %v (present in namespace = %v)", got, want, want)
	}
}

// TestResolveRelayEndpointWindowsTemplate confirms {{.username}} expands in
// a Windows pipe name.
func TestResolveRelayEndpointWindowsTemplate(t *testing.T) {
	got, err := resolveRelayEndpoint(
		config.AgentConfig{Enabled: true, Relay: config.AgentRelayConfig{Pipe: `\\.\pipe\agent-{{.username}}`}},
		"alice", "",
	)
	if err != nil {
		t.Fatalf("resolveRelayEndpoint: %v", err)
	}
	if want := `\\.\pipe\agent-alice`; got != want {
		t.Errorf("endpoint = %q, want %q", got, want)
	}
}

// TestRelaySelfReferenceWindows confirms the loop guard trips when
// an upstream pipe matches dotvault's own pipe, case-insensitively.
func TestRelaySelfReferenceWindows(t *testing.T) {
	vc := testVaultClientWin(t)
	cfg := config.AgentConfig{
		Enabled: true,
		Windows: config.AgentWindowsConfig{Pipe: `\\.\pipe\dotvault-agent`, Putty: boolPtrWin(false)},
		// Same pipe, different case — the namespace is case-insensitive.
		Relay: config.AgentRelayConfig{Pipe: `\\.\PIPE\DOTVAULT-AGENT`},
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
