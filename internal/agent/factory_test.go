package agent

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
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
	// Three configured entries plus the implicit relay.
	if len(sources) != 4 {
		t.Fatalf("want 4 sources (3 configured + the implicit relay), got %d", len(sources))
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
	// The relay is last, and it is last on purpose: an ssh client works down
	// the advertised list against the server's MaxAuthTries budget, so
	// dotvault's own identities get the first attempts.
	if got := sources[len(sources)-1].Type(); got != "agent" {
		t.Errorf("last source type = %q, want agent (the relay is always appended last)", got)
	}
}

// TestRelayIsImplicitAndOptOut covers the two halves of the relay's contract at
// the factory: it appears with no configuration at all, and `relay.enabled: false` is
// the one way to be rid of it.
func TestRelayIsImplicitAndOptOut(t *testing.T) {
	vc := testVaultClient(t)

	// Nothing configured whatsoever: the relay is still there.
	sources, err := NewSourcesFromConfig(config.AgentConfig{Enabled: true}, vc, "kv", "users/", "me")
	if err != nil {
		t.Fatalf("NewSourcesFromConfig: %v", err)
	}
	if len(sources) != 1 || sources[0].Type() != "agent" {
		t.Fatalf("an agent with no keys[] should get exactly the implicit relay, got %d sources", len(sources))
	}

	// Opted out: no relay, and the configured sources are untouched.
	off := false
	sources, err = NewSourcesFromConfig(config.AgentConfig{
		Enabled: true,
		Relay:   config.AgentRelayConfig{Enabled: &off},
		Keys:    []config.AgentKeySource{{Source: "kv", PathPrefix: "ssh/"}},
	}, vc, "kv", "users/", "me")
	if err != nil {
		t.Fatalf("NewSourcesFromConfig: %v", err)
	}
	if len(sources) != 1 || sources[0].Type() != "kv" {
		t.Fatalf("relay:false should leave only the kv source, got %d sources", len(sources))
	}
	for _, src := range sources {
		if src.Type() == "agent" {
			t.Error("relay:false still produced a relay source")
		}
	}
}

func TestResolveUpstreamEndpointTemplate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket resolution")
	}
	got, err := resolveRelayEndpoint(
		config.AgentConfig{Enabled: true, Relay: config.AgentRelayConfig{Socket: "/run/user/{{.uid}}/agent.{{.username}}"}},
		"alice", "1000",
	)
	if err != nil {
		t.Fatalf("resolveRelayEndpoint: %v", err)
	}
	if want := "/run/user/1000/agent.alice"; got != want {
		t.Errorf("endpoint = %q, want %q", got, want)
	}
}

func TestResolveUpstreamEndpointUnknownVariable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket resolution")
	}
	// A mis-typed variable ({{.user}} instead of {{.username}}) must fail at
	// resolution, not silently render "<no value>" into the path.
	_, err := resolveRelayEndpoint(
		config.AgentConfig{Enabled: true, Relay: config.AgentRelayConfig{Socket: "/run/{{.user}}/agent.sock"}},
		"alice", "1000",
	)
	if err == nil {
		t.Fatalf("mis-typed template variable should error, got nil")
	}
}

func TestResolveUpstreamEndpointEmptyRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket resolution")
	}
	// A socket that renders to empty (a bare {{.uid}} when the UID lookup
	// failed) must be rejected here rather than becoming an empty dial target.
	_, err := resolveRelayEndpoint(
		config.AgentConfig{Enabled: true, Relay: config.AgentRelayConfig{Socket: "{{.uid}}"}},
		"alice", "",
	)
	if err == nil {
		t.Fatalf("empty resolved endpoint should error, got nil")
	}
}

func TestNewSourcesUpstreamSelfReferenceGuard(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket resolution")
	}
	vc := testVaultClient(t)
	self := "/tmp/dotvault-self.sock"
	cfg := config.AgentConfig{
		Enabled: true,
		Unix:    config.AgentUnixConfig{Path: self},
		// points back at dotvault's own socket
		Relay: config.AgentRelayConfig{Socket: self},
	}
	sources, err := NewSourcesFromConfig(cfg, vc, "kv", "users/", "me")
	if err != nil {
		t.Fatalf("NewSourcesFromConfig: %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("want 1 source, got %d", len(sources))
	}
	// The self-reference becomes an errSource reporting the loop via Identities.
	if _, err := sources[0].Identities(context.Background()); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Errorf("self-reference should report a loop error, got %v", err)
	}
}

func TestNewSourcesUpstreamSelfReferenceNormalized(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket resolution")
	}
	vc := testVaultClient(t)
	self := "/tmp/dotvault-self.sock"
	cfg := config.AgentConfig{
		Enabled: true,
		Unix:    config.AgentUnixConfig{Path: self},
		// A non-clean path that normalizes to dotvault's own socket must
		// still trip the loop guard.
		Relay: config.AgentRelayConfig{Socket: "/tmp/./dotvault-self.sock"},
	}
	sources, err := NewSourcesFromConfig(cfg, vc, "kv", "users/", "me")
	if err != nil {
		t.Fatalf("NewSourcesFromConfig: %v", err)
	}
	if _, err := sources[0].Identities(context.Background()); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Errorf("non-clean self-reference should report a loop error, got %v", err)
	}
}

func TestResolveEndpointUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix path resolution")
	}
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1234")
	got := ResolveEndpoint(config.AgentConfig{})
	want := filepath.Join("/run/user/1234", "dotvault", "agent.sock")
	if got != want {
		t.Errorf("ResolveEndpoint = %q, want %q", got, want)
	}

	got = ResolveEndpoint(config.AgentConfig{Unix: config.AgentUnixConfig{Path: "/tmp/custom.sock"}})
	if got != "/tmp/custom.sock" {
		t.Errorf("explicit path = %q", got)
	}
}
