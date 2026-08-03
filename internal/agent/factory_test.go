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

func TestNewSourcesUpstreamAgent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket resolution")
	}
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/4321")
	vc := testVaultClient(t)
	cfg := config.AgentConfig{
		Enabled: true,
		Keys: []config.AgentKeySource{
			{Source: "kv", PathPrefix: "ssh/"},
			{Source: "agent"}, // empty socket -> XDG default
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
	us, ok := sources[1].(*upstreamSource)
	if !ok {
		t.Fatalf("source[1] is %T, want *upstreamSource", sources[1])
	}
	if want := "/run/user/4321/ssh-agent.socket"; us.endpoint != want {
		t.Errorf("endpoint = %q, want %q", us.endpoint, want)
	}
}

func TestResolveUpstreamEndpointTemplate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket resolution")
	}
	got, err := resolveUpstreamEndpoint(
		config.AgentKeySource{Source: "agent", Socket: "/run/user/{{.uid}}/agent.{{.username}}"},
		"alice", "1000",
	)
	if err != nil {
		t.Fatalf("resolveUpstreamEndpoint: %v", err)
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
	_, err := resolveUpstreamEndpoint(
		config.AgentKeySource{Source: "agent", Socket: "/run/{{.user}}/agent.sock"},
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
	_, err := resolveUpstreamEndpoint(
		config.AgentKeySource{Source: "agent", Socket: "{{.uid}}"},
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
		Keys: []config.AgentKeySource{
			{Source: "agent", Socket: self}, // points back at dotvault's own socket
		},
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
		Keys: []config.AgentKeySource{
			// A non-clean path that normalizes to dotvault's own socket must
			// still trip the loop guard.
			{Source: "agent", Socket: "/tmp/./dotvault-self.sock"},
		},
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
