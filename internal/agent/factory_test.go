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

func TestDescribeConfigDoesNotMint(t *testing.T) {
	// Point the client at an unreachable Vault. DescribeConfig must NOT mint a
	// certificate for the vault-ca source — doing so would hit Vault and surface
	// a transport error; instead it describes the source from configuration.
	vc := testVaultClient(t)
	cfg := config.AgentConfig{
		Enabled: true,
		Keys: []config.AgentKeySource{
			{Source: "vault-ca", Mount: "ssh-client-signer", Role: "dotvault-user", TTL: "15m", EphemeralKey: true},
		},
	}
	st := DescribeConfig(context.Background(), cfg, vc, "kv", "users/", "me")
	if len(st.Sources) != 1 {
		t.Fatalf("want 1 source, got %d", len(st.Sources))
	}
	src := st.Sources[0]
	if src.Type != "vault-ca" {
		t.Errorf("type = %q, want vault-ca", src.Type)
	}
	if src.Error != "" {
		t.Errorf("vault-ca describe should not error (no mint), got %q", src.Error)
	}
	if len(src.Identities) != 1 || src.Identities[0].Fingerprint != "" {
		t.Fatalf("want one fingerprint-less described identity, got %+v", src.Identities)
	}
	if src.Identities[0].Comment == "" {
		t.Errorf("expected a 'minted on demand' description, got empty comment")
	}
}

func TestDescribeConfigKVErrorAndUnknownSource(t *testing.T) {
	// kv sources DO reach Vault in DescribeConfig (unlike vault-ca). Against an
	// unreachable Vault the kv branch must surface the failure as a per-source
	// Error, and an unknown source must report its own error — neither aborts
	// the snapshot.
	vc := testVaultClient(t)
	cfg := config.AgentConfig{
		Enabled: true,
		Keys: []config.AgentKeySource{
			{Source: "kv", PathPrefix: "ssh/"},
			{Source: "bogus"},
		},
	}
	st := DescribeConfig(context.Background(), cfg, vc, "kv", "users/", "me")
	if len(st.Sources) != 2 {
		t.Fatalf("want 2 sources, got %d", len(st.Sources))
	}
	if st.Sources[0].Type != "kv" || st.Sources[0].Error == "" {
		t.Errorf("kv source against unreachable Vault should carry an Error, got %+v", st.Sources[0])
	}
	if st.Sources[1].Error == "" || !strings.Contains(st.Sources[1].Error, "unknown source") {
		t.Errorf("unknown source should report an 'unknown source' error, got %+v", st.Sources[1])
	}
}

func TestDescribeConfigVaultCADefaultTTL(t *testing.T) {
	// An omitted ttl is described with the shared defaultCertTTL, not a
	// hard-coded literal that could drift from the mint path.
	vc := testVaultClient(t)
	cfg := config.AgentConfig{
		Enabled: true,
		Keys:    []config.AgentKeySource{{Source: "vault-ca", Mount: "m", Role: "r", EphemeralKey: true}},
	}
	st := DescribeConfig(context.Background(), cfg, vc, "kv", "users/", "me")
	if len(st.Sources) != 1 || len(st.Sources[0].Identities) != 1 {
		t.Fatalf("unexpected snapshot: %+v", st.Sources)
	}
	if !strings.Contains(st.Sources[0].Identities[0].Comment, "ttl="+defaultCertTTL.String()) {
		t.Errorf("want default ttl %s in description, got %q", defaultCertTTL, st.Sources[0].Identities[0].Comment)
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
