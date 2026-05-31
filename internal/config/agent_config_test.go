package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func baseConfigWithAgent(agent AgentConfig) *Config {
	return &Config{
		Vault: VaultConfig{Address: "https://vault.example.com"},
		Rules: []Rule{{Name: "r", VaultKey: "k", Target: Target{Path: "/tmp/x", Format: "text"}}},
		Agent: agent,
	}
}

func TestAgentValidateDisabledIgnored(t *testing.T) {
	// A disabled agent with no keys must still validate.
	c := baseConfigWithAgent(AgentConfig{Enabled: false})
	if err := c.validate(); err != nil {
		t.Errorf("disabled agent should validate: %v", err)
	}
}

func TestAgentValidateRequiresKeys(t *testing.T) {
	c := baseConfigWithAgent(AgentConfig{Enabled: true})
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "at least one key source") {
		t.Errorf("want key-source error, got %v", err)
	}
}

func TestAgentValidateKVSource(t *testing.T) {
	c := baseConfigWithAgent(AgentConfig{
		Enabled: true,
		Keys:    []AgentKeySource{{Source: "kv", PathPrefix: "ssh/"}},
	})
	if err := c.validate(); err != nil {
		t.Errorf("kv source should validate: %v", err)
	}
}

func TestAgentValidateVaultCARequiresMountAndRole(t *testing.T) {
	c := baseConfigWithAgent(AgentConfig{
		Enabled: true,
		Keys:    []AgentKeySource{{Source: "vault-ca", Role: "r"}},
	})
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "mount is required") {
		t.Errorf("want mount error, got %v", err)
	}

	c = baseConfigWithAgent(AgentConfig{
		Enabled: true,
		Keys:    []AgentKeySource{{Source: "vault-ca", Mount: "ssh"}},
	})
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "role is required") {
		t.Errorf("want role error, got %v", err)
	}
}

func TestAgentValidateVaultCATTL(t *testing.T) {
	c := baseConfigWithAgent(AgentConfig{
		Enabled: true,
		Keys:    []AgentKeySource{{Source: "vault-ca", Mount: "ssh", Role: "r", TTL: "15m"}},
	})
	if err := c.validate(); err != nil {
		t.Errorf("valid ttl should pass: %v", err)
	}

	c = baseConfigWithAgent(AgentConfig{
		Enabled: true,
		Keys:    []AgentKeySource{{Source: "vault-ca", Mount: "ssh", Role: "r", TTL: "nonsense"}},
	})
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "ttl") {
		t.Errorf("want ttl parse error, got %v", err)
	}
}

func TestAgentValidateInvalidSource(t *testing.T) {
	c := baseConfigWithAgent(AgentConfig{
		Enabled: true,
		Keys:    []AgentKeySource{{Source: "bogus"}},
	})
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "invalid source") {
		t.Errorf("want invalid source error, got %v", err)
	}

	c = baseConfigWithAgent(AgentConfig{
		Enabled: true,
		Keys:    []AgentKeySource{{Source: ""}},
	})
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "source is required") {
		t.Errorf("want source-required error, got %v", err)
	}
}

func boolPtr(b bool) *bool { return &b }

func TestAgentPuttyEnabledDefault(t *testing.T) {
	tests := []struct {
		name string
		in   *bool
		want bool
	}{
		{"unset defaults true", nil, true},
		{"explicit true", boolPtr(true), true},
		{"explicit false", boolPtr(false), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := AgentWindowsConfig{Putty: tt.in}
			if got := w.PuttyEnabled(); got != tt.want {
				t.Errorf("PuttyEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAgentPuttyYAMLRoundTrip confirms the tri-state pointer survives a YAML
// marshal/unmarshal: unset stays nil (default), explicit false stays false.
func TestAgentPuttyYAMLRoundTrip(t *testing.T) {
	// Unset: omitempty drops it, and it parses back to nil (default true).
	out, err := yaml.Marshal(AgentWindowsConfig{Pipe: `\\.\pipe\dotvault-agent`})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), "putty") {
		t.Errorf("unset putty should be omitted, got:\n%s", out)
	}
	var back AgentWindowsConfig
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Putty != nil {
		t.Errorf("unset putty should parse to nil, got %v", *back.Putty)
	}
	if !back.PuttyEnabled() {
		t.Errorf("unset putty should default enabled")
	}

	// Explicit false must round-trip as false.
	out, err = yaml.Marshal(AgentWindowsConfig{Putty: boolPtr(false)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(out), "putty: false") {
		t.Errorf("explicit false should emit `putty: false`, got:\n%s", out)
	}
	back = AgentWindowsConfig{}
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Putty == nil || *back.Putty {
		t.Errorf("explicit false should round-trip as false, got %v", back.Putty)
	}
	if back.PuttyEnabled() {
		t.Errorf("explicit false should report disabled")
	}
}
