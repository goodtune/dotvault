package config

import (
	"strings"
	"testing"
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
