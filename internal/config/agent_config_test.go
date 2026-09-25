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

// TestAgentRelayIsImplicitAndDefaultsOn pins the shape of the feature: the
// relay is not a keys[] entry, it is on when nobody says otherwise, and an
// agent with no key sources at all is a complete configuration because the
// relay alone has something to serve.
func TestAgentRelayIsImplicitAndDefaultsOn(t *testing.T) {
	c := baseConfigWithAgent(AgentConfig{Enabled: true})
	if err := c.validate(); err != nil {
		t.Errorf("agent with no keys[] but an implicit relay should validate: %v", err)
	}
	if !c.Agent.RelayEnabled() {
		t.Error("RelayEnabled() = false with relay unset, want true (absent means on)")
	}

	// An explicit true must be distinguishable from unset at the config layer
	// even though both mean "on" — the registry and .reg surfaces round-trip
	// the pointer, and collapsing the two would silently turn a policy that
	// says nothing into one that says yes.
	on := true
	c = baseConfigWithAgent(AgentConfig{Enabled: true, Relay: AgentRelayConfig{Enabled: &on}})
	if !c.Agent.RelayEnabled() {
		t.Error("RelayEnabled() = false with relay.enabled: true")
	}
	if c.Agent.Relay.Enabled == nil {
		t.Error("an explicit relay.enabled: true collapsed to nil; unset and explicitly-on must stay distinguishable")
	}
}

// TestAgentRelayDisabledNeedsAKeySource covers the one combination that leaves
// the agent with nothing to serve. Starting a listener that can only ever
// answer "no identities" is a mistake worth naming at load.
func TestAgentRelayDisabledNeedsAKeySource(t *testing.T) {
	off := false
	c := baseConfigWithAgent(AgentConfig{Enabled: true, Relay: AgentRelayConfig{Enabled: &off}})
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "nothing to serve") {
		t.Errorf("want a nothing-to-serve error for relay:false with no keys, got %v", err)
	}
	if c.Agent.RelayEnabled() {
		t.Error("RelayEnabled() = true with relay.enabled: false")
	}

	c = baseConfigWithAgent(AgentConfig{
		Enabled: true,
		Relay:   AgentRelayConfig{Enabled: &off},
		Keys:    []AgentKeySource{{Source: "kv", PathPrefix: "ssh/"}},
	})
	if err := c.validate(); err != nil {
		t.Errorf("relay:false with a kv source should validate: %v", err)
	}
}

// TestAgentRelaySettingsWithTheAgentOff pins the convention the relay fields
// follow, because an earlier draft of this commit had them the other way and a
// review caught it: a setting for a section that is switched off is inert, not
// an error. api.unix.path and fuse.mountpoint are validated but never rejected
// while their section is disabled, and windows.putty — the relay's closest
// sibling, another *bool that "only takes effect when agent.enabled" — is not
// rejected either. Refusing here would also stop an operator staging a config
// before flipping enabled, which is a normal thing to want to do.
func TestAgentRelaySettingsWithTheAgentOff(t *testing.T) {
	off := false
	for name, cfg := range map[string]AgentConfig{
		"relay.enabled": {Enabled: false, Relay: AgentRelayConfig{Enabled: &off}},
		"relay.socket":  {Enabled: false, Relay: AgentRelayConfig{Socket: "/run/user/1000/ssh-agent.socket"}},
		"relay.pipe":    {Enabled: false, Relay: AgentRelayConfig{Pipe: `\\.\pipe\openssh-ssh-agent`}},
	} {
		c := baseConfigWithAgent(cfg)
		if err := c.validate(); err != nil {
			t.Errorf("%s with the agent disabled should validate (inert, not an error): %v", name, err)
		}
	}
}

// TestAgentRelayPinnedEndpointValidates is the positive case for the override,
// carried over from the retired TestAgentValidateAgentSource: an enabled agent
// whose relay is pinned to one endpoint, with no keys[] at all, is complete.
func TestAgentRelayPinnedEndpointValidates(t *testing.T) {
	for name, cfg := range map[string]AgentConfig{
		"socket": {Enabled: true, Relay: AgentRelayConfig{Socket: "/run/user/{{.uid}}/ssh-agent.socket"}},
		"pipe":   {Enabled: true, Relay: AgentRelayConfig{Pipe: `\\.\pipe\openssh-ssh-agent`}},
		"both":   {Enabled: true, Relay: AgentRelayConfig{Socket: "/run/x.sock", Pipe: `\\.\pipe\y`}},
	} {
		c := baseConfigWithAgent(cfg)
		if err := c.validate(); err != nil {
			t.Errorf("relay_%s pinned on an enabled agent should validate: %v", name, err)
		}
	}
}

// TestAgentRelayYAMLRoundTrip is the relay's counterpart to
// TestAgentPuttyYAMLRoundTrip. The `relay:` block header is always emitted now
// that it is a struct, so the thing to guard is the tri-state inside it:
// without omitempty an unset Enabled marshals as an explicit `enabled: null`,
// and a config exported through reg-export or the web UI's download would hand
// back a preference nobody expressed — the same trap the .reg side guards with
// TestAgentRelayTriStateRoundTrip.
func TestAgentRelayYAMLRoundTrip(t *testing.T) {
	out, err := yaml.Marshal(AgentConfig{Enabled: true})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), "enabled: null") {
		t.Errorf("an unset relay.enabled should be omitted, not emitted as null, got:\n%s", out)
	}
	var back AgentConfig
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Relay.Enabled != nil {
		t.Errorf("Relay.Enabled = %v after a round trip of an unset value, want nil", *back.Relay.Enabled)
	}

	off := false
	out, err = yaml.Marshal(AgentConfig{Enabled: true, Relay: AgentRelayConfig{Enabled: &off}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	back = AgentConfig{}
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Relay.Enabled == nil || *back.Relay.Enabled {
		t.Errorf("relay.enabled: false did not survive the round trip (got %v), so the off switch would silently turn back on", back.Relay.Enabled)
	}
}

// TestAgentSourceAgentIsRetired makes the migration legible. A config carrying
// the old `source: agent` entry must be told what replaced it, not handed a
// bare "invalid source".
func TestAgentSourceAgentIsRetired(t *testing.T) {
	c := baseConfigWithAgent(AgentConfig{
		Enabled: true,
		Keys:    []AgentKeySource{{Source: "agent"}},
	})
	err := c.validate()
	if err == nil {
		t.Fatal("source: agent should be rejected now that the relay is implicit")
	}
	for _, want := range []string{"no longer a key source", "agent.relay.enabled"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q so the fix is obvious", err, want)
		}
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
