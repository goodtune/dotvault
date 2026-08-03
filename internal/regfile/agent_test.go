package regfile

import (
	"reflect"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// agentConfigFixture is a representative AgentConfig exercising all three source
// kinds, an empty transport path (Unix) alongside a set one (Windows pipe), a
// templated principal list, the ttl / ephemeral_key fields, and an upstream
// agent source carrying both a templated socket and a pipe.
func agentConfigFixture() config.AgentConfig {
	return config.AgentConfig{
		Enabled: true,
		Unix:    config.AgentUnixConfig{Path: ""},
		Windows: config.AgentWindowsConfig{Pipe: `\\.\pipe\dotvault-agent`},
		Keys: []config.AgentKeySource{
			{Source: "kv", PathPrefix: "ssh/"},
			{
				Source:       "vault-ca",
				Mount:        "ssh-client-signer",
				Role:         "dotvault-user",
				Principals:   []string{"{{.vault_username}}", "ops"},
				TTL:          "15m",
				EphemeralKey: true,
			},
			{
				Source: "agent",
				Socket: "/run/user/{{.uid}}/ssh-agent.socket",
				Pipe:   `\\.\pipe\openssh-ssh-agent`,
			},
		},
	}
}

// TestAgentRoundTrip generates a .reg from a config carrying an agent block and
// parses it back, asserting the agent section (including ordered keys and the
// templated principal list) survives unchanged.
func TestAgentRoundTrip(t *testing.T) {
	src := validBaseConfig()
	src.Sync = config.SyncConfig{RawInterval: "15m"}
	src.Agent = agentConfigFixture()

	text, err := GenerateText(src)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}

	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if !reflect.DeepEqual(got.Agent, src.Agent) {
		t.Errorf("Agent mismatch:\ngot:  %+v\nwant: %+v", got.Agent, src.Agent)
	}
}

// TestAgentKeyOrderPreserved confirms the index-named subkeys recover the
// original list order even when more than ten keys force lexical-vs-numeric
// ordering to diverge ("10" < "2" lexically).
func TestAgentKeyOrderPreserved(t *testing.T) {
	src := validBaseConfig()
	src.Agent.Enabled = true
	for i := 0; i < 12; i++ {
		src.Agent.Keys = append(src.Agent.Keys, config.AgentKeySource{
			Source: "kv", PathPrefix: "p" + itoa(i) + "/",
		})
	}

	text, err := GenerateText(src)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Agent.Keys) != len(src.Agent.Keys) {
		t.Fatalf("len(Keys) = %d, want %d", len(got.Agent.Keys), len(src.Agent.Keys))
	}
	for i := range src.Agent.Keys {
		if !reflect.DeepEqual(got.Agent.Keys[i], src.Agent.Keys[i]) {
			t.Errorf("Keys[%d] = %+v, want %+v", i, got.Agent.Keys[i], src.Agent.Keys[i])
		}
	}
}

// TestAgentDisabledEmitsBlock confirms a disabled, key-less agent still
// round-trips: the [Agent] key with Enabled=0 plus the empty Keys deletion
// stanza, parsing back to a zero-value AgentConfig with no keys.
func TestAgentDisabledEmitsBlock(t *testing.T) {
	src := validBaseConfig()

	text, err := GenerateText(src)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	if !strings.Contains(text, `\dotvault\Agent]`) {
		t.Errorf("expected an [Agent] key even when disabled\n%s", text)
	}

	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Agent.Enabled {
		t.Errorf("Agent.Enabled = true, want false")
	}
	if len(got.Agent.Keys) != 0 {
		t.Errorf("Agent.Keys = %v, want empty", got.Agent.Keys)
	}
}

// TestAgentEmptyPrincipalsRoundTrip confirms an explicit empty principals list
// round-trips as a non-nil empty slice (the `principals: []` distinction),
// mirroring the OAuth Scopes treatment.
func TestAgentEmptyPrincipalsRoundTrip(t *testing.T) {
	src := validBaseConfig()
	src.Agent.Enabled = true
	src.Agent.Keys = []config.AgentKeySource{
		{Source: "vault-ca", Mount: "m", Role: "r", Principals: []string{}},
	}

	text, err := GenerateText(src)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Agent.Keys[0].Principals == nil {
		t.Errorf("explicit empty principals should round-trip as non-nil empty slice, got nil")
	}
	if len(got.Agent.Keys[0].Principals) != 0 {
		t.Errorf("principals = %v, want empty", got.Agent.Keys[0].Principals)
	}
}

// TestAgentNonNumericKeySubkeyRejected confirms a hand-edited .reg with a
// non-integer Keys subkey name is a hard parse error rather than silently
// reordered or dropped.
func TestAgentNonNumericKeySubkeyRejected(t *testing.T) {
	reg := "Windows Registry Editor Version 5.00\r\n\r\n" +
		`[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\Agent\Keys\bogus]` + "\r\n" +
		`"Source"="kv"` + "\r\n"
	if _, err := Parse([]byte(reg)); err == nil || !strings.Contains(err.Error(), "non-negative integer index") {
		t.Errorf("want non-integer-index error, got %v", err)
	}
}

// TestAgentPuttyTriStateRoundTrip confirms the windows putty option's
// tri-state semantics survive a .reg round-trip: unset stays nil (the
// default), explicit true and explicit false each recover their value via the
// WindowsPutty DWORD.
func TestAgentPuttyTriStateRoundTrip(t *testing.T) {
	roundTrip := func(t *testing.T, in *bool) *bool {
		t.Helper()
		src := validBaseConfig()
		src.Agent.Enabled = true
		src.Agent.Keys = []config.AgentKeySource{{Source: "kv", PathPrefix: "ssh/"}}
		src.Agent.Windows = config.AgentWindowsConfig{Pipe: `\\.\pipe\dotvault-agent`, Putty: in}

		text, err := GenerateText(src)
		if err != nil {
			t.Fatalf("GenerateText: %v", err)
		}
		// An unset pointer must not emit the DWORD at all.
		if in == nil && strings.Contains(text, "WindowsPutty") {
			t.Errorf("unset putty should not emit WindowsPutty:\n%s", text)
		}
		got, err := Parse([]byte(text))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		return got.Agent.Windows.Putty
	}

	if p := roundTrip(t, nil); p != nil {
		t.Errorf("unset putty should round-trip as nil, got %v", *p)
	}
	if p := roundTrip(t, boolPtr(true)); p == nil || !*p {
		t.Errorf("explicit true should round-trip as true, got %v", p)
	}
	if p := roundTrip(t, boolPtr(false)); p == nil || *p {
		t.Errorf("explicit false should round-trip as false, got %v", p)
	}
}

func boolPtr(b bool) *bool { return &b }

// itoa avoids pulling strconv into the test for a single small int.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
