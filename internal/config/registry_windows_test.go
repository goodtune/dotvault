//go:build windows

package config

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestApplyRegistryLayer(t *testing.T) {
	cfg := &Config{}

	layer := registryLayer{
		VaultAddress:    "https://vault.corp.example.com:8200",
		VaultKVMount:    "secret",
		VaultAuthMethod: "oidc",
		SyncInterval:    "10m",
	}
	applyRegistryLayer(cfg, layer)

	if cfg.Vault.Address != "https://vault.corp.example.com:8200" {
		t.Errorf("Address = %q, want %q", cfg.Vault.Address, "https://vault.corp.example.com:8200")
	}
	if cfg.Vault.KVMount != "secret" {
		t.Errorf("KVMount = %q, want %q", cfg.Vault.KVMount, "secret")
	}
	if cfg.Vault.AuthMethod != "oidc" {
		t.Errorf("AuthMethod = %q, want %q", cfg.Vault.AuthMethod, "oidc")
	}
	if cfg.Sync.RawInterval != "10m" {
		t.Errorf("RawInterval = %q, want %q", cfg.Sync.RawInterval, "10m")
	}
}

func TestApplyRegistryLayerMerge(t *testing.T) {
	// Machine layer sets base values.
	cfg := &Config{}
	machine := registryLayer{
		VaultAddress:    "https://vault.corp.example.com:8200",
		VaultKVMount:    "kv",
		VaultAuthMethod: "ldap",
		SyncInterval:    "15m",
	}
	applyRegistryLayer(cfg, machine)

	// Second layer overrides only AuthMethod.
	override := registryLayer{
		VaultAuthMethod: "oidc",
	}
	applyRegistryLayer(cfg, override)

	if cfg.Vault.Address != "https://vault.corp.example.com:8200" {
		t.Errorf("Address = %q, want base value", cfg.Vault.Address)
	}
	if cfg.Vault.AuthMethod != "oidc" {
		t.Errorf("AuthMethod = %q, want override %q", cfg.Vault.AuthMethod, "oidc")
	}
	if cfg.Sync.RawInterval != "15m" {
		t.Errorf("RawInterval = %q, want machine value %q", cfg.Sync.RawInterval, "15m")
	}
}

func TestApplyRegistryLayerBooleans(t *testing.T) {
	cfg := &Config{}

	enabled := uint32(1)
	skipVerify := uint32(0)
	layer := registryLayer{
		VaultTLSSkipVerify: &skipVerify,
		WebEnabled:         &enabled,
		WebListen:          "127.0.0.1:9090",
	}
	applyRegistryLayer(cfg, layer)

	if cfg.Vault.TLSSkipVerify != false {
		t.Error("TLSSkipVerify should be false when DWORD is 0")
	}
	if cfg.Web.Enabled != true {
		t.Error("Web.Enabled should be true when DWORD is 1")
	}
	if cfg.Web.Listen != "127.0.0.1:9090" {
		t.Errorf("Web.Listen = %q, want %q", cfg.Web.Listen, "127.0.0.1:9090")
	}
}

// TestApplyRegistryLayerBypassSystemConfig covers the top-level
// BypassSystemConfig flag — read directly off the policy root key — which
// gates whether a GPO-managed machine honours a --config command-line
// override. The tri-state DWORD must map 1 -> true, 0 -> false, and absent
// (nil) -> the false default.
func TestApplyRegistryLayerBypassSystemConfig(t *testing.T) {
	set := uint32(1)
	cfg := &Config{}
	applyRegistryLayer(cfg, registryLayer{BypassSystemConfig: &set})
	if !cfg.BypassSystemConfig {
		t.Error("BypassSystemConfig should be true when DWORD is 1")
	}

	clear := uint32(0)
	cfg = &Config{BypassSystemConfig: true}
	applyRegistryLayer(cfg, registryLayer{BypassSystemConfig: &clear})
	if cfg.BypassSystemConfig {
		t.Error("BypassSystemConfig should be false when DWORD is 0")
	}

	cfg = &Config{}
	applyRegistryLayer(cfg, registryLayer{})
	if cfg.BypassSystemConfig {
		t.Error("BypassSystemConfig should default to false when the DWORD is absent")
	}
}

// TestApplyRegistryLayerObservability covers the Observability subkey
// that gates the OTel LoggerProvider wiring. Without these fields
// populated from the registry, a GPO-managed daemon would have
// Observability.Enabled=false (zero value), Init would short-circuit
// to an inactive Provider, and the WARN record from
// LogRegistryConfigManaged — the entire point of this code path —
// would vanish into the no-op global logger.
func TestApplyRegistryLayerObservability(t *testing.T) {
	cfg := &Config{}

	enabled := uint32(1)
	insecure := uint32(0)
	layer := registryLayer{
		ObservabilityEnabled:  &enabled,
		ObservabilityEndpoint: "https://otel.example",
		ObservabilityProtocol: "http/protobuf",
		ObservabilityInsecure: &insecure,
		ObservabilityInterval: "30s",
	}
	applyRegistryLayer(cfg, layer)

	if !cfg.Observability.Enabled {
		t.Error("Observability.Enabled should be true when DWORD is 1")
	}
	if cfg.Observability.Endpoint != "https://otel.example" {
		t.Errorf("Endpoint = %q, want %q", cfg.Observability.Endpoint, "https://otel.example")
	}
	if cfg.Observability.Protocol != "http/protobuf" {
		t.Errorf("Protocol = %q, want %q", cfg.Observability.Protocol, "http/protobuf")
	}
	if cfg.Observability.Insecure {
		t.Error("Insecure should be false when DWORD is 0")
	}
	if cfg.Observability.RawInterval != "30s" {
		t.Errorf("RawInterval = %q, want %q", cfg.Observability.RawInterval, "30s")
	}
}

func TestReadSingleEnrolment(t *testing.T) {
	// Register cleanup first so stray keys are removed even on early failure.
	// Deletes children before parents (required on Windows).
	t.Cleanup(func() {
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test\Enrolments\gh\Settings`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test\Enrolments\gh`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test\Enrolments`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test`)
	})

	// Create a temporary registry key tree simulating:
	//   <testRoot>\Enrolments\gh\Engine = "github"
	//   <testRoot>\Enrolments\gh\Settings\Host = "github.com"
	//   <testRoot>\Enrolments\gh\Settings\Scopes = ["repo", "read:org"]
	base, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`SOFTWARE\dotvault-test\Enrolments\gh`,
		registry.ALL_ACCESS,
	)
	if err != nil {
		t.Fatalf("create test key: %v", err)
	}

	defer base.Close()
	if err := base.SetStringValue("Engine", "github"); err != nil {
		t.Fatalf("set Engine: %v", err)
	}

	settings, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`SOFTWARE\dotvault-test\Enrolments\gh\Settings`,
		registry.ALL_ACCESS,
	)
	if err != nil {
		t.Fatalf("create Settings key: %v", err)
	}
	defer settings.Close()
	if err := settings.SetStringValue("Host", "github.com"); err != nil {
		t.Fatalf("set Host: %v", err)
	}
	if err := settings.SetStringsValue("Scopes", []string{"repo", "read:org"}); err != nil {
		t.Fatalf("set Scopes: %v", err)
	}

	enrolment, err := readSingleEnrolment(registry.CURRENT_USER, `SOFTWARE\dotvault-test`, "gh")
	if err != nil {
		t.Fatalf("readSingleEnrolment() error: %v", err)
	}
	if enrolment.Engine != "github" {
		t.Errorf("Engine = %q, want %q", enrolment.Engine, "github")
	}
	if enrolment.Settings == nil {
		t.Fatal("Settings is nil")
	}
	// Registry value names are TitleCase ("Host", "Scopes") but should be
	// normalized to lowercase keys to match engine setting lookups.
	if host, ok := enrolment.Settings["host"]; !ok || host != "github.com" {
		t.Errorf("Settings[host] = %v, want %q", enrolment.Settings["host"], "github.com")
	}
	scopes, ok := enrolment.Settings["scopes"]
	if !ok {
		t.Fatal("Settings[scopes] missing")
	}
	scopeSlice, ok := scopes.([]any)
	if !ok {
		t.Fatalf("Settings[scopes] type = %T, want []any", scopes)
	}
	if len(scopeSlice) != 2 || scopeSlice[0] != "repo" || scopeSlice[1] != "read:org" {
		t.Errorf("Settings[scopes] = %v, want [repo read:org]", scopeSlice)
	}
}

func TestReadRegistryEnrolmentsNotExist(t *testing.T) {
	// Use a path that definitely doesn't exist.
	enrolments, err := readRegistryEnrolments(registry.CURRENT_USER, `SOFTWARE\dotvault-nonexistent`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enrolments != nil {
		t.Errorf("expected nil enrolments, got %v", enrolments)
	}
}

func TestReadRegistryEnrolmentsMultiple(t *testing.T) {
	// Register cleanup for the entire tree first so it runs even if
	// key creation fails partway through the loop.
	t.Cleanup(func() {
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-enrol\Enrolments\gh`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-enrol\Enrolments\gitlab`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-enrol\Enrolments`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-enrol`)
	})

	// Create two enrolment subkeys under a temporary registry path.
	for _, name := range []string{"gh", "gitlab"} {
		k, _, err := registry.CreateKey(
			registry.CURRENT_USER,
			`SOFTWARE\dotvault-test-enrol\Enrolments\`+name,
			registry.ALL_ACCESS,
		)
		if err != nil {
			t.Fatalf("create key %s: %v", name, err)
		}
		engine := "github"
		if name == "gitlab" {
			engine = "gitlab"
		}
		if err := k.SetStringValue("Engine", engine); err != nil {
			k.Close()
			t.Fatalf("set Engine for %s: %v", name, err)
		}
		k.Close()
	}

	enrolments, err := readRegistryEnrolments(registry.CURRENT_USER, `SOFTWARE\dotvault-test-enrol`)
	if err != nil {
		t.Fatalf("readRegistryEnrolments() error: %v", err)
	}
	if len(enrolments) != 2 {
		t.Fatalf("len(enrolments) = %d, want 2", len(enrolments))
	}
	if enrolments["gh"].Engine != "github" {
		t.Errorf("gh.Engine = %q, want %q", enrolments["gh"].Engine, "github")
	}
	if enrolments["gitlab"].Engine != "gitlab" {
		t.Errorf("gitlab.Engine = %q, want %q", enrolments["gitlab"].Engine, "gitlab")
	}
}

// TestReadRegistryEnrolmentsGroupedKey verifies the LIVE registry loader reads
// back a one-level grouped enrolment key ("databricks/prod") intact. The
// forward slash is a legal character in a Win32 registry key NAME (only
// backslash is the path separator), so the grouped key is stored as a single
// subkey literally named "databricks/prod"; ReadSubKeyNames returns it verbatim
// and readSingleEnrolment reopens it by that name. This is the platform half of
// the round-trip the regfile test covers — together they keep the GPO-parity
// contract honest for grouped keys.
func TestReadRegistryEnrolmentsGroupedKey(t *testing.T) {
	const base = `SOFTWARE\dotvault-test-grouped`
	t.Cleanup(func() {
		registry.DeleteKey(registry.CURRENT_USER, base+`\Enrolments\databricks/prod\Settings`)
		registry.DeleteKey(registry.CURRENT_USER, base+`\Enrolments\databricks/prod`)
		registry.DeleteKey(registry.CURRENT_USER, base+`\Enrolments`)
		registry.DeleteKey(registry.CURRENT_USER, base)
	})

	k, _, err := registry.CreateKey(registry.CURRENT_USER, base+`\Enrolments\databricks/prod`, registry.ALL_ACCESS)
	if err != nil {
		t.Fatalf("create grouped key: %v", err)
	}
	if err := k.SetStringValue("Engine", "databricks"); err != nil {
		k.Close()
		t.Fatalf("set Engine: %v", err)
	}
	k.Close()

	settings, _, err := registry.CreateKey(registry.CURRENT_USER, base+`\Enrolments\databricks/prod\Settings`, registry.ALL_ACCESS)
	if err != nil {
		t.Fatalf("create Settings: %v", err)
	}
	if err := settings.SetStringValue("Host", "https://dbc-123.cloud.databricks.com"); err != nil {
		settings.Close()
		t.Fatalf("set Host: %v", err)
	}
	settings.Close()

	enrolments, err := readRegistryEnrolments(registry.CURRENT_USER, base)
	if err != nil {
		t.Fatalf("readRegistryEnrolments() error: %v", err)
	}
	e, ok := enrolments["databricks/prod"]
	if !ok {
		t.Fatalf("grouped key not read back; got %v", enrolments)
	}
	if e.Engine != "databricks" {
		t.Errorf("Engine = %q, want databricks", e.Engine)
	}
	if e.Settings["host"] != "https://dbc-123.cloud.databricks.com" {
		t.Errorf("host = %v, want the databricks host", e.Settings["host"])
	}
}

func TestLoadFromRegistryNoKeys(t *testing.T) {
	// When no GPO keys exist, loadFromRegistry should return false.
	cfg, managed, err := loadFromRegistry()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// This test may return true if the machine happens to have dotvault
	// GPO keys installed. Skip in that case.
	if managed {
		t.Skip("GPO registry keys found on this machine; skipping no-keys test")
	}
	if cfg != nil {
		t.Error("expected nil config when no keys exist")
	}
}

func TestApplyRegistryLayerAgent(t *testing.T) {
	cfg := &Config{}
	enabled := uint32(1)
	layer := registryLayer{
		AgentEnabled:     &enabled,
		AgentUnixPath:    "/run/user/1000/dotvault/agent.sock",
		AgentWindowsPipe: `\\.\pipe\dotvault-agent`,
	}
	applyRegistryLayer(cfg, layer)

	if !cfg.Agent.Enabled {
		t.Errorf("Agent.Enabled = false, want true")
	}
	if cfg.Agent.Unix.Path != "/run/user/1000/dotvault/agent.sock" {
		t.Errorf("Agent.Unix.Path = %q", cfg.Agent.Unix.Path)
	}
	if cfg.Agent.Windows.Pipe != `\\.\pipe\dotvault-agent` {
		t.Errorf("Agent.Windows.Pipe = %q", cfg.Agent.Windows.Pipe)
	}
	// WindowsPutty absent from the layer: the tri-state stays nil (default true).
	if cfg.Agent.Windows.Putty != nil {
		t.Errorf("Agent.Windows.Putty = %v, want nil (default)", *cfg.Agent.Windows.Putty)
	}
}

// TestApplyRegistryLayerAgentPutty confirms an explicit WindowsPutty DWORD
// maps onto the tri-state pointer (0 => &false, non-zero => &true).
func TestApplyRegistryLayerAgentPutty(t *testing.T) {
	for _, tc := range []struct {
		name string
		dw   uint32
		want bool
	}{
		{"zero disables", 0, false},
		{"one enables", 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			dw := tc.dw
			applyRegistryLayer(cfg, registryLayer{AgentWindowsPutty: &dw})
			if cfg.Agent.Windows.Putty == nil {
				t.Fatalf("Putty = nil, want %v", tc.want)
			}
			if *cfg.Agent.Windows.Putty != tc.want {
				t.Errorf("Putty = %v, want %v", *cfg.Agent.Windows.Putty, tc.want)
			}
		})
	}
}

func TestReadRegistryAgentKeysOrdered(t *testing.T) {
	t.Cleanup(func() {
		for i := 0; i < 12; i++ {
			registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-agent\Agent\Keys\`+itoaTest(i))
		}
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-agent\Agent\Keys`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-agent\Agent`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-agent`)
	})

	// Create 12 index subkeys so numeric vs lexical ordering diverges
	// ("10" < "2" lexically). Each key's Source encodes its index so we can
	// assert the recovered order.
	for i := 0; i < 12; i++ {
		k, _, err := registry.CreateKey(
			registry.CURRENT_USER,
			`SOFTWARE\dotvault-test-agent\Agent\Keys\`+itoaTest(i),
			registry.ALL_ACCESS,
		)
		if err != nil {
			t.Fatalf("create key %d: %v", i, err)
		}
		if err := k.SetStringValue("Source", "src"+itoaTest(i)); err != nil {
			t.Fatalf("set Source %d: %v", i, err)
		}
		k.Close()
	}

	// Give one key the full field set including a Principals REG_MULTI_SZ.
	k0, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-agent\Agent\Keys\0`, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	k0.SetStringValue("Source", "vault-ca")
	k0.SetStringValue("Mount", "ssh-client-signer")
	k0.SetStringValue("Role", "dotvault-user")
	k0.SetStringValue("TTL", "15m")
	k0.SetStringValue("Socket", "/run/user/{{.uid}}/ssh-agent.socket")
	k0.SetStringValue("Pipe", `\\.\pipe\openssh-ssh-agent`)
	k0.SetDWordValue("EphemeralKey", 1)
	k0.SetStringsValue("Principals", []string{"{{.vault_username}}", "ops"})
	k0.Close()

	keys, err := readRegistryAgentKeys(registry.CURRENT_USER, `SOFTWARE\dotvault-test-agent`)
	if err != nil {
		t.Fatalf("readRegistryAgentKeys: %v", err)
	}
	if len(keys) != 12 {
		t.Fatalf("len = %d, want 12", len(keys))
	}
	// Numeric order: index 1..11 keep their "src<i>" Source.
	for i := 1; i < 12; i++ {
		if keys[i].Source != "src"+itoaTest(i) {
			t.Errorf("keys[%d].Source = %q, want %q", i, keys[i].Source, "src"+itoaTest(i))
		}
	}
	// Index 0 carries the full vault-ca field set plus the agent Socket/Pipe.
	if keys[0].Source != "vault-ca" || keys[0].Mount != "ssh-client-signer" ||
		keys[0].Role != "dotvault-user" || keys[0].TTL != "15m" || !keys[0].EphemeralKey {
		t.Errorf("keys[0] = %+v", keys[0])
	}
	if keys[0].Socket != "/run/user/{{.uid}}/ssh-agent.socket" || keys[0].Pipe != `\\.\pipe\openssh-ssh-agent` {
		t.Errorf("keys[0] socket/pipe = %q / %q", keys[0].Socket, keys[0].Pipe)
	}
	if len(keys[0].Principals) != 2 || keys[0].Principals[0] != "{{.vault_username}}" {
		t.Errorf("keys[0].Principals = %v", keys[0].Principals)
	}
}

func TestReadRegistryAgentKeysNotExist(t *testing.T) {
	keys, err := readRegistryAgentKeys(registry.CURRENT_USER, `SOFTWARE\dotvault-nonexistent-agent`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if keys != nil {
		t.Errorf("expected nil keys, got %v", keys)
	}
}

func TestReadRegistryAgentKeysNonNumericRejected(t *testing.T) {
	t.Cleanup(func() {
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-agent-bad\Agent\Keys\bogus`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-agent-bad\Agent\Keys`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-agent-bad\Agent`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-agent-bad`)
	})
	k, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`SOFTWARE\dotvault-test-agent-bad\Agent\Keys\bogus`,
		registry.ALL_ACCESS,
	)
	if err != nil {
		t.Fatal(err)
	}
	k.SetStringValue("Source", "kv")
	k.Close()

	_, err = readRegistryAgentKeys(registry.CURRENT_USER, `SOFTWARE\dotvault-test-agent-bad`)
	if err == nil {
		t.Fatalf("expected an error for a non-integer key subkey name")
	}
}

// TestApplyRegistryLayerWebText covers the Web markdown fields applied from
// the registry layer; the observability scalars are covered by
// TestApplyRegistryLayerObservability above.
func TestApplyRegistryLayerWebText(t *testing.T) {
	cfg := &Config{}
	layer := registryLayer{
		WebLoginText:      "# Welcome",
		WebSecretViewText: "Handle with care.",
	}
	applyRegistryLayer(cfg, layer)

	if cfg.Web.LoginText != "# Welcome" {
		t.Errorf("Web.LoginText = %q", cfg.Web.LoginText)
	}
	if cfg.Web.SecretViewText != "Handle with care." {
		t.Errorf("Web.SecretViewText = %q", cfg.Web.SecretViewText)
	}
}

func TestReadRegistryObservabilityHeaders(t *testing.T) {
	t.Cleanup(func() {
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-obs\Observability\Headers`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-obs\Observability`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-obs`)
	})

	k, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`SOFTWARE\dotvault-test-obs\Observability\Headers`,
		registry.ALL_ACCESS,
	)
	if err != nil {
		t.Fatalf("create Headers key: %v", err)
	}
	// Mixed-case header name to confirm the loader preserves case verbatim.
	if err := k.SetStringValue("X-Honeycomb-Team", "abc123"); err != nil {
		t.Fatalf("set header: %v", err)
	}
	if err := k.SetStringValue("Authorization", "Bearer tok"); err != nil {
		t.Fatalf("set header: %v", err)
	}
	k.Close()

	headers, err := readRegistryObservabilityHeaders(registry.CURRENT_USER, `SOFTWARE\dotvault-test-obs`)
	if err != nil {
		t.Fatalf("readRegistryObservabilityHeaders: %v", err)
	}
	if len(headers) != 2 {
		t.Fatalf("len(headers) = %d, want 2", len(headers))
	}
	if headers["X-Honeycomb-Team"] != "abc123" {
		t.Errorf("X-Honeycomb-Team = %q, want %q", headers["X-Honeycomb-Team"], "abc123")
	}
	if headers["Authorization"] != "Bearer tok" {
		t.Errorf("Authorization = %q, want %q", headers["Authorization"], "Bearer tok")
	}
}

func TestReadRegistryObservabilityHeadersNotExist(t *testing.T) {
	headers, err := readRegistryObservabilityHeaders(registry.CURRENT_USER, `SOFTWARE\dotvault-nonexistent-obs`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if headers != nil {
		t.Errorf("expected nil headers, got %v", headers)
	}
}

func itoaTest(i int) string {
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
