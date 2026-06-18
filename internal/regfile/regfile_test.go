package regfile

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

func mustGenerate(t *testing.T, cfg *config.Config) string {
	t.Helper()
	got, err := GenerateText(cfg)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	return got
}

// validBaseConfig returns a minimally valid Config — one that
// `config.(*Config).validate()` would accept — for tests that want a
// realistic baseline matching what the CLI passes to Generate*.
//
// regfile.Generate* itself does not require validation; many tests in
// this file deliberately construct partial configs to exercise specific
// renderer paths in isolation. End-to-end coverage for the
// load-and-render path lives in TestGenerateOnLoadedConfig.
func validBaseConfig() *config.Config {
	return &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:     "minimal",
				VaultKey: "minimal",
				Target: config.Target{
					Path:   "~/.dotvault/minimal",
					Format: "text",
				},
			},
		},
	}
}

func TestGenerateMinimal(t *testing.T) {
	// Use a config that would actually pass config.(*Config).validate().
	// The CLI always feeds Generate* a validated config, so tests should
	// mirror that.
	cfg := validBaseConfig()
	cfg.Sync = config.SyncConfig{RawInterval: "15m"}

	got := mustGenerate(t, cfg)

	wantContains := []string{
		"Windows Registry Editor Version 5.00\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault]\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Vault]\r\n",
		"\"Address\"=\"https://vault.example.com:8200\"\r\n",
		"\"DisableTokenRenewal\"=dword:00000000\r\n",
		"\"TLSSkipVerify\"=dword:00000000\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Sync]\r\n",
		"\"Interval\"=\"15m\"\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Web]\r\n",
		"\"Enabled\"=dword:00000000\r\n",
	}
	for _, want := range wantContains {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, got)
		}
	}
}

func TestGenerateRulesAndOAuth(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:        "gh",
				Description: "GitHub host config",
				VaultKey:    "gh",
				Target: config.Target{
					Path:   "~/.config/gh/hosts.yml",
					Format: "yaml",
				},
				OAuth: &config.OAuthConfig{
					Provider: "github",
					Scopes:   []string{"repo", "read:org"},
				},
			},
		},
	}

	got := mustGenerate(t, cfg)

	wantContains := []string{
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Rules]\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Rules\\gh]\r\n",
		"\"Description\"=\"GitHub host config\"\r\n",
		"\"TargetFormat\"=\"yaml\"\r\n",
		"\"TargetPath\"=\"~/.config/gh/hosts.yml\"\r\n",
		"\"VaultKey\"=\"gh\"\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Rules\\gh\\OAuth]\r\n",
		"\"Provider\"=\"github\"\r\n",
		// REG_MULTI_SZ for ["repo", "read:org"]: "repo"\0"read:org"\0\0
		// As UTF-16LE bytes the value starts with the prefix below; the
		// rest may be on a continuation line because of line wrapping.
		"\"Scopes\"=hex(7):72,00,65,00,70,00,6f,00,00,00,",
	}
	for _, want := range wantContains {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, got)
		}
	}
}

func TestGenerateMultilineTemplate(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:     "gh",
				VaultKey: "gh",
				Target: config.Target{
					Path:     "~/.config/gh/hosts.yml",
					Format:   "yaml",
					Template: "github.com:\n  oauth_token: \"x\"\n",
				},
			},
		},
	}

	got := mustGenerate(t, cfg)

	if !strings.Contains(got, "\"TargetTemplate\"=hex(1):") {
		t.Errorf("multi-line template should be emitted as hex(1):\n%s", got)
	}
	// First two characters of the template are 'g' (0x67) and 'i' (0x69)
	// in UTF-16LE: 67,00,69,00.
	if !strings.Contains(got, "67,00,69,00") {
		t.Errorf("expected UTF-16LE bytes for template start; got:\n%s", got)
	}
	// Newline (0x0A) should appear in the hex bytes.
	if !strings.Contains(got, "0a,00") {
		t.Errorf("expected UTF-16LE LF byte (0a,00); got:\n%s", got)
	}
}

// TestSSHConfigRuleRoundTrip proves the ssh_config format has full Windows
// registry parity: a rule whose target format is "ssh_config" with a multi-line
// template (the dotvault-forward use case) survives both the .reg render → parse
// cycle (the multi-line template routing through hex(1) like any other) and the
// .reg → YAML → config.Load pipeline (so the format string is accepted by the
// validator on both surfaces).
func TestSSHConfigRuleRoundTrip(t *testing.T) {
	const template = "Host *\n    User {{ username }}\n" +
		"    RemoteForward /home/{{ username }}/.ssh/dotvault.sock 127.0.0.1:8200\n"
	src := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:     "ssh",
				VaultKey: "ssh",
				Target: config.Target{
					Path:     "~/.ssh/config",
					Format:   "ssh_config",
					Template: template,
				},
			},
		},
	}

	// .reg render carries the format verbatim and emits the multi-line
	// template as hex(1).
	text := mustGenerate(t, src)
	if !strings.Contains(text, "\"TargetFormat\"=\"ssh_config\"\r\n") {
		t.Errorf("rendered .reg missing ssh_config format\n--- output ---\n%s", text)
	}
	if !strings.Contains(text, "\"TargetTemplate\"=hex(1):") {
		t.Errorf("multi-line ssh_config template should be hex(1)\n--- output ---\n%s", text)
	}

	// .reg parse reconstructs the rule with the format and template intact.
	parsed, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(parsed.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(parsed.Rules))
	}
	if parsed.Rules[0].Target.Format != "ssh_config" {
		t.Errorf("Format = %q, want ssh_config", parsed.Rules[0].Target.Format)
	}
	if parsed.Rules[0].Target.Template != template {
		t.Errorf("Template round-trip mismatch.\n--- want ---\n%q\n--- got ---\n%q", template, parsed.Rules[0].Target.Template)
	}

	// The YAML path (reg-export → config.Load) accepts the format too.
	yamlBytes, err := MarshalYAML(src)
	if err != nil {
		t.Fatalf("MarshalYAML: %v", err)
	}
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(yamlPath, yamlBytes, 0600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	loaded, err := config.Load(yamlPath)
	if err != nil {
		t.Fatalf("config.Load rejected ssh_config rule: %v\nyaml:\n%s", err, yamlBytes)
	}
	if len(loaded.Rules) != 1 || loaded.Rules[0].Target.Format != "ssh_config" {
		t.Errorf("ssh_config rule not preserved through YAML load: %+v", loaded.Rules)
	}
}

// TestKeylessRuleRoundTrip covers a rule with no vault_key (an empty VaultKey):
// it must survive the .reg render → parse cycle (VaultKey emitted as "" and read
// back empty, not dropped or defaulted) and the .reg → YAML → config.Load
// pipeline (the validator accepting a keyless rule because it carries a
// template). This is the registry-parity guarantee for the keyless feature.
func TestKeylessRuleRoundTrip(t *testing.T) {
	const template = "Host *\n    User {{ username }}\n"
	src := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name: "dotvault-forward", // no VaultKey
				Target: config.Target{
					Path:     "~/.ssh/config",
					Format:   "ssh_config",
					Template: template,
				},
			},
		},
	}

	text := mustGenerate(t, src)
	if !strings.Contains(text, "\"VaultKey\"=\"\"\r\n") {
		t.Errorf("keyless rule should emit VaultKey as \"\"\n--- output ---\n%s", text)
	}

	parsed, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(parsed.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(parsed.Rules))
	}
	if parsed.Rules[0].VaultKey != "" {
		t.Errorf("VaultKey = %q, want empty (keyless)", parsed.Rules[0].VaultKey)
	}
	if parsed.Rules[0].Target.Template != template {
		t.Errorf("Template round-trip mismatch: %q", parsed.Rules[0].Target.Template)
	}

	// The YAML path (reg-export → config.Load) accepts the keyless rule.
	yamlBytes, err := MarshalYAML(src)
	if err != nil {
		t.Fatalf("MarshalYAML: %v", err)
	}
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(yamlPath, yamlBytes, 0600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	loaded, err := config.Load(yamlPath)
	if err != nil {
		t.Fatalf("config.Load rejected keyless rule: %v\nyaml:\n%s", err, yamlBytes)
	}
	if len(loaded.Rules) != 1 || loaded.Rules[0].VaultKey != "" {
		t.Errorf("keyless rule not preserved through YAML load: %+v", loaded.Rules)
	}
}

func TestGenerateEnrolments(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Enrolments: map[string]config.Enrolment{
			"gh": {
				Engine: "github",
				Settings: map[string]any{
					"host":   "github.com",
					"scopes": []any{"repo", "gist"},
				},
			},
			"ssh": {
				Engine: "ssh",
				Settings: map[string]any{
					"passphrase": "recommended",
				},
			},
		},
	}

	got := mustGenerate(t, cfg)

	wantContains := []string{
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Enrolments]\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Enrolments\\gh]\r\n",
		"\"Engine\"=\"github\"\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Enrolments\\gh\\Settings]\r\n",
		"\"host\"=\"github.com\"\r\n",
		"\"scopes\"=hex(7):",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Enrolments\\ssh]\r\n",
		"\"Engine\"=\"ssh\"\r\n",
		"\"passphrase\"=\"recommended\"\r\n",
	}
	for _, want := range wantContains {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, got)
		}
	}

	// gh should appear before ssh (sorted output).
	ghIdx := strings.Index(got, `\Enrolments\gh]`)
	sshIdx := strings.Index(got, `\Enrolments\ssh]`)
	if ghIdx == -1 || sshIdx == -1 || ghIdx > sshIdx {
		t.Errorf("expected gh before ssh in sorted output; gh=%d ssh=%d", ghIdx, sshIdx)
	}
}

// TestGroupedEnrolmentKeyRoundTrip verifies that a one-level grouped enrolment
// key ("databricks/prod") survives the .reg render → parse cycle. The forward
// slash is legal inside a registry key *name* (only backslash is the path
// separator), so the grouped key becomes a single Enrolments subkey named
// "databricks/prod" and round-trips without any structural nesting — keeping
// the GPO-parity contract intact for grouped enrolments.
func TestGroupedEnrolmentKeyRoundTrip(t *testing.T) {
	src := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{Name: "minimal", VaultKey: "minimal", Target: config.Target{Path: "~/.dotvault/minimal", Format: "text"}},
		},
		Enrolments: map[string]config.Enrolment{
			"databricks/prod": {
				Engine:   "databricks",
				Settings: map[string]any{"host": "https://dbc-123.cloud.databricks.com"},
			},
		},
	}

	text, err := GenerateText(src)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	if !strings.Contains(text, `\Enrolments\databricks/prod]`) {
		t.Errorf("rendered .reg missing grouped enrolment subkey\n--- output ---\n%s", text)
	}

	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	e, ok := got.Enrolments["databricks/prod"]
	if !ok {
		t.Fatalf("grouped enrolment key did not round-trip; got %v", got.Enrolments)
	}
	if e.Engine != "databricks" {
		t.Errorf("engine = %q, want databricks", e.Engine)
	}
	if e.Settings["host"] != "https://dbc-123.cloud.databricks.com" {
		t.Errorf("host setting = %v, want the databricks host", e.Settings["host"])
	}
}

func TestGenerateNestedMapSetting(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Enrolments: map[string]config.Enrolment{
			"sample": {
				Engine: "copy",
				Settings: map[string]any{
					"format": "json",
					"from": map[string]any{
						"mount": "kv",
						"path":  "apps/sample/keys/{{.user}}",
					},
				},
			},
		},
	}

	got := mustGenerate(t, cfg)

	wantContains := []string{
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Enrolments\\sample]\r\n",
		"\"Engine\"=\"copy\"\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Enrolments\\sample\\Settings]\r\n",
		"\"format\"=\"json\"\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Enrolments\\sample\\Settings\\from]\r\n",
		"\"mount\"=\"kv\"\r\n",
		"\"path\"=\"apps/sample/keys/{{.user}}\"\r\n",
	}
	for _, want := range wantContains {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, got)
		}
	}
}

func TestGenerateUnsupportedSettingTypeErrors(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Enrolments: map[string]config.Enrolment{
			"gh": {
				Engine: "github",
				Settings: map[string]any{
					"port": 22, // ints are not representable
				},
			},
		},
	}
	_, err := GenerateText(cfg)
	if err == nil {
		t.Fatalf("expected error for unsupported setting type")
	}
	if !strings.Contains(err.Error(), "port") || !strings.Contains(err.Error(), "int") {
		t.Errorf("error should mention the offending setting and type; got: %v", err)
	}
}

func TestGenerateMixedListErrors(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Enrolments: map[string]config.Enrolment{
			"gh": {
				Engine: "github",
				Settings: map[string]any{
					"scopes": []any{"repo", 42}, // mixed list
				},
			},
		},
	}
	_, err := GenerateText(cfg)
	if err == nil {
		t.Fatalf("expected error for mixed-type list")
	}
}

func TestGenerateRejectsControlCharsInName(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Enrolments: map[string]config.Enrolment{
			"gh": {
				Engine: "github",
				Settings: map[string]any{
					"bad\nname": "value",
				},
			},
		},
	}
	_, err := GenerateText(cfg)
	if err == nil {
		t.Fatalf("expected error for control char in setting name")
	}
}

func TestGenerateEscapesQuoteAndBackslashInName(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Enrolments: map[string]config.Enrolment{
			"gh": {
				Engine: "github",
				Settings: map[string]any{
					`weird"name\path`: "value",
				},
			},
		},
	}
	got := mustGenerate(t, cfg)
	// Both " and \ in the name must be backslash-escaped on the wire.
	if !strings.Contains(got, `"weird\"name\\path"="value"`) {
		t.Errorf("setting name not escaped correctly; got:\n%s", got)
	}
}

func TestSyncIntervalDefaultedYAMLEmitsEmpty(t *testing.T) {
	// When the YAML omits sync.interval, config.Load fills Interval with
	// the 15m default but leaves RawInterval empty. Exporting must NOT
	// fall back to time.Duration.String() ("15m0s"), which would pollute
	// diffs and round-trip through registry/validate to the same default
	// anyway. The export emits an empty REG_SZ; the registry-side load
	// then re-applies the default during validate.
	yaml := `vault:
  address: "https://vault.example.com:8200"
rules:
  - name: r
    vault_key: r
    target:
      path: /tmp/r
      format: text
`
	dir := t.TempDir()
	yamlPath := dir + "/config.yaml"
	if err := os.WriteFile(yamlPath, []byte(yaml), 0600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	cfg, err := config.Load(yamlPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	got, err := GenerateText(cfg)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	if strings.Contains(got, "15m0s") {
		t.Errorf("output should not contain Go-format duration \"15m0s\":\n%s", got)
	}
	if !strings.Contains(got, `"Interval"=""`) {
		t.Errorf("expected empty REG_SZ for unset interval; got:\n%s", got)
	}
}

func TestRulesAndEnrolmentsAreDeletedBeforeRecreate(t *testing.T) {
	// Re-importing an exported .reg should be idempotent: rules or
	// enrolments removed from YAML must also disappear from the registry,
	// so the export emits a deletion stanza for each dynamic subtree
	// before the recreation block.
	cfg := validBaseConfig()
	cfg.Enrolments = map[string]config.Enrolment{
		"gh": {Engine: "github"},
	}
	got := mustGenerate(t, cfg)

	rulesDel := `[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\Rules]`
	rulesKey := `[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\Rules]`
	enrolDel := `[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\Enrolments]`
	enrolKey := `[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\Enrolments]`

	for _, want := range []string{rulesDel, rulesKey, enrolDel, enrolKey} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in output:\n%s", want, got)
		}
	}
	// Deletion must come before recreation so the .reg processor wipes
	// the subtree first.
	if strings.Index(got, rulesDel) > strings.Index(got, rulesKey) {
		t.Errorf("Rules deletion stanza must precede recreation")
	}
	if strings.Index(got, enrolDel) > strings.Index(got, enrolKey) {
		t.Errorf("Enrolments deletion stanza must precede recreation")
	}
}

func TestEmptyRulesEmitsOnlyDeletion(t *testing.T) {
	// A config with no rules should still emit `[-...\Rules]` so an
	// import wipes any previously-defined rules.
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
	}
	got, err := GenerateText(cfg)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	if !strings.Contains(got, `[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\Rules]`) {
		t.Errorf("expected Rules deletion stanza even with no rules:\n%s", got)
	}
	// And no recreation key for Rules (no rules to put under it).
	if strings.Contains(got, `[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\Rules]`+"\r\n") {
		t.Errorf("did not expect Rules recreation when no rules present:\n%s", got)
	}
}

func TestEmptyOAuthScopesEmitsEmptyMultiSZ(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:     "gh",
				VaultKey: "gh",
				Target:   config.Target{Path: "~/x", Format: "yaml"},
				OAuth: &config.OAuthConfig{
					Provider: "github",
					Scopes:   []string{}, // explicit empty list
				},
			},
		},
	}
	got := mustGenerate(t, cfg)
	// Empty REG_MULTI_SZ is just the trailing NUL pair: 00,00.
	if !strings.Contains(got, `"Scopes"=hex(7):00,00`) {
		t.Errorf("expected empty REG_MULTI_SZ for empty scopes; got:\n%s", got)
	}
}

func TestNilOAuthScopesOmitted(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:     "gh",
				VaultKey: "gh",
				Target:   config.Target{Path: "~/x", Format: "yaml"},
				OAuth: &config.OAuthConfig{
					Provider: "github",
					// Scopes is nil — key absent in YAML, omit from output
				},
			},
		},
	}
	got := mustGenerate(t, cfg)
	if strings.Contains(got, `"Scopes"=`) {
		t.Errorf("nil scopes should be omitted from output; got:\n%s", got)
	}
}

func TestEmptyEnrolmentListSettingEmitsEmptyMultiSZ(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Enrolments: map[string]config.Enrolment{
			"gh": {
				Engine: "github",
				Settings: map[string]any{
					"scopes": []any{}, // explicit empty list from YAML
				},
			},
		},
	}
	got := mustGenerate(t, cfg)
	if !strings.Contains(got, `"scopes"=hex(7):00,00`) {
		t.Errorf("expected empty REG_MULTI_SZ for empty scopes setting; got:\n%s", got)
	}
}

func TestRejectsBadRuleName(t *testing.T) {
	// Names containing path/structural delimiters or control chars must be
	// rejected. Unicode names are NOT in this list because they're allowed
	// (UTF-16LE output represents them faithfully).
	for _, bad := range []string{`with\backslash`, `with]bracket`, `with[bracket`, "with\nnewline"} {
		cfg := &config.Config{
			Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
			Rules: []config.Rule{
				{
					Name:     bad,
					VaultKey: "k",
					Target:   config.Target{Path: "/tmp/x", Format: "text"},
				},
			},
		}
		if _, err := GenerateText(cfg); err == nil {
			t.Errorf("expected error for rule name %q", bad)
		}
	}
}

func TestAcceptsUnicodeRuleName(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:     "café",
				VaultKey: "k",
				Target:   config.Target{Path: "/tmp/x", Format: "text"},
			},
		},
	}
	got, err := GenerateText(cfg)
	if err != nil {
		t.Fatalf("Unicode rule name should be accepted: %v", err)
	}
	if !strings.Contains(got, `\Rules\café]`) {
		t.Errorf("Unicode rule name not present in key path:\n%s", got)
	}
}

func TestRejectsBadEnrolmentName(t *testing.T) {
	for _, bad := range []string{`with\backslash`, `with]bracket`, "with\tcontrol"} {
		cfg := &config.Config{
			Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
			Enrolments: map[string]config.Enrolment{
				bad: {Engine: "github"},
			},
		}
		if _, err := GenerateText(cfg); err == nil {
			t.Errorf("expected error for enrolment name %q", bad)
		}
	}
}

func TestAcceptsUnicodeValueName(t *testing.T) {
	// Unicode characters in value names are allowed: the default UTF-16LE
	// output represents them faithfully and the --ascii output stays
	// valid UTF-8.
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Enrolments: map[string]config.Enrolment{
			"gh": {
				Engine: "github",
				Settings: map[string]any{
					"naïve": "value",
				},
			},
		},
	}
	got, err := GenerateText(cfg)
	if err != nil {
		t.Fatalf("Unicode value name should be accepted: %v", err)
	}
	if !strings.Contains(got, `"naïve"="value"`) {
		t.Errorf("Unicode value name not present:\n%s", got)
	}
}

func TestRejectsNULInStringValue(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Enrolments: map[string]config.Enrolment{
			"gh": {
				Engine: "github",
				Settings: map[string]any{
					"key": "before\x00after",
				},
			},
		},
	}
	_, err := GenerateText(cfg)
	if err == nil {
		t.Fatal("expected error for embedded NUL in string value")
	}
	if !strings.Contains(err.Error(), "NUL") {
		t.Errorf("error should mention NUL; got: %v", err)
	}
}

func TestRejectsNULInMultiStringElement(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:     "gh",
				VaultKey: "k",
				Target:   config.Target{Path: "/tmp/x", Format: "text"},
				OAuth: &config.OAuthConfig{
					Provider: "github",
					Scopes:   []string{"ok", "bad\x00scope"},
				},
			},
		},
	}
	_, err := GenerateText(cfg)
	if err == nil {
		t.Fatal("expected error for embedded NUL in multi-string element")
	}
}

func TestEmptyStringEmittedExplicitly(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{
			Address: "https://vault.example.com:8200",
			// CACert/AuthMethod/etc. are empty — should be emitted as ""
			// so re-import clears any previously-set value.
		},
		Sync: config.SyncConfig{RawInterval: "15m"},
	}
	got, err := GenerateText(cfg)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	for _, want := range []string{
		`"AuthMethod"=""`,
		`"AuthMount"=""`,
		`"AuthRole"=""`,
		`"CACert"=""`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in output (clearing semantics):\n%s", want, got)
		}
	}
}

func TestHexValueLongHeadStillEmitsByteOnFirstLine(t *testing.T) {
	// Build a setting name long enough that head + first byte sits well
	// past 50 chars but still fits within the wrap budget. The first
	// emitted line must contain at least one hex byte rather than a bare
	// `head\` with no payload.
	longName := strings.Repeat("a", 50) // legal printable ASCII
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Enrolments: map[string]config.Enrolment{
			"gh": {
				Engine: "github",
				Settings: map[string]any{
					longName: "value\nwith newline", // forces hex(1)
				},
			},
		},
	}
	got := mustGenerate(t, cfg)
	// Find the first hex line for this setting and confirm it contains
	// at least one byte token before any backslash continuation.
	prefix := `"` + longName + `"=hex(1):`
	idx := strings.Index(got, prefix)
	if idx == -1 {
		t.Fatalf("hex value not present in output:\n%s", got)
	}
	firstLineEnd := strings.Index(got[idx:], "\r\n")
	if firstLineEnd == -1 {
		t.Fatalf("no CRLF after hex value start")
	}
	firstLine := got[idx : idx+firstLineEnd]
	// The body after `hex(1):` must contain at least one two-hex-digit byte.
	body := strings.TrimSuffix(strings.TrimPrefix(firstLine, prefix), `\`)
	if len(body) < 2 {
		t.Errorf("first hex line has no payload byte: %q", firstLine)
	}
}

func TestHexValueRejectsImpossiblyLongName(t *testing.T) {
	// A name so long that head + first byte cannot fit within maxLineLen
	// must error rather than produce malformed output.
	tooLong := strings.Repeat("a", 200)
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Enrolments: map[string]config.Enrolment{
			"gh": {
				Engine: "github",
				Settings: map[string]any{
					tooLong: "value\nwith newline",
				},
			},
		},
	}
	if _, err := GenerateText(cfg); err == nil {
		t.Fatalf("expected error for impossibly long value name")
	}
}

func TestQuoteREGSZ(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{`hello`, `"hello"`},
		{`with"quote`, `"with\"quote"`},
		{`back\slash`, `"back\\slash"`},
		{`C:\Program Files\foo`, `"C:\\Program Files\\foo"`},
	}
	for _, tt := range tests {
		got := quoteREGSZ(tt.in)
		if got != tt.want {
			t.Errorf("quoteREGSZ(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNeedsHex(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"hello", false},
		{"with\nnewline", true},
		{"with\ttab", true},
		{"unicode é", true},
		{"all printable !@#$%^&*()", false},
	}
	for _, tt := range tests {
		got := needsHex(tt.in)
		if got != tt.want {
			t.Errorf("needsHex(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestUTF16StringBytes(t *testing.T) {
	// "A" -> 41,00 plus NUL terminator 00,00.
	got := utf16StringBytes("A")
	want := []byte{0x41, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("utf16StringBytes(\"A\") = % x, want % x", got, want)
	}
}

func TestUTF16MultiStringBytesSingle(t *testing.T) {
	// REG_MULTI_SZ for ["A"]: "A"\0\0
	// As UTF-16LE bytes: 41,00,00,00,00,00 (single string + double-NUL terminator)
	got := utf16MultiStringBytes([]string{"A"})
	want := []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("utf16MultiStringBytes([\"A\"]) = % x, want % x", got, want)
	}
}

func TestUTF16MultiStringBytesMulti(t *testing.T) {
	// ["A", "B"] -> 41,00,00,00,42,00,00,00,00,00
	got := utf16MultiStringBytes([]string{"A", "B"})
	want := []byte{0x41, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("utf16MultiStringBytes = % x, want % x", got, want)
	}
}

func TestUTF16MultiStringBytesEmpty(t *testing.T) {
	// Empty MULTI_SZ is just the trailing NUL pair.
	got := utf16MultiStringBytes(nil)
	want := []byte{0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("utf16MultiStringBytes(nil) = % x, want % x", got, want)
	}
}

func TestEncodeUTF16LE(t *testing.T) {
	got := encodeUTF16LE("A")
	// BOM + A in UTF-16LE
	want := []byte{0xFF, 0xFE, 0x41, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("encodeUTF16LE = % x, want % x", got, want)
	}
}

func TestGenerateProducesUTF16LEWithBOM(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
	}
	got, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(got) < 2 || got[0] != 0xFF || got[1] != 0xFE {
		t.Errorf("Generate output missing UTF-16LE BOM; first bytes = % x", got[:min(8, len(got))])
	}
	// First payload character is 'W' from "Windows Registry...".
	if len(got) < 4 || got[2] != 'W' || got[3] != 0x00 {
		t.Errorf("Generate output not UTF-16LE encoded; bytes 2-3 = % x", got[2:4])
	}
}

func TestGenerateOnLoadedConfig(t *testing.T) {
	// Round-trip: load a YAML through config.Load (which runs validate)
	// and confirm Generate accepts the result. This exercises the actual
	// path the CLI uses.
	yamlBody := `vault:
  address: "https://vault.example.com:8200"
  auth_method: "oidc"
sync:
  interval: "15m"
rules:
  - name: gh
    vault_key: gh
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      template: |
        github.com:
          oauth_token: "{{ .oauth_token }}"
enrolments:
  gh:
    engine: github
`
	dir := t.TempDir()
	yamlPath := dir + "/config.yaml"
	if err := os.WriteFile(yamlPath, []byte(yamlBody), 0600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	cfg, err := config.Load(yamlPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	got, err := GenerateText(cfg)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	for _, want := range []string{
		"Windows Registry Editor Version 5.00",
		`\Rules\gh]`,
		`"VaultKey"="gh"`,
		`\Enrolments\gh]`,
		`"Engine"="github"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("loaded-config output missing %q\n%s", want, got)
		}
	}
}

func TestHexValueAcceptsLongUnicodeName(t *testing.T) {
	// A name made entirely of multi-byte runes that exceeds maxLineLen
	// when measured in bytes but fits when measured in runes. Without
	// rune-aware length tracking, writeHexValue would (incorrectly)
	// reject this as "too long to encode within 76 columns".
	longUnicode := strings.Repeat("é", 40) // 40 runes, 80 UTF-8 bytes
	cfg := validBaseConfig()
	cfg.Enrolments = map[string]config.Enrolment{
		"gh": {
			Engine: "github",
			Settings: map[string]any{
				longUnicode: "value\nforces hex(1)",
			},
		},
	}
	if _, err := GenerateText(cfg); err != nil {
		t.Errorf("Unicode name should be accepted with rune-length tracking: %v", err)
	}
}

func TestHexLineWrapping(t *testing.T) {
	// Build a value long enough to force multiple continuations.
	value := strings.Repeat("a", 200)
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:     "r",
				VaultKey: "k",
				Target: config.Target{
					Path:     "/tmp/x",
					Format:   "text",
					Template: "\n" + value, // leading newline forces hex(1)
				},
			},
		},
	}
	got := mustGenerate(t, cfg)

	if !strings.Contains(got, ",\\\r\n  ") {
		t.Errorf("expected backslash continuation in wrapped hex value; got:\n%s", got)
	}
	// Now that wrapping accounts for the two-space continuation indent,
	// no emitted *value* line should exceed maxLineLen characters. Key
	// declaration lines (`[...]`) are exempt: the wrap budget governs hex
	// value encoding only, and registry key paths can legitimately be
	// longer (regedit.exe emits them unwrapped too).
	for _, line := range strings.Split(got, "\r\n") {
		if strings.HasPrefix(line, "[") {
			continue
		}
		if len(line) > maxLineLen {
			t.Errorf("line exceeds wrap limit (%d > %d): %q", len(line), maxLineLen, line)
		}
	}
}
