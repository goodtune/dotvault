package regfile

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// TestParseTextRoundTrip generates a .reg in plain-text form and parses it
// back, asserting the recovered Config matches the source on the fields
// the renderer is responsible for round-tripping. The minimal-rule shape
// matches the canonical CLI usage: validate -> Generate -> Parse.
func TestParseTextRoundTrip(t *testing.T) {
	src := &config.Config{
		Vault: config.VaultConfig{
			Address:             "https://vault.example.com:8200",
			AuthMethod:          "oidc",
			KVMount:             "kv",
			UserPrefix:          "users/",
			DisableTokenRenewal: true,
		},
		Sync: config.SyncConfig{RawInterval: "30m"},
		Web: config.WebConfig{
			Enabled: true,
			Listen:  "127.0.0.1:9000",
		},
		Rules: []config.Rule{
			{
				Name:        "gh",
				Description: "GitHub host config",
				VaultKey:    "gh",
				Target: config.Target{
					Path:     "~/.config/gh/hosts.yml",
					Format:   "yaml",
					Template: "github.com:\n  oauth_token: \"{{ .oauth_token }}\"\n",
				},
				OAuth: &config.OAuthConfig{
					Provider: "github",
					Scopes:   []string{"repo", "read:org"},
				},
			},
		},
		Enrolments: map[string]config.Enrolment{
			"gh": {
				Engine: "github",
				Settings: map[string]any{
					"host":   "github.com",
					"scopes": []any{"repo", "gist"},
				},
			},
		},
	}

	text, err := GenerateText(src)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}

	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Compare structurally.
	if got.Vault != src.Vault {
		t.Errorf("Vault mismatch:\ngot:  %+v\nwant: %+v", got.Vault, src.Vault)
	}
	if got.Sync.RawInterval != src.Sync.RawInterval {
		t.Errorf("Sync.RawInterval = %q, want %q", got.Sync.RawInterval, src.Sync.RawInterval)
	}
	if got.Web != src.Web {
		t.Errorf("Web mismatch:\ngot:  %+v\nwant: %+v", got.Web, src.Web)
	}
	if !reflect.DeepEqual(got.Rules, src.Rules) {
		t.Errorf("Rules mismatch:\ngot:  %+v\nwant: %+v", got.Rules, src.Rules)
	}
	if !reflect.DeepEqual(got.Enrolments, src.Enrolments) {
		t.Errorf("Enrolments mismatch:\ngot:  %+v\nwant: %+v", got.Enrolments, src.Enrolments)
	}
}

// TestParseUTF16LE reads the canonical regedit.exe-style UTF-16LE-with-BOM
// output and confirms the parser handles the encoding transparently.
func TestParseUTF16LE(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Sync = config.SyncConfig{RawInterval: "15m"}

	utf16, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Sanity: BOM present.
	if !bytes.HasPrefix(utf16, []byte{0xFF, 0xFE}) {
		t.Fatalf("Generate did not produce a UTF-16LE BOM")
	}

	got, err := Parse(utf16)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Vault.Address != cfg.Vault.Address {
		t.Errorf("Vault.Address = %q, want %q", got.Vault.Address, cfg.Vault.Address)
	}
	if got.Sync.RawInterval != "15m" {
		t.Errorf("Sync.RawInterval = %q, want \"15m\"", got.Sync.RawInterval)
	}
}

// TestParseMultilineHexTemplate exercises the wrap/continuation handler
// for hex(1) values whose UTF-16LE byte sequence spans multiple physical
// lines.
func TestParseMultilineHexTemplate(t *testing.T) {
	template := strings.Repeat("github.com:\n  oauth_token: \"x\"\n", 8)
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:     "gh",
				VaultKey: "gh",
				Target: config.Target{
					Path:     "~/.config/gh/hosts.yml",
					Format:   "yaml",
					Template: template,
				},
			},
		},
	}
	text, err := GenerateText(cfg)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	if !strings.Contains(text, ",\\\r\n  ") {
		t.Fatalf("generated output should contain hex continuation")
	}
	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(got.Rules))
	}
	if got.Rules[0].Target.Template != template {
		t.Errorf("template not round-tripped:\ngot:  %q\nwant: %q",
			got.Rules[0].Target.Template, template)
	}
}

// TestParseEmptyMultiSZScopes confirms an explicit `[]` in the source
// survives the .reg round-trip as a non-nil empty list. Engines that key
// behaviour off "list present but empty" depend on this distinction.
func TestParseEmptyMultiSZScopes(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:     "gh",
				VaultKey: "gh",
				Target:   config.Target{Path: "~/x", Format: "yaml"},
				OAuth: &config.OAuthConfig{
					Provider: "github",
					Scopes:   []string{}, // explicit empty
				},
			},
		},
	}
	text, err := GenerateText(cfg)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Rules[0].OAuth == nil {
		t.Fatalf("OAuth lost during round-trip")
	}
	if got.Rules[0].OAuth.Scopes == nil {
		t.Errorf("explicit empty scopes should survive round-trip as non-nil slice; got nil")
	}
	if len(got.Rules[0].OAuth.Scopes) != 0 {
		t.Errorf("expected empty Scopes, got %v", got.Rules[0].OAuth.Scopes)
	}
}

// TestParseDeletionStanzaIgnored ensures the [-PATH] subtree wipe lines
// emitted for idempotency don't confuse the parser into discarding the
// recreation that follows.
func TestParseDeletionStanzaIgnored(t *testing.T) {
	cfg := validBaseConfig()
	text, err := GenerateText(cfg)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	if !strings.Contains(text, `[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\Rules]`) {
		t.Fatalf("generator should emit deletion stanza")
	}
	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Rules) != 1 || got.Rules[0].Name != "minimal" {
		t.Errorf("rules not recovered after deletion stanza: %+v", got.Rules)
	}
}

// TestParseValidatesAfterLoad confirms a parsed Config is acceptable to
// config.(*Config).validate, simulating how the CLI's reg-export path
// will hand off to the loader before printing YAML.
func TestParseValidatesAfterLoad(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Sync = config.SyncConfig{RawInterval: "15m"}

	text, err := GenerateText(cfg)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	parsed, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Encode parsed config to YAML and reload via config.Load to
	// exercise the validation pipeline the CLI will invoke.
	yamlBytes, err := MarshalYAML(parsed)
	if err != nil {
		t.Fatalf("MarshalYAML: %v", err)
	}
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(yamlPath, yamlBytes, 0600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	if _, err := config.Load(yamlPath); err != nil {
		t.Errorf("config.Load on round-tripped YAML failed: %v\nyaml:\n%s", err, yamlBytes)
	}
}

// TestParseRejectsUnknownInput surfaces a clear error when the caller
// hands us something that isn't a Windows Registry Editor v5 file.
func TestParseRejectsUnknownInput(t *testing.T) {
	if _, err := Parse([]byte("[Hello]\n")); err == nil {
		t.Errorf("expected error for non-reg input")
	}
}

// TestParseEnrolmentSettingTypes covers REG_SZ and REG_MULTI_SZ settings
// inside an enrolment's Settings subkey and confirms multi-string values
// emerge as []any (matching how YAML unmarshal would represent the same
// list, so downstream code sees a single representation).
func TestParseEnrolmentSettingTypes(t *testing.T) {
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
		},
	}
	text, err := GenerateText(cfg)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	en, ok := got.Enrolments["gh"]
	if !ok {
		t.Fatalf("missing gh enrolment")
	}
	if en.Engine != "github" {
		t.Errorf("Engine = %q, want \"github\"", en.Engine)
	}
	if got, want := en.Settings["host"], "github.com"; got != want {
		t.Errorf("settings[host] = %v, want %v", got, want)
	}
	scopes, ok := en.Settings["scopes"].([]any)
	if !ok {
		t.Fatalf("settings[scopes] = %T, want []any", en.Settings["scopes"])
	}
	if !reflect.DeepEqual(scopes, []any{"repo", "gist"}) {
		t.Errorf("settings[scopes] = %v, want [repo gist]", scopes)
	}
}

// TestMarshalYAMLLoadsBack covers the full reg -> yaml -> Config pipeline.
func TestMarshalYAMLLoadsBack(t *testing.T) {
	src := &config.Config{
		Vault: config.VaultConfig{
			Address:    "https://vault.example.com:8200",
			AuthMethod: "ldap",
			KVMount:    "secret",
			UserPrefix: "team/",
		},
		Sync: config.SyncConfig{RawInterval: "5m"},
		Rules: []config.Rule{
			{
				Name:     "netrc",
				VaultKey: "netrc",
				Target: config.Target{
					Path:   "~/.netrc",
					Format: "netrc",
				},
			},
		},
	}
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
		t.Fatalf("config.Load: %v\nyaml:\n%s", err, yamlBytes)
	}
	if loaded.Vault.Address != src.Vault.Address {
		t.Errorf("Vault.Address = %q, want %q", loaded.Vault.Address, src.Vault.Address)
	}
	if loaded.Sync.RawInterval != src.Sync.RawInterval {
		t.Errorf("Sync.RawInterval = %q, want %q", loaded.Sync.RawInterval, src.Sync.RawInterval)
	}
	if len(loaded.Rules) != 1 || loaded.Rules[0].Name != "netrc" {
		t.Errorf("rules not preserved: %+v", loaded.Rules)
	}
}

// TestParseLowercasesEnrolmentSettingNames mirrors the registry-side
// loader's case-insensitive handling: a hand-edited .reg that capitalises
// settings names like "Host" or "ClientID" must still surface as the
// lowercase keys engines consume (e.g. `host`, `client_id`).
func TestParseLowercasesEnrolmentSettingNames(t *testing.T) {
	reg := "Windows Registry Editor Version 5.00\r\n\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Enrolments\\gh]\r\n" +
		"\"Engine\"=\"github\"\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Enrolments\\gh\\Settings]\r\n" +
		"\"Host\"=\"github.com\"\r\n" +
		"\"Client_ID\"=\"abc123\"\r\n"

	got, err := Parse([]byte(reg))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	en, ok := got.Enrolments["gh"]
	if !ok {
		t.Fatalf("missing gh enrolment")
	}
	if _, present := en.Settings["host"]; !present {
		t.Errorf("expected lowercase 'host' key in settings; got %v", en.Settings)
	}
	if _, present := en.Settings["client_id"]; !present {
		t.Errorf("expected lowercase 'client_id' key in settings; got %v", en.Settings)
	}
	for k := range en.Settings {
		if k != strings.ToLower(k) {
			t.Errorf("setting key %q is not lowercase", k)
		}
	}
}

// TestMarshalYAMLMapKeysSorted pins the implicit map-key sort that
// yaml.v3 currently performs. The doc comment on MarshalYAML calls this
// out as a non-spec guarantee; if a future yaml.v3 release stops
// sorting we want this test to fail loudly so we can switch to an
// explicit yaml.Node walk before downstream diffs go noisy.
func TestMarshalYAMLMapKeysSorted(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:     "r",
				VaultKey: "r",
				Target:   config.Target{Path: "/tmp/r", Format: "text"},
			},
		},
		// Insert keys in non-alphabetical order so a stable iteration
		// would still betray missing sort logic.
		Enrolments: map[string]config.Enrolment{
			"zulu":    {Engine: "ssh"},
			"alpha":   {Engine: "github"},
			"mike":    {Engine: "jfrog"},
			"charlie": {Engine: "github", Settings: map[string]any{"zoo": "z", "ant": "a", "moose": "m"}},
		},
	}
	out, err := MarshalYAML(cfg)
	if err != nil {
		t.Fatalf("MarshalYAML: %v", err)
	}
	body := string(out)

	// Top-level enrolment keys must appear alphabetically.
	wantOrder := []string{"alpha", "charlie", "mike", "zulu"}
	prev := 0
	for _, name := range wantOrder {
		idx := strings.Index(body[prev:], "\n  "+name+":")
		if idx < 0 {
			t.Fatalf("enrolment %q missing from output:\n%s", name, body)
		}
		prev += idx + 1
	}

	// Settings map under "charlie" must also be alphabetised.
	settingsOrder := []string{"ant:", "moose:", "zoo:"}
	prev = strings.Index(body, "charlie:")
	for _, key := range settingsOrder {
		idx := strings.Index(body[prev:], key)
		if idx < 0 {
			t.Fatalf("settings key %q missing from output:\n%s", key, body)
		}
		prev += idx + 1
	}
}

// TestParseRejectsUnterminatedContinuation guards against a silent
// truncation of hex(1)/hex(7) values when the input ends mid-continuation.
// Without an explicit error the partial hex blob parses as a shorter
// value (e.g. a template clipped halfway through), so the parser must
// fail loudly instead.
func TestParseRejectsUnterminatedContinuation(t *testing.T) {
	bad := "Windows Registry Editor Version 5.00\r\n\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Rules\\r]\r\n" +
		"\"TargetTemplate\"=hex(1):67,00,69,00,\\\r\n" // dangling continuation
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatalf("expected error for unterminated continuation")
	}
	if !strings.Contains(err.Error(), "unterminated") {
		t.Errorf("error should mention 'unterminated'; got: %v", err)
	}
}

// TestParseSkipsValueDeletions accepts the regedit `"name"=-` syntax that
// removes a previously-set value. Real-world GPO exports routinely
// include these alongside [-KEY] stanzas; failing hard on them would
// stop reg-export from converting otherwise valid input.
func TestParseSkipsValueDeletions(t *testing.T) {
	src := "Windows Registry Editor Version 5.00\r\n\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Vault]\r\n" +
		"\"Address\"=\"https://vault.example.com:8200\"\r\n" +
		"\"DeprecatedSetting\"=-\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Rules\\r]\r\n" +
		"\"VaultKey\"=\"r\"\r\n" +
		"\"TargetPath\"=\"/tmp/r\"\r\n" +
		"\"TargetFormat\"=\"text\"\r\n" +
		"\"OldField\"=-\r\n"

	got, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse should accept value-deletion lines: %v", err)
	}
	if got.Vault.Address != "https://vault.example.com:8200" {
		t.Errorf("Vault.Address = %q, want %q", got.Vault.Address, "https://vault.example.com:8200")
	}
	if len(got.Rules) != 1 || got.Rules[0].Name != "r" {
		t.Errorf("expected 1 rule named 'r', got %+v", got.Rules)
	}
}

// TestParseKindMismatchErrors confirms that a known config field with
// the wrong .reg type is a hard parse error rather than silently
// decoding to the zero value. The first failure reported wins, so the
// test asserts on substring rather than exact key.
func TestParseKindMismatchErrors(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantSubstr string
	}{
		{
			name: "string where dword expected",
			body: "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Vault]\r\n" +
				"\"Address\"=\"https://vault.example.com:8200\"\r\n" +
				"\"TLSSkipVerify\"=\"yes\"\r\n",
			wantSubstr: "TLSSkipVerify",
		},
		{
			name: "dword where string expected",
			body: "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Vault]\r\n" +
				"\"Address\"=dword:00000001\r\n",
			wantSubstr: "Address",
		},
		{
			name: "string where multi-string expected",
			body: "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Rules\\r]\r\n" +
				"\"VaultKey\"=\"r\"\r\n" +
				"\"TargetPath\"=\"/tmp/r\"\r\n" +
				"\"TargetFormat\"=\"text\"\r\n" +
				"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Rules\\r\\OAuth]\r\n" +
				"\"Provider\"=\"github\"\r\n" +
				"\"Scopes\"=\"repo\"\r\n",
			wantSubstr: "Scopes",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			full := "Windows Registry Editor Version 5.00\r\n\r\n" + tc.body
			_, err := Parse([]byte(full))
			if err == nil {
				t.Fatalf("expected kind-mismatch error")
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error %q should mention %q", err.Error(), tc.wantSubstr)
			}
			if !strings.Contains(err.Error(), "unexpected type") {
				t.Errorf("error should describe a kind mismatch; got %q", err.Error())
			}
		})
	}
}

// TestParseCaseInsensitivePaths confirms registry key paths are
// compared case-insensitively. Windows registry treats key paths as
// case-insensitive, so a hand-written .reg using non-canonical case
// (e.g. "Software" instead of "SOFTWARE", or "vault" instead of
// "Vault") must still produce a complete config rather than silently
// dropping the values.
func TestParseCaseInsensitivePaths(t *testing.T) {
	src := "Windows Registry Editor Version 5.00\r\n\r\n" +
		// Lower-case Software, mixed-case dotvault, lowercase vault
		"[HKEY_LOCAL_MACHINE\\Software\\Policies\\goodtune\\DotVault\\vault]\r\n" +
		"\"Address\"=\"https://vault.example.com:8200\"\r\n" +
		// Lowercase rules + oauth under it.
		"[hkey_local_machine\\SOFTWARE\\Policies\\goodtune\\dotvault\\RULES\\gh]\r\n" +
		"\"VaultKey\"=\"gh\"\r\n" +
		"\"TargetPath\"=\"/tmp/gh\"\r\n" +
		"\"TargetFormat\"=\"text\"\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Rules\\gh\\oauth]\r\n" +
		"\"Provider\"=\"github\"\r\n"

	got, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse should accept case-folded paths: %v", err)
	}
	if got.Vault.Address != "https://vault.example.com:8200" {
		t.Errorf("Vault.Address lost across case-folded prefix; got %q", got.Vault.Address)
	}
	if len(got.Rules) != 1 || got.Rules[0].Name != "gh" {
		t.Fatalf("expected rule 'gh', got %+v", got.Rules)
	}
	if got.Rules[0].OAuth == nil || got.Rules[0].OAuth.Provider != "github" {
		t.Errorf("OAuth child key lost across case-folded segment; got %+v", got.Rules[0].OAuth)
	}
}

// TestParseRejectsUnsupportedSettingType refuses to silently drop an
// enrolment Settings value whose .reg type isn't REG_SZ or
// REG_MULTI_SZ. regfile.Generate refuses to emit those types in the
// first place, so encountering one on read indicates either a
// hand-edited file or an export from a different tool — losing the
// value would silently degrade the config without warning.
func TestParseRejectsUnsupportedSettingType(t *testing.T) {
	src := "Windows Registry Editor Version 5.00\r\n\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Enrolments\\gh]\r\n" +
		"\"Engine\"=\"github\"\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Enrolments\\gh\\Settings]\r\n" +
		"\"port\"=dword:00000016\r\n"
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatalf("expected error for REG_DWORD enrolment setting")
	}
	if !strings.Contains(err.Error(), "port") || !strings.Contains(err.Error(), "REG_DWORD") {
		t.Errorf("error should mention name and observed kind; got %v", err)
	}
}

// TestParseMultiSZPreservesMiddleEmptyElements confirms the parser
// surfaces every element of a REG_MULTI_SZ list, even when one of the
// middle entries is an empty string. The previous "stop at the first
// consecutive NUL" logic truncated `["a", "", "b"]` to `["a"]`, which
// disagreed with both the writer (utf16MultiStringBytes appends each
// element followed by a NUL plus a final list-terminator NUL) and
// Windows MultiSZ semantics (drop only the trailing empty terminator).
func TestParseMultiSZPreservesMiddleEmptyElements(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:     "gh",
				VaultKey: "gh",
				Target:   config.Target{Path: "~/x", Format: "yaml"},
				OAuth: &config.OAuthConfig{
					Provider: "github",
					Scopes:   []string{"a", "", "b"},
				},
			},
		},
	}
	text, err := GenerateText(cfg)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Rules[0].OAuth == nil {
		t.Fatalf("OAuth lost in round-trip")
	}
	want := []string{"a", "", "b"}
	if !reflect.DeepEqual(got.Rules[0].OAuth.Scopes, want) {
		t.Errorf("Scopes round-trip mismatch:\ngot:  %#v\nwant: %#v", got.Rules[0].OAuth.Scopes, want)
	}
}

// TestParseRejectsUnterminatedMultiSZ guards against a corrupted
// REG_MULTI_SZ blob whose payload doesn't end in a NUL terminator.
// Without the explicit check the function would silently emit an
// empty list and drop the truncated final segment without surfacing
// any error, which would make data loss invisible.
func TestParseRejectsUnterminatedMultiSZ(t *testing.T) {
	// hex(7) for "ab" without the trailing NUL terminator pair.
	bad := "Windows Registry Editor Version 5.00\r\n\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Rules\\r]\r\n" +
		"\"VaultKey\"=\"r\"\r\n" +
		"\"TargetPath\"=\"/tmp/r\"\r\n" +
		"\"TargetFormat\"=\"text\"\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Rules\\r\\OAuth]\r\n" +
		"\"Provider\"=\"github\"\r\n" +
		// 61,00,62,00 = "ab" UTF-16LE, missing the trailing 00,00 pair.
		"\"Scopes\"=hex(7):61,00,62,00\r\n"
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatalf("expected error for unterminated REG_MULTI_SZ")
	}
	if !strings.Contains(err.Error(), "REG_MULTI_SZ") || !strings.Contains(err.Error(), "terminator") {
		t.Errorf("error should describe the missing terminator; got %v", err)
	}
}

// TestParseRejectsMalformedHex catches user-edited hex blobs that become
// unparseable, so a corrupt .reg surfaces a clear error rather than
// silently producing partial config.
func TestParseRejectsMalformedHex(t *testing.T) {
	bad := "Windows Registry Editor Version 5.00\r\n\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Rules\\r]\r\n" +
		"\"TargetTemplate\"=hex(1):zz,zz\r\n"
	if _, err := Parse([]byte(bad)); err == nil {
		t.Errorf("expected error for malformed hex bytes")
	}
}
