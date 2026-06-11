package regfile

import (
	"reflect"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// TestRemoteConfigRoundTrip confirms the full remote_config block — scalars
// and the Headers map — survives a GenerateText -> Parse cycle.
func TestRemoteConfigRoundTrip(t *testing.T) {
	src := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		RemoteConfig: config.RemoteConfig{
			URL:                "https://dotvault-config.example.com/v1/config",
			RawRefreshInterval: "10m",
			CACert:             `C:\ProgramData\dotvault\corp-ca.pem`,
			Headers: map[string]string{
				"X-Dotvault-Env":  "production",
				"X-Dotvault-Site": "sydney",
			},
		},
		Rules: []config.Rule{
			{
				Name:     "minimal",
				VaultKey: "minimal",
				Target:   config.Target{Path: "~/.dotvault/minimal", Format: "text"},
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

	if !reflect.DeepEqual(got.RemoteConfig, src.RemoteConfig) {
		t.Errorf("RemoteConfig mismatch:\ngot:  %+v\nwant: %+v", got.RemoteConfig, src.RemoteConfig)
	}
}

// TestRemoteConfigHeadersEmittedOnExport verifies the renderer writes the
// dimension headers under a RemoteConfig\Headers subkey with the
// delete-before-recreate stanza so removals clear on re-import.
func TestRemoteConfigHeadersEmittedOnExport(t *testing.T) {
	src := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		RemoteConfig: config.RemoteConfig{
			URL:     "https://dotvault-config.example.com/v1/config",
			Headers: map[string]string{"X-Dotvault-Env": "production"},
		},
		Rules: []config.Rule{
			{
				Name:     "minimal",
				VaultKey: "minimal",
				Target:   config.Target{Path: "~/.dotvault/minimal", Format: "text"},
			},
		},
	}

	text, err := GenerateText(src)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	if !strings.Contains(text, `[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\RemoteConfig]`) {
		t.Errorf("rendered .reg missing RemoteConfig key:\n%s", text)
	}
	if !strings.Contains(text, `[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\RemoteConfig\Headers]`) {
		t.Errorf("rendered .reg missing Headers subkey:\n%s", text)
	}
	if !strings.Contains(text, `[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\RemoteConfig\Headers]`) {
		t.Errorf("rendered .reg missing Headers deletion stanza:\n%s", text)
	}

	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.RemoteConfig.Headers["X-Dotvault-Env"] != "production" {
		t.Errorf("Headers[X-Dotvault-Env] = %q after round-trip, want %q", got.RemoteConfig.Headers["X-Dotvault-Env"], "production")
	}
}

// TestRemoteConfigParsedWhenAuthored confirms hand-authored / GPO
// RemoteConfig values are read back, tolerating arbitrary segment case and
// preserving header-name case verbatim.
func TestRemoteConfigParsedWhenAuthored(t *testing.T) {
	const reg = "Windows Registry Editor Version 5.00\r\n\r\n" +
		`[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\remoteconfig]` + "\r\n" +
		`"URL"="https://dotvault-config.example.com/v1/config"` + "\r\n" +
		`"RefreshInterval"="15m"` + "\r\n\r\n" +
		`[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\remoteconfig\headers]` + "\r\n" +
		`"X-Dotvault-Env"="staging"` + "\r\n\r\n"

	got, err := Parse([]byte(reg))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.RemoteConfig.URL != "https://dotvault-config.example.com/v1/config" {
		t.Errorf("URL = %q", got.RemoteConfig.URL)
	}
	if got.RemoteConfig.RawRefreshInterval != "15m" {
		t.Errorf("RawRefreshInterval = %q", got.RemoteConfig.RawRefreshInterval)
	}
	want := map[string]string{"X-Dotvault-Env": "staging"}
	if !reflect.DeepEqual(got.RemoteConfig.Headers, want) {
		t.Errorf("Headers = %v, want %v", got.RemoteConfig.Headers, want)
	}
}

// TestRemoteConfigHeaderWrongTypeRejected confirms a non-REG_SZ header value
// is a hard parse error rather than silently dropped.
func TestRemoteConfigHeaderWrongTypeRejected(t *testing.T) {
	const reg = "Windows Registry Editor Version 5.00\r\n\r\n" +
		`[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\RemoteConfig\Headers]` + "\r\n" +
		`"X-Dotvault-Env"=dword:00000001` + "\r\n\r\n"

	if _, err := Parse([]byte(reg)); err == nil {
		t.Fatal("expected error for non-REG_SZ remote-config header value, got nil")
	}
}

// TestRemoteConfigAbsentRoundTrip confirms a config without the section
// round-trips as absent: the renderer emits an all-empty RemoteConfig key,
// the parser reads it back to the zero value, and the top-level `omitempty`
// keeps the re-emitted YAML free of a remote_config block.
func TestRemoteConfigAbsentRoundTrip(t *testing.T) {
	src := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:     "minimal",
				VaultKey: "minimal",
				Target:   config.Target{Path: "~/.dotvault/minimal", Format: "text"},
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
	if !reflect.DeepEqual(got.RemoteConfig, config.RemoteConfig{}) {
		t.Errorf("expected zero-value RemoteConfig, got %+v", got.RemoteConfig)
	}

	yamlBytes, err := MarshalYAML(got)
	if err != nil {
		t.Fatalf("MarshalYAML: %v", err)
	}
	if strings.Contains(string(yamlBytes), "remote_config:") {
		t.Errorf("absent remote_config should not appear in YAML:\n%s", yamlBytes)
	}
}

// TestRemoteConfigLoadsBackThroughYAML exercises the reg -> YAML emit path
// the CLI and web download endpoint use.
func TestRemoteConfigLoadsBackThroughYAML(t *testing.T) {
	src := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		RemoteConfig: config.RemoteConfig{
			URL:                "https://dotvault-config.example.com/v1/config",
			RawRefreshInterval: "30m",
		},
		Rules: []config.Rule{
			{
				Name:     "minimal",
				VaultKey: "minimal",
				Target:   config.Target{Path: "~/.dotvault/minimal", Format: "text"},
			},
		},
	}

	text, err := GenerateText(src)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	parsed, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	yamlBytes, err := MarshalYAML(parsed)
	if err != nil {
		t.Fatalf("MarshalYAML: %v", err)
	}
	if !strings.Contains(string(yamlBytes), "remote_config:") {
		t.Errorf("expected remote_config block in YAML output:\n%s", yamlBytes)
	}
	if !strings.Contains(string(yamlBytes), "refresh_interval: 30m") {
		t.Errorf("expected refresh_interval in YAML output:\n%s", yamlBytes)
	}
}
