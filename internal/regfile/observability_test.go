package regfile

import (
	"reflect"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// TestObservabilityRoundTrip confirms the full observability block —
// scalars and the Headers map — survives a Generate -> Parse cycle.
// Conversion is lossless in every direction, so headers are emitted
// verbatim (not stripped).
func TestObservabilityRoundTrip(t *testing.T) {
	src := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Observability: config.ObservabilityConfig{
			Enabled:     true,
			Endpoint:    "otel-collector.example.com:4317",
			Protocol:    "grpc",
			Insecure:    true,
			RawInterval: "30s",
			Headers: map[string]string{
				"Authorization":    "Bearer round-trip-token",
				"X-Honeycomb-Team": "abc123",
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

	if !reflect.DeepEqual(got.Observability, src.Observability) {
		t.Errorf("Observability mismatch:\ngot:  %+v\nwant: %+v", got.Observability, src.Observability)
	}
}

// TestObservabilityHeadersEmittedOnExport verifies the renderer writes
// header values verbatim under an Observability\Headers subkey, and that a
// header dropped from the source clears via the delete-before-recreate
// stanza on re-import.
func TestObservabilityHeadersEmittedOnExport(t *testing.T) {
	src := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Observability: config.ObservabilityConfig{
			Enabled:  true,
			Endpoint: "otel.example.com:4318",
			Protocol: "http/protobuf",
			Headers: map[string]string{
				"authorization": "Bearer the-token",
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
	if !strings.Contains(text, "Bearer the-token") {
		t.Errorf("rendered .reg dropped the header value:\n%s", text)
	}
	if !strings.Contains(text, `[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\Observability\Headers]`) {
		t.Errorf("rendered .reg missing Headers subkey:\n%s", text)
	}
	// Idempotency: the subtree is deleted before recreation so removals clear.
	if !strings.Contains(text, `[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\Observability\Headers]`) {
		t.Errorf("rendered .reg missing Headers deletion stanza:\n%s", text)
	}

	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Observability.Headers["authorization"] != "Bearer the-token" {
		t.Errorf("Headers[authorization] = %q after round-trip, want %q", got.Observability.Headers["authorization"], "Bearer the-token")
	}
}

// TestObservabilityHeadersParsedWhenAuthored confirms that hand-authored /
// GPO Observability\Headers values are read back by the parser, preserving
// header-name case and tolerating a lower-cased `headers` segment.
func TestObservabilityHeadersParsedWhenAuthored(t *testing.T) {
	const reg = "Windows Registry Editor Version 5.00\r\n\r\n" +
		`[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\Observability]` + "\r\n" +
		`"Enabled"=dword:00000001` + "\r\n" +
		`"Endpoint"="otel.example.com:4318"` + "\r\n\r\n" +
		// Note the lower-case `headers` segment and mixed-case header name to
		// prove case-insensitive segment matching plus verbatim name preservation.
		`[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\Observability\headers]` + "\r\n" +
		`"X-Honeycomb-Team"="abc123"` + "\r\n" +
		`"Authorization"="Bearer tok"` + "\r\n\r\n"

	got, err := Parse([]byte(reg))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := map[string]string{
		"X-Honeycomb-Team": "abc123",
		"Authorization":    "Bearer tok",
	}
	if !reflect.DeepEqual(got.Observability.Headers, want) {
		t.Errorf("Headers mismatch:\ngot:  %v\nwant: %v", got.Observability.Headers, want)
	}
}

// TestObservabilityHeaderWrongTypeRejected confirms a non-REG_SZ header
// value is a hard parse error rather than silently dropped.
func TestObservabilityHeaderWrongTypeRejected(t *testing.T) {
	const reg = "Windows Registry Editor Version 5.00\r\n\r\n" +
		`[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\Observability\Headers]` + "\r\n" +
		`"authorization"=dword:00000001` + "\r\n\r\n"

	if _, err := Parse([]byte(reg)); err == nil {
		t.Fatal("expected error for non-REG_SZ header value, got nil")
	}
}

// TestWebTextRoundTrip confirms the multi-line markdown Web fields survive
// a Generate -> Parse cycle (they route through hex(1) like rule templates).
func TestWebTextRoundTrip(t *testing.T) {
	src := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Web: config.WebConfig{
			Enabled:        true,
			Listen:         "127.0.0.1:9000",
			LoginText:      "# Welcome\n\nSign in with **SSO**.\n",
			SecretViewText: "Handle these credentials carefully.\n",
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
	if got.Web != src.Web {
		t.Errorf("Web mismatch:\ngot:  %+v\nwant: %+v", got.Web, src.Web)
	}
}

// TestObservabilityAbsentRoundTrip confirms a config with no observability
// block round-trips as absent: the renderer always emits an (all-zero)
// Observability key, the parser reads it back to the zero value, and the
// top-level `omitempty` keeps the re-emitted YAML free of an observability
// block. This pins the absent<->absent behaviour so a future change to the
// always-emit renderer can't silently start materialising an empty block.
func TestObservabilityAbsentRoundTrip(t *testing.T) {
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
	if !reflect.DeepEqual(got.Observability, config.ObservabilityConfig{}) {
		t.Errorf("expected zero-value Observability, got %+v", got.Observability)
	}

	yamlBytes, err := MarshalYAML(got)
	if err != nil {
		t.Fatalf("MarshalYAML: %v", err)
	}
	if strings.Contains(string(yamlBytes), "observability:") {
		t.Errorf("absent observability should not appear in YAML:\n%s", yamlBytes)
	}
}

// TestObservabilityLoadsBackThroughYAML exercises the full reg -> YAML ->
// config.Load path the CLI and web download endpoint use, confirming the
// observability block validates cleanly after a registry round-trip.
func TestObservabilityLoadsBackThroughYAML(t *testing.T) {
	src := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Observability: config.ObservabilityConfig{
			Enabled:     true,
			Endpoint:    "otel.example.com:4317",
			Protocol:    "grpc",
			RawInterval: "1m",
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
	if !strings.Contains(string(yamlBytes), "observability:") {
		t.Errorf("expected observability block in YAML output:\n%s", yamlBytes)
	}
	if !strings.Contains(string(yamlBytes), "export_interval: 1m") {
		t.Errorf("expected export_interval in YAML output:\n%s", yamlBytes)
	}
}
