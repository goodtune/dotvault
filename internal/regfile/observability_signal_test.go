package regfile

import (
	"reflect"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
	"gopkg.in/yaml.v3"
)

// TestObservabilitySignalRoundTrip covers the per-signal override blocks
// through the .reg render → parse cycle: tri-state Enabled/Insecure, the
// separate-backend endpoint/protocol, and header maps — including the
// nil-vs-explicitly-empty distinction that key presence encodes.
func TestObservabilitySignalRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		obs  config.ObservabilityConfig
	}{
		{
			name: "separate backends per signal",
			obs: config.ObservabilityConfig{
				Enabled:  true,
				Endpoint: "shared:4317",
				Protocol: "grpc",
				Headers:  map[string]string{"Authorization": "Bearer shared"},
				Metrics: config.ObservabilitySignalConfig{
					Endpoint:    "https://metrics.vendor.example",
					Protocol:    "http/protobuf",
					Insecure:    boolPtr(false),
					Headers:     map[string]string{"X-Metrics-Key": "m"},
					Temporality: "delta",
				},
				Logs: config.ObservabilitySignalConfig{
					Enabled:  boolPtr(false),
					Endpoint: "logs.vendor.example:4317",
				},
			},
		},
		{
			name: "zero-value signals inherit (nil tri-states, nil headers)",
			obs: config.ObservabilityConfig{
				Enabled:  true,
				Endpoint: "shared:4317",
			},
		},
		{
			name: "explicitly empty signal headers survive as empty, not nil",
			obs: config.ObservabilityConfig{
				Enabled: true,
				Headers: map[string]string{"Authorization": "Bearer shared"},
				Logs: config.ObservabilitySignalConfig{
					Headers: map[string]string{},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := validBaseConfig()
			src.Observability = tc.obs

			for _, enc := range []struct {
				name     string
				generate func() ([]byte, error)
			}{
				{"text", func() ([]byte, error) {
					text, err := GenerateText(src)
					return []byte(text), err
				}},
				{"utf16", func() ([]byte, error) { return Generate(src) }},
			} {
				data, err := enc.generate()
				if err != nil {
					t.Fatalf("%s generate: %v", enc.name, err)
				}
				got, err := Parse(data)
				if err != nil {
					t.Fatalf("%s parse: %v", enc.name, err)
				}
				if !reflect.DeepEqual(got.Observability, src.Observability) {
					t.Errorf("%s Observability mismatch:\ngot:  %+v\nwant: %+v", enc.name, got.Observability, src.Observability)
				}
			}
		})
	}
}

// TestObservabilitySignalEmptyHeadersIsNotInherit pins WHY key presence
// matters: an operator who wrote `logs: {headers: {}}` excluded the shared
// bearer token from the log backend, and a round-trip that collapsed the
// empty map to nil would silently re-attach those credentials.
func TestObservabilitySignalEmptyHeadersIsNotInherit(t *testing.T) {
	src := validBaseConfig()
	src.Observability = config.ObservabilityConfig{
		Enabled: true,
		Headers: map[string]string{"Authorization": "Bearer shared-secret"},
		Logs:    config.ObservabilitySignalConfig{Headers: map[string]string{}},
	}

	text, err := GenerateText(src)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}

	if got.Observability.Logs.Headers == nil {
		t.Fatal("logs.headers collapsed to nil across the round-trip; the shared credentials would silently re-attach to the log backend")
	}
	resolved := got.Observability.LogsSignal()
	if len(resolved.Headers) != 0 {
		t.Errorf("resolved log headers = %v, want none", resolved.Headers)
	}
	// And the metrics signal (nil headers, inherit) still gets the shared map.
	if got.Observability.Metrics.Headers != nil {
		t.Errorf("metrics.headers = %v, want nil (inherit)", got.Observability.Metrics.Headers)
	}
}

// TestObservabilitySignalCaseInsensitiveKeys confirms a hand-authored .reg
// using lowercase segment names still lands in the right fields — registry
// paths are case-insensitive, and the parser folds the fixed positions.
func TestObservabilitySignalCaseInsensitiveKeys(t *testing.T) {
	src := validBaseConfig()
	src.Observability = config.ObservabilityConfig{
		Enabled: true,
		Metrics: config.ObservabilitySignalConfig{
			Endpoint: "metrics:4317",
			Headers:  map[string]string{"K": "v"},
		},
	}
	text, err := GenerateText(src)
	if err != nil {
		t.Fatal(err)
	}
	lowered := strings.ReplaceAll(text, `\Observability\Metrics`, `\observability\metrics`)
	lowered = strings.ReplaceAll(lowered, `\metrics\Headers`, `\metrics\headers`)

	got, err := Parse([]byte(lowered))
	if err != nil {
		t.Fatal(err)
	}
	if got.Observability.Metrics.Endpoint != "metrics:4317" {
		t.Errorf("Metrics.Endpoint = %q after case-folded parse", got.Observability.Metrics.Endpoint)
	}
	if got.Observability.Metrics.Headers["K"] != "v" {
		t.Errorf("Metrics.Headers = %v after case-folded parse", got.Observability.Metrics.Headers)
	}
}

// TestObservabilitySignalYAMLRoundTrip is the regression test for the YAML
// emission blocker: MarshalYAML must preserve the Headers nil-vs-empty
// distinction, because collapsing nil ("inherit the shared credentials")
// into `headers: {}` ("send none") silently detaches auth from both signals
// after a single config-download or reg-export → re-import cycle.
func TestObservabilitySignalYAMLRoundTrip(t *testing.T) {
	src := validBaseConfig()
	src.Observability = config.ObservabilityConfig{
		Enabled:  true,
		Endpoint: "shared:4317",
		Headers:  map[string]string{"Authorization": "Bearer shared-secret"},
		// Metrics: temporality only — nil headers must round-trip as nil
		// (inherit), and the temporality string must survive MarshalYAML
		// (the custom marshaller's scalar mirror drops any field it
		// doesn't carry).
		Metrics: config.ObservabilitySignalConfig{Temporality: "delta"},
		Logs: config.ObservabilitySignalConfig{
			Enabled: boolPtr(false),
			Headers: map[string]string{}, // explicitly none, must stay non-nil empty
		},
	}

	data, err := MarshalYAML(src)
	if err != nil {
		t.Fatalf("MarshalYAML: %v", err)
	}

	var got config.Config
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("re-parse emitted YAML: %v", err)
	}

	if got.Observability.Metrics.Headers != nil {
		t.Errorf("metrics.headers = %v after YAML round-trip, want nil (inherit) — shared credentials were silently detached", got.Observability.Metrics.Headers)
	}
	if got.Observability.Metrics.Temporality != "delta" {
		t.Errorf("metrics.temporality = %q after YAML round-trip, want %q — MarshalYAML's scalar mirror dropped the field", got.Observability.Metrics.Temporality, "delta")
	}
	if got.Observability.Logs.Headers == nil {
		t.Error("logs.headers = nil after YAML round-trip, want non-nil empty (explicitly none)")
	}
	if got.Observability.Logs.Enabled == nil || *got.Observability.Logs.Enabled {
		t.Errorf("logs.enabled = %v after YAML round-trip, want explicit false", got.Observability.Logs.Enabled)
	}
	// The resolved outcome is what actually reaches the exporters: metrics
	// must still carry the shared credentials, logs must carry none.
	if got.Observability.MetricsSignal().Headers["Authorization"] != "Bearer shared-secret" {
		t.Error("resolved metrics headers lost the shared credentials across the YAML round-trip")
	}
	if len(got.Observability.LogsSignal().Headers) != 0 {
		t.Errorf("resolved logs headers = %v, want none", got.Observability.LogsSignal().Headers)
	}
}
