package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestResolveSignal pins the per-signal layering: the shared observability
// fields are defaults, the signal block overrides field-by-field, and
// headers replace wholesale rather than merging (merging credential maps
// invites sending one backend's bearer token to the other).
func TestResolveSignal(t *testing.T) {
	shared := ObservabilityConfig{
		Enabled:  true,
		Endpoint: "shared:4317",
		Protocol: "grpc",
		Insecure: true,
		Headers:  map[string]string{"Authorization": "Bearer shared"},
	}

	cases := []struct {
		name string
		sig  ObservabilitySignalConfig
		want ResolvedSignal
	}{
		{
			name: "zero value inherits everything",
			sig:  ObservabilitySignalConfig{},
			want: ResolvedSignal{
				Enabled:  true,
				Endpoint: "shared:4317",
				Protocol: "grpc",
				Insecure: true,
				Headers:  map[string]string{"Authorization": "Bearer shared"},
			},
		},
		{
			name: "separate backend overrides endpoint, protocol, insecure, headers",
			sig: ObservabilitySignalConfig{
				Endpoint: "https://logs.vendor.example",
				Protocol: "http/protobuf",
				Insecure: boolPtr(false),
				Headers:  map[string]string{"X-Api-Key": "logs-key"},
			},
			want: ResolvedSignal{
				Enabled:  true,
				Endpoint: "https://logs.vendor.example",
				Protocol: "http/protobuf",
				Insecure: false,
				Headers:  map[string]string{"X-Api-Key": "logs-key"},
			},
		},
		{
			name: "explicit empty headers map suppresses the shared credentials",
			sig:  ObservabilitySignalConfig{Headers: map[string]string{}},
			want: ResolvedSignal{
				Enabled:  true,
				Endpoint: "shared:4317",
				Protocol: "grpc",
				Insecure: true,
				Headers:  map[string]string{},
			},
		},
		{
			name: "signal disabled under enabled master",
			sig:  ObservabilitySignalConfig{Enabled: boolPtr(false)},
			want: ResolvedSignal{
				Enabled:  false,
				Endpoint: "shared:4317",
				Protocol: "grpc",
				Insecure: true,
				Headers:  map[string]string{"Authorization": "Bearer shared"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shared.ResolveSignal(tc.sig)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ResolveSignal:\ngot:  %+v\nwant: %+v", got, tc.want)
			}
		})
	}

	t.Run("master switch off wins over per-signal true", func(t *testing.T) {
		// The top-level flag stays the master switch; a signal block can
		// select within an enabled subsystem but never resurrect a
		// disabled one — otherwise "observability.enabled: false" would
		// stop meaning off.
		off := shared
		off.Enabled = false
		got := off.ResolveSignal(ObservabilitySignalConfig{Enabled: boolPtr(true)})
		if got.Enabled {
			t.Error("signal enabled=true must not override observability.enabled=false")
		}
	})
}

// TestDeprecatedSharedFields pins the stage-one deprecation query: exactly
// the four shared exporter fields count, detected by presence (insecure only
// when true — the shared field is a plain bool, so an explicit false is
// indistinguishable from unset), and per-signal configuration never trips
// it — that is the migration target, not the deprecated surface.
func TestDeprecatedSharedFields(t *testing.T) {
	cases := []struct {
		name string
		obs  ObservabilityConfig
		want []string
	}{
		{
			name: "zero value has nothing deprecated",
			obs:  ObservabilityConfig{Enabled: true},
			want: nil,
		},
		{
			name: "all four shared exporter fields",
			obs: ObservabilityConfig{
				Enabled:  true,
				Endpoint: "shared:4317",
				Protocol: "grpc",
				Insecure: true,
				Headers:  map[string]string{"Authorization": "Bearer x"},
			},
			want: []string{
				"observability.endpoint",
				"observability.protocol",
				"observability.insecure",
				"observability.headers",
			},
		},
		{
			name: "per-signal-only config is the migration target, not deprecated",
			obs: ObservabilityConfig{
				Enabled: true,
				Metrics: ObservabilitySignalConfig{
					Endpoint: "metrics:4317",
					Protocol: "grpc",
					Insecure: boolPtr(true),
					Headers:  map[string]string{"X-Key": "m"},
				},
				Logs: ObservabilitySignalConfig{
					Endpoint: "https://logs.vendor.example",
					Protocol: "http/protobuf",
				},
			},
			want: nil,
		},
		{
			name: "export_interval and enabled are not part of the deprecation",
			obs:  ObservabilityConfig{Enabled: true, RawInterval: "30s", ExportInterval: 30 * time.Second},
			want: nil,
		},
		{
			name: "empty shared headers map is not a use",
			obs:  ObservabilityConfig{Enabled: true, Headers: map[string]string{}},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.obs.DeprecatedSharedFields()
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("DeprecatedSharedFields = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestValidateObservabilitySignals covers the new validation surface: bad
// per-signal protocols are named by their exact field, header hygiene
// applies to the per-signal maps, and enabling the master switch with both
// signals explicitly off is rejected as the contradiction it is.
func TestValidateObservabilitySignals(t *testing.T) {
	base := func() *Config {
		return &Config{
			Vault: VaultConfig{Address: "https://vault.example.com:8200"},
			Rules: []Rule{{Name: "r", VaultKey: "r", Target: Target{Path: "~/x", Format: "text"}}},
		}
	}

	t.Run("bad per-signal protocol names the field", func(t *testing.T) {
		c := base()
		c.Observability = ObservabilityConfig{
			Enabled: true,
			Logs:    ObservabilitySignalConfig{Protocol: "carrier-pigeon"},
		}
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "observability.logs.protocol") {
			t.Errorf("err = %v, want a message naming observability.logs.protocol", err)
		}
	})

	t.Run("both signals off under enabled master is rejected", func(t *testing.T) {
		c := base()
		c.Observability = ObservabilityConfig{
			Enabled: true,
			Metrics: ObservabilitySignalConfig{Enabled: boolPtr(false)},
			Logs:    ObservabilitySignalConfig{Enabled: boolPtr(false)},
		}
		if err := c.Validate(); err == nil {
			t.Error("want an error for enabled master with both signals disabled")
		}
	})

	t.Run("per-signal header hygiene", func(t *testing.T) {
		c := base()
		c.Observability = ObservabilityConfig{
			Enabled: true,
			Metrics: ObservabilitySignalConfig{Headers: map[string]string{"Bad\r\nKey": "v"}},
		}
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "observability.metrics.headers") {
			t.Errorf("err = %v, want a message naming observability.metrics.headers", err)
		}
	})

	t.Run("one signal off is fine", func(t *testing.T) {
		c := base()
		c.Observability = ObservabilityConfig{
			Enabled: true,
			Logs:    ObservabilitySignalConfig{Enabled: boolPtr(false)},
		}
		if err := c.Validate(); err != nil {
			t.Errorf("Validate: %v", err)
		}
	})
}
