//go:build windows

package config

import "testing"

// TestApplyRegistryLayerMTLSRevokeSuperseded pins the GPO half of the
// tri-state, mirroring TestApplyRegistryLayerAgentPutty.
//
// The registry is the third of the three surfaces a config field must
// round-trip through, and it is the one Linux CI can never execute — so
// without this the absent-versus-explicit-false distinction was verified for
// YAML and .reg only. Absent must leave the *bool nil (inherit the default-on),
// not pin it to false: a Windows fleet whose policy simply does not mention the
// value must keep revoking.
func TestApplyRegistryLayerMTLSRevokeSuperseded(t *testing.T) {
	tests := []struct {
		name  string
		dword *uint32
		want  *bool
	}{
		{"absent inherits the default", nil, nil},
		{"zero opts out", ptrDWORD(0), ptrBool(false)},
		{"one opts in", ptrDWORD(1), ptrBool(true)},
		{"any non-zero opts in", ptrDWORD(2), ptrBool(true)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			applyRegistryLayer(cfg, registryLayer{MTLSRevokeSuperseded: tc.dword})
			got := cfg.Vault.MTLS.RevokeSuperseded
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("RevokeSuperseded = %v, want nil (inherit)", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("RevokeSuperseded = nil, want %v", *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("RevokeSuperseded = %v, want %v", *got, *tc.want)
			}
			// The resolved meaning is what call sites actually consult.
			wantEnabled := tc.want == nil || *tc.want
			if cfg.Vault.MTLS.RevokeSupersededEnabled() != wantEnabled {
				t.Errorf("RevokeSupersededEnabled() = %v, want %v",
					cfg.Vault.MTLS.RevokeSupersededEnabled(), wantEnabled)
			}
		})
	}
}

func ptrDWORD(v uint32) *uint32 { return &v }
func ptrBool(v bool) *bool      { return &v }
