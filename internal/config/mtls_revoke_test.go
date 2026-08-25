package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMTLSRevokeSupersededDefault pins the tri-state's default.
//
// It must default to ON. Revocation is the half of rotation only the CA can
// perform, and a superseded certificate that is never revoked stays a valid
// credential for the rest of its TTL — so a deployment that never mentions the
// field should get the safe behaviour, not the convenient one. The field is a
// *bool precisely so "never mentioned" is distinguishable from "explicitly
// off"; a plain bool's zero value would silently mean off.
func TestMTLSRevokeSupersededDefault(t *testing.T) {
	yes, no := true, false
	tests := []struct {
		name string
		set  *bool
		want bool
	}{
		{"unset defaults to on", nil, true},
		{"explicit true", &yes, true},
		{"explicit false opts out", &no, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := MTLSConfig{RevokeSuperseded: tc.set}
			if got := m.RevokeSupersededEnabled(); got != tc.want {
				t.Errorf("RevokeSupersededEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMTLSRevokeSupersededFromYAML confirms the field parses from YAML, and
// that an absent field stays nil rather than decoding to false.
func TestMTLSRevokeSupersededFromYAML(t *testing.T) {
	write := func(t *testing.T, body string) *Config {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		return cfg
	}

	base := `vault:
  address: "https://vault.example.com"
  auth_method: "mtls"
  mtls:
    cert_role: dv
    pki_role: dv-client
%s
rules:
  - name: r
    vault_key: k
    target:
      path: /tmp/x
      format: json
`

	t.Run("absent stays nil", func(t *testing.T) {
		cfg := write(t, strings.Replace(base, "%s\n", "", 1))
		if cfg.Vault.MTLS.RevokeSuperseded != nil {
			t.Errorf("RevokeSuperseded = %v, want nil when the field is absent", *cfg.Vault.MTLS.RevokeSuperseded)
		}
		if !cfg.Vault.MTLS.RevokeSupersededEnabled() {
			t.Error("an unmentioned revoke_superseded must resolve to enabled")
		}
	})

	t.Run("explicit false opts out", func(t *testing.T) {
		cfg := write(t, strings.Replace(base, "%s", "    revoke_superseded: false", 1))
		if cfg.Vault.MTLS.RevokeSuperseded == nil || *cfg.Vault.MTLS.RevokeSuperseded {
			t.Fatalf("RevokeSuperseded = %v, want an explicit false", cfg.Vault.MTLS.RevokeSuperseded)
		}
		if cfg.Vault.MTLS.RevokeSupersededEnabled() {
			t.Error("revoke_superseded: false must resolve to disabled")
		}
	})
}
