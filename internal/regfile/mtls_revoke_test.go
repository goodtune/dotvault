package regfile

import (
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// TestMTLSRevokeSupersededRoundTrip pins the tri-state through the .reg
// surface. The registry is the Group Policy surface for the whole config, so a
// field that does not round-trip is a field a Windows fleet cannot set — and
// for a tri-state the absent case carries meaning of its own: emitting it
// unconditionally would freeze an unset default into an explicit value on the
// next import.
func TestMTLSRevokeSupersededRoundTrip(t *testing.T) {
	base := func(set *bool) *config.Config {
		return &config.Config{
			Vault: config.VaultConfig{
				Address:    "https://vault.example.com",
				AuthMethod: "mtls",
				MTLS: config.MTLSConfig{
					CertMount: "cert", CertRole: "dv",
					PKIMount: "pki", PKIRole: "dv-client",
					KeyType: "ec", CommonName: "{{.user}}",
					RevokeSuperseded: set,
				},
			},
			Rules: []config.Rule{{
				Name: "r", VaultKey: "k",
				Target: config.Target{Path: "/tmp/x", Format: "json"},
			}},
		}
	}

	yes, no := true, false
	tests := []struct {
		name    string
		set     *bool
		emitted bool
	}{
		{"unset is not emitted", nil, false},
		{"explicit true", &yes, true},
		{"explicit false", &no, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			text, err := GenerateText(base(tc.set))
			if err != nil {
				t.Fatalf("GenerateText: %v", err)
			}
			if got := strings.Contains(text, "RevokeSuperseded"); got != tc.emitted {
				t.Fatalf("emitted=%v, want %v:\n%s", got, tc.emitted, text)
			}

			back, err := Parse([]byte(text))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got := back.Vault.MTLS.RevokeSuperseded
			switch {
			case tc.set == nil && got != nil:
				t.Errorf("RevokeSuperseded = %v, want nil (inherit the default)", *got)
			case tc.set != nil && got == nil:
				t.Errorf("RevokeSuperseded = nil, want an explicit %v", *tc.set)
			case tc.set != nil && *got != *tc.set:
				t.Errorf("RevokeSuperseded = %v, want %v", *got, *tc.set)
			}
			// Whatever the wire form, the resolved meaning must survive.
			if want := base(tc.set).Vault.MTLS.RevokeSupersededEnabled(); back.Vault.MTLS.RevokeSupersededEnabled() != want {
				t.Errorf("RevokeSupersededEnabled() = %v, want %v", back.Vault.MTLS.RevokeSupersededEnabled(), want)
			}
		})
	}
}
