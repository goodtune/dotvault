package regfile

import (
	"reflect"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// TestMTLSRoundTrip confirms the vault.mtls block — scalars, the SealToPCRs
// tri-less bool, and the nested BYO paths — survives a Generate -> Parse cycle
// through the .reg surface.
func TestMTLSRoundTrip(t *testing.T) {
	src := &config.Config{
		Vault: config.VaultConfig{
			Address:    "https://vault.example.com:8200",
			AuthMethod: "mtls+tpm",
			MTLS: config.MTLSConfig{
				BootstrapMethod: "oidc",
				BootstrapMount:  "oidc-corp",
				CertMount:       "cert",
				CertRole:        "dotvault",
				PKIMount:        "pki",
				PKIRole:         "dotvault-client",
				KeyType:         "ec",
				CommonName:      "{{.user}}@corp",
				TTL:             "720h",
				ReissueBefore:   "168h",
				StorageDir:      "/var/lib/dotvault/mtls",
				SealToPCRs:      true,
				BYO: config.MTLSBYO{
					Cert: "/etc/dotvault/byo.crt",
					Key:  "/etc/dotvault/byo.key",
				},
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

	if !reflect.DeepEqual(got.Vault.MTLS, src.Vault.MTLS) {
		t.Errorf("MTLS mismatch:\ngot:  %+v\nwant: %+v", got.Vault.MTLS, src.Vault.MTLS)
	}
}

// TestMTLSAbsentRoundTrip confirms a config that does not use cert auth still
// round-trips with an empty MTLS block (every scalar emitted as "" so a
// re-import clears stale values).
func TestMTLSAbsentRoundTrip(t *testing.T) {
	src := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200", AuthMethod: "oidc"},
		Rules: []config.Rule{
			{Name: "minimal", VaultKey: "minimal", Target: config.Target{Path: "~/x", Format: "text"}},
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
	if !reflect.DeepEqual(got.Vault.MTLS, config.MTLSConfig{}) {
		t.Errorf("expected empty MTLS, got %+v", got.Vault.MTLS)
	}
}
