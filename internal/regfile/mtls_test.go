package regfile

import (
	"reflect"
	"strconv"
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

// TestMTLSKeyBitsRoundTrip confirms vault.mtls.key_bits survives the .reg
// surface as a REG_DWORD.
//
// The existing TestMTLSRoundTrip uses key_type ec, where key_bits is invalid by
// config validation and so is always zero — a zero DWORD round-trips trivially
// even if the field were never emitted at all. This exercises the case that
// actually distinguishes a working implementation: an RSA config carrying a
// non-default modulus size, which is the whole reason the option exists (a
// Vault PKI role's key_bits is a minimum, so a 4096-bit role needs this set).
func TestMTLSKeyBitsRoundTrip(t *testing.T) {
	for _, bits := range []int{2048, 3072, 4096, 8192} {
		t.Run(strconv.Itoa(bits), func(t *testing.T) {
			src := &config.Config{
				Vault: config.VaultConfig{
					Address:    "https://vault.example.com:8200",
					AuthMethod: "mtls",
					MTLS: config.MTLSConfig{
						BootstrapMethod: "oidc",
						CertMount:       "cert",
						CertRole:        "dotvault",
						PKIMount:        "pki",
						PKIRole:         "dotvault-client",
						KeyType:         "rsa",
						KeyBits:         bits,
						CommonName:      "{{.user}}",
						ReissueBefore:   "168h",
					},
				},
				Rules: []config.Rule{
					{Name: "r", VaultKey: "k", Target: config.Target{Path: "~/x", Format: "text"}},
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
			if got.Vault.MTLS.KeyBits != bits {
				t.Errorf("KeyBits = %d, want %d", got.Vault.MTLS.KeyBits, bits)
			}
			if !reflect.DeepEqual(got.Vault.MTLS, src.Vault.MTLS) {
				t.Errorf("MTLS mismatch:\ngot:  %+v\nwant: %+v", got.Vault.MTLS, src.Vault.MTLS)
			}
		})
	}
}
