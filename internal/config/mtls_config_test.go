package config

import (
	"strings"
	"testing"
	"time"
)

func baseConfigWithMTLS(method string, m MTLSConfig) *Config {
	return &Config{
		Vault: VaultConfig{Address: "https://vault.example.com", AuthMethod: method, MTLS: m},
		Rules: []Rule{{Name: "r", VaultKey: "k", Target: Target{Path: "/tmp/x", Format: "text"}}},
	}
}

func TestMTLSValidateIgnoredForNonCertMethods(t *testing.T) {
	// A non-cert method must not require any mtls fields.
	c := baseConfigWithMTLS("oidc", MTLSConfig{})
	if err := c.validate(); err != nil {
		t.Errorf("oidc should validate without mtls config: %v", err)
	}
}

func TestMTLSValidateDefaults(t *testing.T) {
	c := baseConfigWithMTLS("mtls", MTLSConfig{CertRole: "dv", PKIRole: "dv-client"})
	if err := c.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	m := c.Vault.MTLS
	if m.BootstrapMethod != "oidc" {
		t.Errorf("BootstrapMethod default = %q, want oidc", m.BootstrapMethod)
	}
	if m.CertMount != DefaultCertMount {
		t.Errorf("CertMount default = %q, want %q", m.CertMount, DefaultCertMount)
	}
	if m.PKIMount != DefaultPKIMount {
		t.Errorf("PKIMount default = %q", m.PKIMount)
	}
	if m.KeyType != "ec" {
		t.Errorf("KeyType default = %q, want ec", m.KeyType)
	}
	if m.CommonName != DefaultMTLSCommonName {
		t.Errorf("CommonName default = %q", m.CommonName)
	}
	if m.ReissueBeforeDur != DefaultReissueBefore {
		t.Errorf("ReissueBeforeDur default = %v, want %v", m.ReissueBeforeDur, DefaultReissueBefore)
	}
}

func TestMTLSValidateRequiresCertRole(t *testing.T) {
	c := baseConfigWithMTLS("mtls", MTLSConfig{PKIRole: "dv-client"})
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "cert_role") {
		t.Errorf("want cert_role error, got %v", err)
	}
}

func TestMTLSValidateRequiresPKIRoleUnlessBYO(t *testing.T) {
	c := baseConfigWithMTLS("mtls", MTLSConfig{CertRole: "dv"})
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "pki_role") {
		t.Errorf("want pki_role error, got %v", err)
	}

	// With a BYO cert, pki_role is not required.
	c = baseConfigWithMTLS("mtls", MTLSConfig{
		CertRole: "dv",
		BYO:      MTLSBYO{Cert: "/c.pem", Key: "/k.pem"},
	})
	if err := c.validate(); err != nil {
		t.Errorf("byo config should validate without pki_role: %v", err)
	}
}

func TestMTLSValidateBYOBothOrNeither(t *testing.T) {
	c := baseConfigWithMTLS("mtls", MTLSConfig{CertRole: "dv", PKIRole: "p", BYO: MTLSBYO{Cert: "/c.pem"}})
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "set together") {
		t.Errorf("want both-or-neither error, got %v", err)
	}
}

func TestMTLSValidateBootstrapMethod(t *testing.T) {
	c := baseConfigWithMTLS("mtls", MTLSConfig{CertRole: "dv", PKIRole: "p", BootstrapMethod: "saml"})
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "bootstrap_method") {
		t.Errorf("want bootstrap_method error, got %v", err)
	}
}

func TestMTLSValidateRSARejectedForTPM(t *testing.T) {
	c := baseConfigWithMTLS("mtls+tpm", MTLSConfig{CertRole: "dv", PKIRole: "p", KeyType: "rsa"})
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "EC-only") {
		t.Errorf("want EC-only rejection, got %v", err)
	}

	// RSA is fine for plain mtls.
	c = baseConfigWithMTLS("mtls", MTLSConfig{CertRole: "dv", PKIRole: "p", KeyType: "rsa"})
	if err := c.validate(); err != nil {
		t.Errorf("rsa should validate for plain mtls: %v", err)
	}
}

func TestMTLSValidateBadKeyType(t *testing.T) {
	c := baseConfigWithMTLS("mtls", MTLSConfig{CertRole: "dv", PKIRole: "p", KeyType: "dsa"})
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "key_type") {
		t.Errorf("want key_type error, got %v", err)
	}
}

func TestIsMTLSMethod(t *testing.T) {
	for method, want := range map[string]bool{
		"mtls":     true,
		"mtls+tpm": true,
		"mtls+os":  true,
		"oidc":     false,
		"ldap+tpm": false,
		"token":    false,
		"":         false,
	} {
		if got := IsMTLSMethod(method); got != want {
			t.Errorf("IsMTLSMethod(%q) = %v, want %v", method, got, want)
		}
	}
}

func TestMTLSOSDefaultsAndValidation(t *testing.T) {
	// mtls+os validates with cert_role + pki_role, defaults the TTL to 30d, and
	// accepts rsa (only mtls+tpm is EC-only).
	t.Run("defaults TTL to 30d and accepts rsa", func(t *testing.T) {
		c := baseConfigWithMTLS("mtls+os", MTLSConfig{CertRole: "dv", PKIRole: "p", KeyType: "rsa"})
		if err := c.validate(); err != nil {
			t.Fatalf("mtls+os should validate: %v", err)
		}
		if c.Vault.MTLS.TTL != DefaultMTLSOSTTL {
			t.Errorf("TTL default = %q, want %q", c.Vault.MTLS.TTL, DefaultMTLSOSTTL)
		}
	})

	// An explicit TTL is honoured, not overridden by the 30d default.
	t.Run("explicit TTL preserved", func(t *testing.T) {
		c := baseConfigWithMTLS("mtls+os", MTLSConfig{CertRole: "dv", PKIRole: "p", TTL: "12h"})
		if err := c.validate(); err != nil {
			t.Fatalf("validate: %v", err)
		}
		if c.Vault.MTLS.TTL != "12h" {
			t.Errorf("TTL = %q, want it preserved as 12h", c.Vault.MTLS.TTL)
		}
	})

	// BYO is rejected for mtls+os (the OS store cannot import an external key).
	t.Run("rejects BYO", func(t *testing.T) {
		c := baseConfigWithMTLS("mtls+os", MTLSConfig{
			CertRole: "dv", PKIRole: "p",
			BYO: MTLSBYO{Cert: "/c.pem", Key: "/k.pem"},
		})
		if err := c.validate(); err == nil || !strings.Contains(err.Error(), "mtls+os") {
			t.Errorf("want mtls+os BYO rejection, got %v", err)
		}
	})
}

func TestMTLSValidateReissueBefore(t *testing.T) {
	c := baseConfigWithMTLS("mtls", MTLSConfig{CertRole: "dv", PKIRole: "p", ReissueBefore: "3d"})
	if err := c.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.Vault.MTLS.ReissueBeforeDur != 72*time.Hour {
		t.Errorf("ReissueBeforeDur = %v, want 72h", c.Vault.MTLS.ReissueBeforeDur)
	}

	c = baseConfigWithMTLS("mtls", MTLSConfig{CertRole: "dv", PKIRole: "p", ReissueBefore: "-1h"})
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "must be positive") {
		t.Errorf("want positive error, got %v", err)
	}
}
