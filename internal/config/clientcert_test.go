package config

import (
	"strings"
	"testing"
	"time"
)

func clientCertBaseConfig() *Config {
	return &Config{
		Vault: VaultConfig{Address: "https://vault.example.com"},
		Rules: []Rule{{
			Name:     "gh",
			VaultKey: "gh",
			Target:   Target{Path: "~/.netrc", Format: "netrc"},
		}},
	}
}

func TestClientCertDefaults(t *testing.T) {
	cfg := clientCertBaseConfig()
	cfg.ClientCert = ClientCertConfig{Enabled: true, PKIRole: "client"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.ClientCert.TTL != 5*time.Minute {
		t.Errorf("TTL = %s, want 5m", cfg.ClientCert.TTL)
	}
	if cfg.ClientCert.RawTTL != "" {
		t.Errorf("RawTTL = %q, want it left empty so an export round-trips unset", cfg.ClientCert.RawTTL)
	}
	if got := cfg.ClientCertCommonName(); got != "{{.token_username}}" {
		t.Errorf("ClientCertCommonName() = %q", got)
	}
	if cfg.ClientCert.KeyType != "ec" {
		t.Errorf("KeyType = %q, want ec", cfg.ClientCert.KeyType)
	}
	if got := cfg.ClientCertPKIMount(); got != "pki" {
		t.Errorf("ClientCertPKIMount() = %q, want pki", got)
	}
	if got := cfg.ClientCertPKIRole(); got != "client" {
		t.Errorf("ClientCertPKIRole() = %q, want client", got)
	}
}

func TestClientCertInheritsMTLSPKI(t *testing.T) {
	for _, borrowOnly := range []bool{false, true} {
		cfg := clientCertBaseConfig()
		cfg.Vault.AuthMethod = "mtls+tpm"
		cfg.Vault.BorrowOnly = borrowOnly
		if borrowOnly {
			cfg.Vault.TokenSockets = SocketList{"~/.ssh/dotvault.sock"}
		}
		cfg.Vault.MTLS = MTLSConfig{CertRole: "dotvault", PKIMount: "pki-int", PKIRole: "workstation"}
		cfg.ClientCert = ClientCertConfig{Enabled: true}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("borrow_only=%v: Validate: %v", borrowOnly, err)
		}
		if got := cfg.ClientCertPKIMount(); got != "pki-int" {
			t.Errorf("borrow_only=%v: mount = %q, want pki-int", borrowOnly, got)
		}
		if got := cfg.ClientCertPKIRole(); got != "workstation" {
			t.Errorf("borrow_only=%v: role = %q, want workstation", borrowOnly, got)
		}
	}
}

func TestClientCertOwnValuesWin(t *testing.T) {
	cfg := clientCertBaseConfig()
	cfg.Vault.MTLS = MTLSConfig{PKIMount: "pki-int", PKIRole: "workstation"}
	cfg.ClientCert = ClientCertConfig{Enabled: true, PKIMount: "tools", PKIRole: "tool", CommonName: "{{.os_user}}"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.ClientCertPKIMount() != "tools" || cfg.ClientCertPKIRole() != "tool" || cfg.ClientCertCommonName() != "{{.os_user}}" {
		t.Errorf("own values not preferred: %q %q %q", cfg.ClientCertPKIMount(), cfg.ClientCertPKIRole(), cfg.ClientCertCommonName())
	}
}

func TestClientCertTTLFloor(t *testing.T) {
	cfg := clientCertBaseConfig()
	cfg.ClientCert = ClientCertConfig{Enabled: true, PKIRole: "client", RawTTL: "30s"}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "1m0s") {
		t.Fatalf("Validate() = %v, want an error naming the 1m0s floor", err)
	}

	cfg = clientCertBaseConfig()
	cfg.ClientCert = ClientCertConfig{Enabled: true, PKIRole: "client", RawTTL: "720h"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("no ceiling expected: %v", err)
	}
	if cfg.ClientCert.TTL != 720*time.Hour {
		t.Errorf("TTL = %s", cfg.ClientCert.TTL)
	}
}

func TestClientCertRejectsAmbiguousTemplateVars(t *testing.T) {
	for _, cn := range []string{
		"{{.user}}",
		"{{.vault_username}}",
		"prefix-{{.token_username}}-{{.user}}",
		"{{if .os_user}}{{.vault_username}}{{end}}",
		"{{with .os_user}}{{.user}}{{end}}",
		"{{range .x}}a{{end}}",
		"{{printf \"%s\" .user}}",
		"{{$.user}}",
	} {
		cfg := clientCertBaseConfig()
		cfg.ClientCert = ClientCertConfig{Enabled: true, PKIRole: "client", CommonName: cn}
		err := cfg.Validate()
		if err == nil {
			t.Errorf("common_name %q accepted", cn)
			continue
		}
		if !strings.Contains(err.Error(), "token_username") || !strings.Contains(err.Error(), "os_user") {
			t.Errorf("common_name %q: error %q must name token_username and os_user", cn, err)
		}
	}
}

func TestClientCertAcceptsKnownTemplateVars(t *testing.T) {
	for _, cn := range []string{
		"{{.token_username}}",
		"{{.os_user}}",
		"{{.token_username}}@{{.os_user}}",
		"{{if .token_username}}{{.token_username}}{{else}}{{.os_user}}{{end}}",
		"static-name",
	} {
		cfg := clientCertBaseConfig()
		cfg.ClientCert = ClientCertConfig{Enabled: true, PKIRole: "client", CommonName: cn}
		if err := cfg.Validate(); err != nil {
			t.Errorf("common_name %q rejected: %v", cn, err)
		}
	}
}

func TestClientCertRejectsUnparseableTemplate(t *testing.T) {
	cfg := clientCertBaseConfig()
	cfg.ClientCert = ClientCertConfig{Enabled: true, PKIRole: "client", CommonName: "{{.token_username"}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "client_cert.common_name") {
		t.Fatalf("Validate() = %v, want a client_cert.common_name parse error", err)
	}
}

func TestClientCertKeyParams(t *testing.T) {
	tests := []struct {
		name string
		cc   ClientCertConfig
		want string
	}{
		{"bad type", ClientCertConfig{KeyType: "dsa"}, `client_cert.key_type "dsa": must be ec or rsa`},
		{"bits on ec", ClientCertConfig{KeyBits: 2048}, "client_cert.key_bits is only valid with key_type rsa"},
		{"bad bits", ClientCertConfig{KeyType: "rsa", KeyBits: 1024}, "client_cert.key_bits 1024: must be one of"},
		{"good rsa", ClientCertConfig{KeyType: "rsa", KeyBits: 4096}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := clientCertBaseConfig()
			tc.cc.Enabled = true
			tc.cc.PKIRole = "client"
			cfg.ClientCert = tc.cc
			err := cfg.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestClientCertRoleRequired(t *testing.T) {
	cfg := clientCertBaseConfig()
	cfg.ClientCert = ClientCertConfig{Enabled: true}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "client_cert.pki_role is required (no vault.mtls.pki_role to inherit)") {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestClientCertHeldNeedsNoRole(t *testing.T) {
	cfg := clientCertBaseConfig()
	cfg.Vault.AuthMethod = "mtls"
	cfg.Vault.MTLS = MTLSConfig{CertRole: "dotvault", PKIRole: "workstation"}
	cfg.ClientCert = ClientCertConfig{Enabled: true}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !cfg.ClientCertHeld() {
		t.Error("ClientCertHeld() = false under plain mtls with the section enabled")
	}

	// Held means the role is not needed at all: only borrow_only lifts the
	// vault.mtls requirement, so exercise that route for "no role anywhere".
	cfg = clientCertBaseConfig()
	cfg.Vault.AuthMethod = "mtls"
	cfg.Vault.BorrowOnly = true
	cfg.Vault.TokenSockets = SocketList{"~/.ssh/dotvault.sock"}
	cfg.ClientCert = ClientCertConfig{Enabled: true}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("held, no role anywhere: %v", err)
	}
}

func TestClientCertHeldMatrix(t *testing.T) {
	for _, tc := range []struct {
		method  string
		enabled bool
		want    bool
	}{
		{"mtls", true, true},
		{"mtls", false, false},
		{"mtls+tpm", true, false},
		{"mtls+os", true, false},
		{"oidc", true, false},
		{"", true, false},
	} {
		c := &Config{Vault: VaultConfig{AuthMethod: tc.method}, ClientCert: ClientCertConfig{Enabled: tc.enabled}}
		if got := c.ClientCertHeld(); got != tc.want {
			t.Errorf("method %q enabled %v: ClientCertHeld() = %v, want %v", tc.method, tc.enabled, got, tc.want)
		}
	}
}

func TestClientCertValidatedWhenDisabled(t *testing.T) {
	cfg := clientCertBaseConfig()
	cfg.ClientCert = ClientCertConfig{Enabled: false, RawTTL: "10s"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("a bad ttl in a disabled section was accepted")
	}

	// And a disabled section with no role is fine: nothing will issue.
	cfg = clientCertBaseConfig()
	cfg.ClientCert = ClientCertConfig{Enabled: false}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled section with no role: %v", err)
	}
}

func TestClientCertRefusedInRemoteDocument(t *testing.T) {
	_, err := ParsePartial([]byte("client_cert:\n  enabled: true\n"))
	if err == nil || !strings.Contains(err.Error(), "client_cert") {
		t.Fatalf("ParsePartial() = %v, want a static-section error naming client_cert", err)
	}
}

func TestClientCertNotUserOverridable(t *testing.T) {
	_, err := ParseUserConfig([]byte("client_cert:\n  enabled: true\n"))
	if err == nil || !strings.Contains(err.Error(), "client_cert") {
		t.Fatalf("ParseUserConfig() = %v, want an error naming client_cert", err)
	}
}
