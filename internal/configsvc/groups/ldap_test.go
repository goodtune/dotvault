package groups

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewLDAPValidation(t *testing.T) {
	valid := LDAPConfig{
		URL:    "ldaps://ldap.example.com",
		BaseDN: "ou=groups,dc=example,dc=com",
		Filter: "(&(objectClass=groupOfNames)(member=uid=%s,ou=people,dc=example,dc=com))",
	}

	tests := []struct {
		name    string
		mutate  func(*LDAPConfig)
		wantErr string
	}{
		{"valid", func(c *LDAPConfig) {}, ""},
		{"missing url", func(c *LDAPConfig) { c.URL = "" }, "url is required"},
		{"bad scheme", func(c *LDAPConfig) { c.URL = "https://ldap.example.com" }, "scheme"},
		{"missing base_dn", func(c *LDAPConfig) { c.BaseDN = "" }, "base_dn"},
		{"filter without placeholder", func(c *LDAPConfig) { c.Filter = "(objectClass=groupOfNames)" }, "%s"},
		{"both password forms", func(c *LDAPConfig) { c.BindPassword = "x"; c.BindPasswordFile = "/run/secret" }, "mutually exclusive"},
		{"missing ca_cert file", func(c *LDAPConfig) { c.CACert = "/nonexistent/ca.pem" }, "ca_cert"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.mutate(&cfg)
			_, err := NewLDAP(cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("NewLDAP: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NewLDAP error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestSearchFilterEscapesUser(t *testing.T) {
	got := searchFilter("(member=uid=%s,ou=people)", "ali*ce)(uid=admin")
	if strings.Contains(got, "*") || strings.Contains(got, ")(") {
		t.Fatalf("filter metacharacters not escaped: %s", got)
	}
	if want := "(member=uid=ali\\2ace\\29\\28uid=admin,ou=people)"; got != want {
		t.Fatalf("searchFilter = %q, want %q", got, want)
	}
}

func TestLDAPDefaultAttribute(t *testing.T) {
	r, err := NewLDAP(LDAPConfig{
		URL:    "ldap://ldap.example.com",
		BaseDN: "dc=example,dc=com",
		Filter: "(member=%s)",
	})
	if err != nil {
		t.Fatalf("NewLDAP: %v", err)
	}
	if got := r.(*ldapResolver).cfg.Attribute; got != "cn" {
		t.Fatalf("default attribute = %q, want cn", got)
	}
}

func TestReadBindPassword(t *testing.T) {
	if got, err := ReadBindPassword("literal", ""); err != nil || got != "literal" {
		t.Fatalf("literal = %q, %v", got, err)
	}
	path := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(path, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadBindPassword("", path); err != nil || got != "from-file" {
		t.Fatalf("file = %q, %v (trailing newline must be trimmed)", got, err)
	}
	if _, err := ReadBindPassword("", filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("missing password file accepted")
	}
}
