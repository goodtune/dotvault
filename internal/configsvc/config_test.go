package configsvc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "configsvc.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
store:
  driver: sqlite
  dsn: ":memory:"
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9100" {
		t.Errorf("Listen = %q, want default 127.0.0.1:9100", cfg.Listen)
	}
	if cfg.Groups.Source != "static" {
		t.Errorf("Groups.Source = %q, want default static", cfg.Groups.Source)
	}
	if cfg.Groups.TTL != time.Minute {
		t.Errorf("Groups.TTL = %v, want default 1m", cfg.Groups.TTL)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"missing driver", "listen: :9100\n", "store.driver is required"},
		{"unknown driver", "store:\n  driver: postgres\n", "must be sqlite or vault"},
		{"sqlite without dsn", "store:\n  driver: sqlite\n", "store.dsn is required"},
		{"vault without address", "store:\n  driver: vault\n", "store.vault.address is required"},
		{"bad vault auth", "store:\n  driver: vault\n  vault:\n    address: https://v\n    auth: approle\n", "token or kubernetes"},
		{"kubernetes without role", "store:\n  driver: vault\n  vault:\n    address: https://v\n    auth: kubernetes\n", "kubernetes.role is required"},
		{"unknown groups source", "store: {driver: sqlite, dsn: ':memory:'}\ngroups: {source: oidc}\n", "static or ldap"},
		{"ldap without url", "store: {driver: sqlite, dsn: ':memory:'}\ngroups: {source: ldap}\n", "groups.ldap.url"},
		{"ldap without placeholder", "store: {driver: sqlite, dsn: ':memory:'}\ngroups:\n  source: ldap\n  ldap:\n    url: ldap://x\n    base_dn: dc=x\n    filter: '(member=alice)'\n", "%s"},
		{"bad ttl", "store: {driver: sqlite, dsn: ':memory:'}\ngroups: {ttl: soon}\n", "groups.ttl"},
		{"tls half configured", "store: {driver: sqlite, dsn: ':memory:'}\ntls: {cert_file: /a.pem}\n", "both cert_file and key_file"},
		{"unknown key", "store: {driver: sqlite, dsn: ':memory:'}\nlisten_addr: :9100\n", "listen_addr"},
		{"admin without any login path", "store: {driver: sqlite, dsn: ':memory:'}\nadmin: {enabled: true, group: admins}\n", "neither ldap login nor an mtls listener"},
		{"admin ldap without group", "store: {driver: sqlite, dsn: ':memory:'}\nadmin:\n  enabled: true\n  ldap: {url: ldap://x, user_dn_template: 'uid=%s,dc=x'}\n", "admin.group is required"},
		{"admin ldap without dn strategy", "store: {driver: sqlite, dsn: ':memory:'}\nadmin:\n  enabled: true\n  group: admins\n  ldap: {url: ldap://x}\n", "user_dn_template or user_search"},
		{"admin ldap both dn strategies", "store: {driver: sqlite, dsn: ':memory:'}\nadmin:\n  enabled: true\n  group: admins\n  ldap: {url: ldap://x, user_dn_template: 'uid=%s,dc=x', user_search_base_dn: dc=x, user_search_filter: '(uid=%s)'}\n", "mutually exclusive"},
		{"admin ldap template without placeholder", "store: {driver: sqlite, dsn: ':memory:'}\nadmin:\n  enabled: true\n  group: admins\n  ldap: {url: ldap://x, user_dn_template: 'uid=alice,dc=x'}\n", "%s"},
		{"admin mtls incomplete", "store: {driver: sqlite, dsn: ':memory:'}\nadmin:\n  enabled: true\n  mtls: {listen: ':9101'}\n", "ca_cert, cert_file, and key_file"},
		{"admin bad session ttl", "store: {driver: sqlite, dsn: ':memory:'}\nadmin:\n  enabled: true\n  session_ttl: never\n  mtls: {listen: ':9101', ca_cert: /a, cert_file: /b, key_file: /c}\n", "admin.session_ttl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadConfig(writeConfig(t, tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("LoadConfig error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfigDayTTL(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
store:
  driver: sqlite
  dsn: ":memory:"
groups:
  ttl: 1d
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Groups.TTL != 24*time.Hour {
		t.Errorf("Groups.TTL = %v, want 24h", cfg.Groups.TTL)
	}
}

func TestOpenStoreAndResolver(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
store:
  driver: sqlite
  dsn: ":memory:"
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	st, err := cfg.OpenStore(context.Background())
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer st.Close()
	resolver, err := cfg.OpenResolver(st)
	if err != nil {
		t.Fatalf("OpenResolver: %v", err)
	}
	groups, err := resolver.Groups(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("Groups: %v", err)
	}
	if len(groups) != 0 {
		t.Fatalf("Groups = %v, want empty for unknown user", groups)
	}
}
