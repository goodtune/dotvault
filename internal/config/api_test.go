package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAPISocketPath(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1234")

	t.Run("disabled yields no path", func(t *testing.T) {
		c := &Config{API: APIConfig{Unix: APIUnixConfig{Path: "/tmp/api.sock"}}}
		got, err := c.APISocketPath()
		if err != nil {
			t.Fatalf("APISocketPath: %v", err)
		}
		if got != "" {
			// A configured-but-disabled path must not be bound, or turning
			// the socket "off" would still leave it serving tokens.
			t.Errorf("path = %q, want empty when api.enabled is false", got)
		}
	})

	t.Run("enabled without path uses the runtime default", func(t *testing.T) {
		c := &Config{API: APIConfig{Enabled: true}}
		got, err := c.APISocketPath()
		if err != nil {
			t.Fatalf("APISocketPath: %v", err)
		}
		if want := "/run/user/1234/dotvault/api.sock"; got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
	})

	t.Run("explicit path wins", func(t *testing.T) {
		c := &Config{API: APIConfig{Enabled: true, Unix: APIUnixConfig{Path: "/tmp/custom.sock"}}}
		got, err := c.APISocketPath()
		if err != nil {
			t.Fatalf("APISocketPath: %v", err)
		}
		if got != "/tmp/custom.sock" {
			t.Errorf("path = %q, want /tmp/custom.sock", got)
		}
	})
}

// TestTokenBorrowSocketsOrder pins the ordering decision: the local API
// socket is tried before vault.token_socket because the SSH-forwarded peer is
// the one that disappears when the session drops, and a process that outlives
// its session must not depend on it.
func TestTokenBorrowSocketsOrder(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1234")

	cases := []struct {
		name string
		cfg  Config
		want []string
	}{
		{
			name: "both configured: local first",
			cfg: Config{
				API:   APIConfig{Enabled: true, Unix: APIUnixConfig{Path: "/run/dotvault/api.sock"}},
				Vault: VaultConfig{TokenSocket: "~/.ssh/dotvault.sock"},
			},
			want: []string{"/run/dotvault/api.sock", "~/.ssh/dotvault.sock"},
		},
		{
			name: "api enabled without a path contributes the default",
			cfg:  Config{API: APIConfig{Enabled: true}},
			want: []string{"/run/user/1234/dotvault/api.sock"},
		},
		{
			name: "api disabled leaves only the peer socket",
			cfg:  Config{Vault: VaultConfig{TokenSocket: "~/.ssh/dotvault.sock"}},
			want: []string{"~/.ssh/dotvault.sock"},
		},
		{
			name: "neither configured",
			cfg:  Config{},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.TokenBorrowSockets()
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("TokenBorrowSockets() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidateAPIPath(t *testing.T) {
	cases := []struct {
		path    string
		wantErr bool
	}{
		{"", false},
		{"/run/user/1000/dotvault/api.sock", false},
		{"~/.dotvault/api.sock", false},
		// Relative paths resolve against the process's working directory, so
		// the daemon and a client started elsewhere would disagree about
		// where the socket is — reject rather than silently diverge.
		{"api.sock", true},
		{"./run/api.sock", true},
	}
	for _, tc := range cases {
		c := &Config{API: APIConfig{Unix: APIUnixConfig{Path: tc.path}}}
		err := c.validateAPI()
		if tc.wantErr && err == nil {
			t.Errorf("validateAPI(%q) = nil, want error", tc.path)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("validateAPI(%q) = %v, want nil", tc.path, err)
		}
	}
}

// TestAPISectionRoundTripsThroughYAML confirms the section survives the
// documented YAML shape, including the nesting that leaves room for a future
// windows: block.
func TestAPISectionRoundTripsThroughYAML(t *testing.T) {
	yamlSrc := `
vault:
  address: https://vault.example.com:8200
api:
  enabled: true
  unix:
    path: /run/user/1000/dotvault/api.sock
rules:
  - name: gh
    vault_key: gh
    target:
      path: ~/.config/gh/hosts.yml
      format: yaml
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yamlSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.API.Enabled {
		t.Errorf("API.Enabled = false, want true")
	}
	if want := "/run/user/1000/dotvault/api.sock"; cfg.API.Unix.Path != want {
		t.Errorf("API.Unix.Path = %q, want %q", cfg.API.Unix.Path, want)
	}
}
