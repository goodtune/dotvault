package config

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSocketListUnmarshalScalar(t *testing.T) {
	var v struct {
		S SocketList `yaml:"token_socket"`
	}
	if err := yaml.Unmarshal([]byte("token_socket: ~/.ssh/dotvault.sock\n"), &v); err != nil {
		t.Fatal(err)
	}
	if want := (SocketList{"~/.ssh/dotvault.sock"}); !reflect.DeepEqual(v.S, want) {
		t.Errorf("got %v, want %v", v.S, want)
	}
}

func TestSocketListUnmarshalSequence(t *testing.T) {
	var v struct {
		S SocketList `yaml:"token_socket"`
	}
	in := "token_socket:\n  - ~/.ssh/dotvault.sock\n  - ~/.ssh/dotvault.*.sock\n"
	if err := yaml.Unmarshal([]byte(in), &v); err != nil {
		t.Fatal(err)
	}
	if want := (SocketList{"~/.ssh/dotvault.sock", "~/.ssh/dotvault.*.sock"}); !reflect.DeepEqual(v.S, want) {
		t.Errorf("got %v, want %v", v.S, want)
	}
}

// An empty scalar and an empty sequence both mean "explicitly disabled":
// non-nil and empty, distinguishable from an absent key (nil).
func TestSocketListUnmarshalEmptyForms(t *testing.T) {
	for _, in := range []string{"token_socket: \"\"\n", "token_socket: []\n"} {
		var v struct {
			S SocketList `yaml:"token_socket"`
		}
		if err := yaml.Unmarshal([]byte(in), &v); err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if v.S == nil || len(v.S) != 0 {
			t.Errorf("%q: got %#v, want non-nil empty", in, v.S)
		}
	}
	var absent struct {
		S SocketList `yaml:"token_socket"`
	}
	if err := yaml.Unmarshal([]byte("other: 1\n"), &absent); err != nil {
		t.Fatal(err)
	}
	if absent.S != nil {
		t.Errorf("absent key: got %#v, want nil", absent.S)
	}
}

func TestSocketListUnmarshalRejectsMapping(t *testing.T) {
	var v struct {
		S SocketList `yaml:"token_socket"`
	}
	if err := yaml.Unmarshal([]byte("token_socket: {a: b}\n"), &v); err == nil {
		t.Fatal("expected error for mapping")
	}
}

func TestValidateSocketPattern(t *testing.T) {
	cases := []struct {
		in      string
		wantErr string
	}{
		{"~/.ssh/dotvault.sock", ""},
		{"~/.ssh/dotvault.*.sock", ""},
		{"/run/user/1000/dotvault/api.sock", ""},
		{"/tmp/dotvault-?.sock", ""},
		{"", "must not be empty"},
		{"relative/dotvault.sock", "must be an absolute path"},
		{"~user/dotvault.sock", "must be an absolute path"},
		{"~/*/dotvault.sock", "only in the final path segment"},
		{"/tmp/*/dotvault.sock", "only in the final path segment"},
		{"/tmp/dotvault\x00.sock", "NUL"},
	}
	for _, c := range cases {
		err := ValidateSocketPattern(c.in)
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("%q: unexpected error %v", c.in, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%q: got %v, want error containing %q", c.in, err, c.wantErr)
		}
	}
}

func TestValidateRejectsBadTokenSocketEntry(t *testing.T) {
	cfg := minimalValidConfig()
	cfg.Vault.TokenSockets = SocketList{"relative.sock"}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "vault.token_socket") {
		t.Fatalf("got %v, want vault.token_socket validation error", err)
	}
}

func minimalValidConfig() *Config {
	return &Config{
		Vault: VaultConfig{Address: "http://127.0.0.1:8200", AuthMethod: "token"},
		Rules: []Rule{{Name: "r", VaultKey: "k", Target: Target{Path: "/tmp/x", Format: "text"}}},
	}
}
