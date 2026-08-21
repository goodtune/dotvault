package config

import (
	"strings"
	"testing"
)

func deleteNullsYAML(format string) string {
	return `
vault:
  address: "https://vault.example.com:8200"

rules:
  - name: app
    vault_key: "app"
    target:
      path: "~/.config/app/config"
      format: ` + format + `
      delete_nulls: true
      template: |
        {"token": "{{ .token }}", "KEY_I_USED_TO_FILL": null}
`
}

// TestLoadDeleteNullsAcceptedForNullableFormats pins the two formats whose
// syntax has a null literal a template can actually render.
func TestLoadDeleteNullsAcceptedForNullableFormats(t *testing.T) {
	for _, format := range []string{"json", "yaml"} {
		t.Run(format, func(t *testing.T) {
			path := writeTemp(t, deleteNullsYAML(format))
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !cfg.Rules[0].Target.DeleteNulls {
				t.Error("delete_nulls did not survive Load")
			}
		})
	}
}

// TestLoadDeleteNullsRejectedForNullLessFormats is the load-bearing half of
// the validation: silently accepting the flag on a format that cannot carry
// a null would leave an operator believing a retired credential had been
// deleted while it sat in the file untouched.
func TestLoadDeleteNullsRejectedForNullLessFormats(t *testing.T) {
	for _, format := range []string{"ini", "toml", "text", "netrc", "ssh_config"} {
		t.Run(format, func(t *testing.T) {
			path := writeTemp(t, deleteNullsYAML(format))
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error for delete_nulls with format %q", format)
			}
			if !strings.Contains(err.Error(), "delete_nulls") {
				t.Errorf("error should name the offending field, got: %v", err)
			}
		})
	}
}

// TestLoadDeleteNullsDefaultsFalse pins the default. delete_nulls must be
// something an operator opts into per rule, never behaviour a rule inherits.
func TestLoadDeleteNullsDefaultsFalse(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"

rules:
  - name: app
    vault_key: "app"
    target:
      path: "~/.config/app/config.json"
      format: json
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Rules[0].Target.DeleteNulls {
		t.Error("delete_nulls defaulted to true")
	}
}
