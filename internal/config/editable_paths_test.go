package config

import (
	"strings"
	"testing"
)

func TestValidateEditablePathsCanonicalises(t *testing.T) {
	entries := []string{"/personal/", "scratch/notes"}
	if err := validateEditablePaths(entries); err != nil {
		t.Fatalf("validateEditablePaths: %v", err)
	}
	// Rewritten in place so everything downstream — the policy, the UI, the
	// config download — sees one spelling of a given subtree.
	if entries[0] != "personal" || entries[1] != "scratch/notes" {
		t.Errorf("entries = %v, want [personal scratch/notes]", entries)
	}
}

// The key-space root is the one thing the section exists to keep out of
// reach, so an entry naming it is an error rather than something silently
// dropped — dropping it would leave an operator believing they had granted
// something they had not.
func TestValidateEditablePathsRefusesRoot(t *testing.T) {
	for _, raw := range []string{"", "/", "//"} {
		err := validateEditablePaths([]string{raw})
		if err == nil {
			t.Errorf("validateEditablePaths([%q]) = nil, want an error", raw)
			continue
		}
		if !strings.Contains(err.Error(), "key space root") {
			t.Errorf("validateEditablePaths([%q]) = %v, want it to name the root", raw, err)
		}
	}
}

func TestValidateEditablePathsRefusesTraversalAndDuplicates(t *testing.T) {
	if err := validateEditablePaths([]string{"personal/../gh"}); err == nil {
		t.Error("a traversal segment was accepted")
	}
	if err := validateEditablePaths([]string{"personal", "/personal"}); err == nil {
		t.Error("a duplicate (after canonicalisation) was accepted")
	}
}

// Checked whether or not the web UI is enabled, matching the
// api.unix.path / fuse.mountpoint convention.
func TestEditablePathsValidatedWhileWebDisabled(t *testing.T) {
	cfg := minimalConfigForTest()
	cfg.Web.Enabled = false
	cfg.Web.EditablePaths = []string{".."}
	if err := cfg.validate(); err == nil {
		t.Error("a bad editable path was accepted with web disabled")
	}
}

func TestEditablePathsAcceptedAndCanonicalisedByValidate(t *testing.T) {
	cfg := minimalConfigForTest()
	cfg.Web.Enabled = true
	cfg.Web.Listen = "127.0.0.1:9000"
	cfg.Web.EditablePaths = []string{"personal/"}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := cfg.Web.EditablePaths[0]; got != "personal" {
		t.Errorf("EditablePaths[0] = %q, want %q", got, "personal")
	}
}

// minimalConfigForTest returns the smallest config that passes validate(), so
// a test can isolate the field it is exercising.
func minimalConfigForTest() *Config {
	return &Config{
		Vault: VaultConfig{Address: "https://vault.example"},
		Rules: []Rule{{
			Name:     "r",
			VaultKey: "gh",
			Target:   Target{Path: "~/.config/gh", Format: "yaml"},
		}},
	}
}
