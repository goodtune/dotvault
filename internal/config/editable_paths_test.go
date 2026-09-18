package config

import (
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/kvpath"
)

func TestValidateEditablePathsCanonicalises(t *testing.T) {
	entries := []string{"/personal/", "scratch"}
	if err := validateEditablePaths(entries); err != nil {
		t.Fatalf("validateEditablePaths: %v", err)
	}
	// Rewritten in place so everything downstream — the policy, the UI, the
	// config download — sees one spelling of a given folder.
	if entries[0] != "personal" || entries[1] != "scratch" {
		t.Errorf("entries = %v, want [personal scratch]", entries)
	}
}

// The user's key space is one folder deep: an enrolment key is flat ("gh") or
// grouped exactly once ("databricks/prod", see validateEnrolmentKey), so
// "scratch/notes" names a *secret*, not a folder. Accepting it as a root would
// grant editing over a subtree that cannot exist, and — because the policy
// drops what it cannot use — would do so silently. Reported at load, where the
// operator can see it.
func TestValidateEditablePathsRefusesAMultiSegmentEntry(t *testing.T) {
	for _, raw := range []string{"scratch/notes", "a/b/c", "/personal/aws/"} {
		err := validateEditablePaths([]string{raw})
		if err == nil {
			t.Errorf("validateEditablePaths([%q]) = nil, want an error", raw)
			continue
		}
		if !strings.Contains(err.Error(), "single path segment") {
			t.Errorf("validateEditablePaths([%q]) = %v, want it to name the depth rule", raw, err)
		}
	}
}

// A backslash is not a separator in a Vault path, so an entry carrying one
// would name a folder literally called "personal\notes" rather than the
// nested path a Windows admin meant. validateEnrolmentKey refuses it for the
// same reason; this is that rule, not a new one.
func TestValidateEditablePathsRefusesABackslash(t *testing.T) {
	for _, raw := range []string{`personal\notes`, `a\b`} {
		err := validateEditablePaths([]string{raw})
		if err == nil {
			t.Errorf("validateEditablePaths([%q]) = nil, want an error", raw)
			continue
		}
		if !strings.Contains(err.Error(), "backslash") {
			t.Errorf("validateEditablePaths([%q]) = %v, want it to name the backslash", raw, err)
		}
	}
}

// Config load and the policy must agree on what a root is: anything load
// accepts the policy must use, and anything load refuses must never reach it.
// They share kvpath.CleanEditableRoot precisely so this holds.
//
// Compared per entry rather than through Enabled(), which is a whole-list
// proxy: a mixed list like ["personal", "a/b/c"] is refused at load while the
// policy still reports Enabled() from the entry it kept, so the case that
// most needs checking is the one Enabled() cannot express.
func TestEditablePathsConfigAndPolicyAgree(t *testing.T) {
	for _, raw := range []string{"personal", "scratch/notes", "", "..", "a/b/c", `personal
otes`, "/personal/"} {
		entries := []string{raw}
		loadErr := validateEditablePaths(entries)
		roots := kvpath.NewEditPolicy([]string{raw}, nil).Roots()

		if loadErr != nil {
			if len(roots) != 0 {
				t.Errorf("%q: config load refused it (%v) but the policy kept root(s) %v", raw, loadErr, roots)
			}
			continue
		}
		// Accepted: the policy must hold exactly the canonical form load
		// rewrote the entry to, so the two cannot drift on spelling either.
		if len(roots) != 1 || roots[0] != entries[0] {
			t.Errorf("%q: config load canonicalised to %q but the policy holds %v", raw, entries[0], roots)
		}
	}

	// A mixed list: load refuses the whole thing, so nothing in it — not even
	// the good entry — may be treated as granted.
	mixed := []string{"personal", "a/b/c"}
	if err := validateEditablePaths(append([]string(nil), mixed...)); err == nil {
		t.Error("a list with one bad entry was accepted")
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
