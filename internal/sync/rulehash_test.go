package sync

import (
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// TestRuleRenderHash_StableAndSensitive locks down the contract the skip gate
// depends on: the hash is stable for an unchanged rule, and changes when any
// render-affecting field changes — most importantly the template, which is the
// edit that previously failed to re-apply on an untouched secret. The rule name
// is deliberately NOT part of the hash (it is the state key, not an input to
// the rendered output).
func TestRuleRenderHash_StableAndSensitive(t *testing.T) {
	base := config.Rule{
		Name:     "ssh",
		VaultKey: "ssh",
		Target: config.Target{
			Path:     "~/.ssh/config",
			Format:   "ssh_config",
			Template: "User {{ username }}\nRemoteForward /home/{{ username }}/.ssh/dotvault.sock oldhost:9000\n",
			Merge:    "",
		},
	}

	want := ruleRenderHash(base)
	if want == "" {
		t.Fatal("ruleRenderHash returned empty string")
	}

	// Identical definition (different name) hashes the same: name is the state
	// key, not a render input.
	same := base
	same.Name = "different-name"
	if got := ruleRenderHash(same); got != want {
		t.Errorf("name change altered hash: got %s, want %s", got, want)
	}

	// Each render-affecting field flips the hash. The template case is the bug
	// this whole mechanism exists to fix.
	mutators := map[string]func(*config.Rule){
		"template": func(r *config.Rule) {
			r.Target.Template = "User {{ username }}\nRemoteForward /home/{{ username }}/.ssh/dotvault.sock newhost:9001\n"
		},
		"vault_key": func(r *config.Rule) { r.VaultKey = "ssh2" },
		"path":      func(r *config.Rule) { r.Target.Path = "~/.ssh/other" },
		"format":    func(r *config.Rule) { r.Target.Format = "text" },
		"merge":     func(r *config.Rule) { r.Target.Merge = "deep" },
	}
	for field, mutate := range mutators {
		r := base
		mutate(&r)
		if got := ruleRenderHash(r); got == want {
			t.Errorf("%s change did not alter hash (still %s)", field, got)
		}
	}
}

// TestRuleRenderHash_FieldBoundaries guards the length-prefixing: two rules that
// differ only in where a field boundary falls must not collide. Without the
// length prefix, ("ab","c") and ("a","bc") would hash identically.
func TestRuleRenderHash_FieldBoundaries(t *testing.T) {
	a := config.Rule{VaultKey: "ab", Target: config.Target{Path: "c"}}
	b := config.Rule{VaultKey: "a", Target: config.Target{Path: "bc"}}
	if ruleRenderHash(a) == ruleRenderHash(b) {
		t.Error("field-boundary collision: distinct rules hashed equal")
	}
}
