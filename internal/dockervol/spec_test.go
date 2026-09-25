package dockervol

import (
	"strings"
	"testing"
	"time"
)

func TestParseOptionsDefaults(t *testing.T) {
	spec, err := ParseOptions(nil, time.Minute)
	if err != nil {
		t.Fatalf("ParseOptions: %v", err)
	}
	if spec.Layout != LayoutJSON || spec.Mode != DefaultMode || spec.TTL != time.Minute || len(spec.Secrets) != 0 {
		t.Errorf("defaults = %+v", spec)
	}
	if !spec.Covers("anything/at/all") {
		t.Error("an empty selection must cover the whole subtree")
	}
}

func TestParseOptionsSelection(t *testing.T) {
	spec, err := ParseOptions(map[string]string{OptSecrets: " jfrog, databricks/ ,gh,gh"}, time.Minute)
	if err != nil {
		t.Fatalf("ParseOptions: %v", err)
	}
	want := []string{"databricks/", "gh", "jfrog"}
	if strings.Join(spec.Secrets, ",") != strings.Join(want, ",") {
		t.Errorf("Secrets = %v, want %v (sorted, deduplicated)", spec.Secrets, want)
	}
	for path, covered := range map[string]bool{
		"gh":              true,
		"gh/sub":          false, // a bare name is one secret, not a folder
		"databricks":      false, // the folder's own name is a different secret, which render never emits
		"databricks/prod": true,
		"databricksx":     false,
		"other":           false,
	} {
		if got := spec.Covers(path); got != covered {
			t.Errorf("Covers(%q) = %v, want %v", path, got, covered)
		}
	}
}

func TestParseOptionsRejects(t *testing.T) {
	for name, opts := range map[string]map[string]string{
		"unknown option":         {"secret": "gh"},
		"bad layout":             {OptLayout: "yaml"},
		"non-octal mode":         {OptMode: "rw"},
		"write bit":              {OptMode: "0600"},
		"no owner read":          {OptMode: "0044"},
		"zero mode":              {OptMode: "0"},
		"ttl zero":               {OptTTL: "0"},
		"ttl over ceiling":       {OptTTL: "1h"},
		"ttl unparseable":        {OptTTL: "soon"},
		"path traversal":         {OptSecrets: "../other"},
		"bare slash":             {OptSecrets: "/"},
		"embedded empty segment": {OptSecrets: "a//b"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseOptions(opts, time.Minute); err == nil {
				t.Errorf("ParseOptions(%v) accepted", opts)
			}
		})
	}
	if _, err := ParseOptions(nil, 0); err == nil {
		t.Error("ParseOptions accepted no ttl at all")
	}
}

func TestParseOptionsModeAndTTL(t *testing.T) {
	spec, err := ParseOptions(map[string]string{OptMode: "0444", OptTTL: "30s", OptLayout: "fields"}, time.Minute)
	if err != nil {
		t.Fatalf("ParseOptions: %v", err)
	}
	if spec.Mode != 0o444 || spec.TTL != 30*time.Second || spec.Layout != LayoutFields {
		t.Errorf("spec = %+v", spec)
	}
	if got := spec.DirMode(); got != 0o755 {
		t.Errorf("DirMode() = %o, want 0755 so a reader granted read can traverse", got)
	}
	if got := (Spec{Mode: 0o400}).DirMode(); got != 0o700 {
		t.Errorf("DirMode() = %o, want 0700 for owner-only files", got)
	}
	if got := (Spec{Mode: 0o440}).DirMode(); got != 0o750 {
		t.Errorf("DirMode() = %o, want 0750", got)
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"a", "my-vol.1_x", "0abc"} {
		if err := ValidateName(ok); err != nil {
			t.Errorf("ValidateName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-lead", "a/b", "..", "a b", strings.Repeat("x", 256)} {
		if err := ValidateName(bad); err == nil {
			t.Errorf("ValidateName(%q) accepted", bad)
		}
	}
}

func TestSpecEqualIgnoresOrderButNotContent(t *testing.T) {
	a, _ := ParseOptions(map[string]string{OptSecrets: "b,a"}, time.Minute)
	b, _ := ParseOptions(map[string]string{OptSecrets: "a,b"}, time.Minute)
	c, _ := ParseOptions(map[string]string{OptSecrets: "a"}, time.Minute)
	if !a.Equal(b) {
		t.Error("same selection in a different order must compare equal")
	}
	if a.Equal(c) {
		t.Error("different selections must not compare equal")
	}
}
