package handlers

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestYAMLHandler_ReadExisting(t *testing.T) {
	h := &YAMLHandler{}
	data, err := h.Read("testdata/existing.yml")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	node, ok := data.(*yaml.Node)
	if !ok {
		t.Fatalf("Read() returned %T, want *yaml.Node", data)
	}
	if node.Kind != yaml.DocumentNode {
		t.Errorf("node.Kind = %d, want DocumentNode (%d)", node.Kind, yaml.DocumentNode)
	}
}

func TestYAMLHandler_ReadMissing(t *testing.T) {
	h := &YAMLHandler{}
	data, err := h.Read("testdata/nonexistent.yml")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	// Should return an empty document node
	node, ok := data.(*yaml.Node)
	if !ok {
		t.Fatalf("Read() returned %T, want *yaml.Node", data)
	}
	if node.Kind != yaml.DocumentNode {
		t.Errorf("node.Kind = %d, want DocumentNode", node.Kind)
	}
}

func TestYAMLHandler_Parse(t *testing.T) {
	h := &YAMLHandler{}
	data, err := h.Parse(`github.com:
  oauth_token: "new-token"`)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	node, ok := data.(*yaml.Node)
	if !ok {
		t.Fatalf("Parse() returned %T, want *yaml.Node", data)
	}
	if node.Kind != yaml.DocumentNode {
		t.Errorf("node.Kind = %d, want DocumentNode", node.Kind)
	}
}

func TestYAMLHandler_MergeDeep(t *testing.T) {
	h := &YAMLHandler{}

	existing, err := h.Read("testdata/existing.yml")
	if err != nil {
		t.Fatalf("Read existing: %v", err)
	}
	incoming, err := h.Read("testdata/incoming.yml")
	if err != nil {
		t.Fatalf("Read incoming: %v", err)
	}

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	// Write merged to temp and compare with expected
	dir := t.TempDir()
	outPath := filepath.Join(dir, "merged.yml")
	if err := h.Write(outPath, merged, 0644); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	want, err := os.ReadFile("testdata/merged.yml")
	if err != nil {
		t.Fatalf("read expected: %v", err)
	}

	if string(got) != string(want) {
		t.Errorf("merged output:\n%s\nwant:\n%s", got, want)
	}
}

func TestYAMLHandler_MergePreservesExistingKeys(t *testing.T) {
	h := &YAMLHandler{}

	existingYAML := `top:
  keep_this: original
  update_this: old`
	incomingYAML := `top:
  update_this: new
  add_this: added`

	existing, _ := h.Parse(existingYAML)
	incoming, _ := h.Parse(incomingYAML)

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	// Serialize and check all three keys present
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.yml")
	h.Write(outPath, merged, 0644)

	got, _ := os.ReadFile(outPath)
	s := string(got)

	for _, want := range []string{"keep_this: original", "update_this: new", "add_this: added"} {
		if !strings.Contains(s, want) {
			t.Errorf("merged output missing %q:\n%s", want, s)
		}
	}
}

func TestYAMLHandler_WriteAtomicAndPermissions(t *testing.T) {
	h := &YAMLHandler{}
	data, _ := h.Parse(`key: value`)

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.yml")
	if err := h.Write(outPath, data, 0600); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("permissions = %o, want 0600", info.Mode().Perm())
	}
}

// mergeYAMLForTest runs a full Read-equivalent merge and returns the written
// file both as a parsed map and as raw bytes. Assertions go through the parsed
// form: a substring search over the rendered file matches unrelated text and
// cannot tell a deleted key from one whose value merely changed.
func mergeYAMLForTest(t *testing.T, h *YAMLHandler, existing, incoming string) (map[string]any, string) {
	t.Helper()
	ex, err := h.Parse(existing)
	if err != nil {
		t.Fatalf("Parse(existing): %v", err)
	}
	in, err := h.Parse(incoming)
	if err != nil {
		t.Fatalf("Parse(incoming): %v", err)
	}
	merged, err := h.Merge(ex, in)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	out := filepath.Join(t.TempDir(), "out.yaml")
	if err := h.Write(out, merged, 0600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got map[string]any
	if err := yaml.Unmarshal(raw, &got); err != nil {
		t.Fatalf("re-parse written file: %v\n%s", err, raw)
	}
	return got, string(raw)
}

// TestYAMLHandler_DeleteNulls mirrors the JSON contract on the node-based
// merge path, where a tombstone splices the key/value pair out of the mapping
// node. Assertions run against the re-parsed output because that is what a
// consumer of the file actually sees.
func TestYAMLHandler_DeleteNulls(t *testing.T) {
	for _, tc := range []struct {
		name       string
		existing   string
		incoming   string
		wantKeys   map[string]any
		wantAbsent []string
	}{
		{
			name:       "removes the tombstoned key and keeps the rest",
			existing:   "keep: 1\nKEY_I_USED_TO_FILL: secret\n",
			incoming:   "KEY_I_USED_TO_FILL: null\n",
			wantKeys:   map[string]any{"keep": 1},
			wantAbsent: []string{"KEY_I_USED_TO_FILL"},
		},
		{
			// `key: ~` and the bare `key:` an empty template substitution
			// produces both resolve to the null tag, so all three spellings
			// must behave identically.
			name:       "tilde spelling is a tombstone",
			existing:   "gone: secret\nkeep: 1\n",
			incoming:   "gone: ~\n",
			wantKeys:   map[string]any{"keep": 1},
			wantAbsent: []string{"gone"},
		},
		{
			name:       "bare key spelling is a tombstone",
			existing:   "gone: secret\nkeep: 1\n",
			incoming:   "gone:\n",
			wantKeys:   map[string]any{"keep": 1},
			wantAbsent: []string{"gone"},
		},
		{
			name:       "deleting an absent key is a no-op",
			existing:   "keep: 1\n",
			incoming:   "KEY_I_USED_TO_FILL: null\n",
			wantKeys:   map[string]any{"keep": 1},
			wantAbsent: []string{"KEY_I_USED_TO_FILL"},
		},
		{
			name:       "tombstoning a subtree removes the whole subtree",
			existing:   "auth:\n  token: t\nother: 1\n",
			incoming:   "auth: null\n",
			wantKeys:   map[string]any{"other": 1},
			wantAbsent: []string{"auth"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, raw := mergeYAMLForTest(t, &YAMLHandler{DeleteNulls: true}, tc.existing, tc.incoming)
			for k, want := range tc.wantKeys {
				v, ok := got[k]
				if !ok {
					t.Errorf("key %q missing from output:\n%s", k, raw)
					continue
				}
				if !reflect.DeepEqual(v, want) {
					t.Errorf("key %q = %#v, want %#v", k, v, want)
				}
			}
			for _, k := range tc.wantAbsent {
				if _, ok := got[k]; ok {
					t.Errorf("key %q survived deletion:\n%s", k, raw)
				}
			}
		})
	}
}

// TestYAMLHandler_DeleteNullsNested pins that a nested tombstone removes only
// its own key and leaves its siblings alone.
func TestYAMLHandler_DeleteNullsNested(t *testing.T) {
	got, raw := mergeYAMLForTest(t, &YAMLHandler{DeleteNulls: true},
		"auth:\n  token: t\n  legacy: old\n",
		"auth:\n  legacy: null\n")

	auth, ok := got["auth"].(map[string]any)
	if !ok {
		t.Fatalf("auth is not a mapping: %#v\n%s", got["auth"], raw)
	}
	if _, gone := auth["legacy"]; gone {
		t.Errorf("auth.legacy survived deletion:\n%s", raw)
	}
	if auth["token"] != "t" {
		t.Errorf("auth.token = %#v, want \"t\"", auth["token"])
	}
}

// TestYAMLHandler_DeleteNullsRemovesDuplicateKeys is a security regression
// test. yaml.v3 does not reject duplicate keys, and most consumers take the
// *last* occurrence — so a tombstone that stopped at the first match would
// report a deletion while leaving the value that actually gets read.
func TestYAMLHandler_DeleteNullsRemovesDuplicateKeys(t *testing.T) {
	got, raw := mergeYAMLForTest(t, &YAMLHandler{DeleteNulls: true},
		"password: first\nkeep: 1\npassword: second\n",
		"password: null\n")

	if _, ok := got["password"]; ok {
		t.Errorf("a duplicate password key survived deletion:\n%s", raw)
	}
	if strings.Contains(raw, "second") || strings.Contains(raw, "first") {
		t.Errorf("a duplicate credential value is still on disk:\n%s", raw)
	}
}

// TestYAMLHandler_DeleteNullsRefusesAliasedDocuments pins the refusal. A key
// supplied by a merge key, or shared through an anchor, cannot be removed
// soundly by name — deleting it would either leave the value in effect or
// strand an alias. Refusing loudly beats reporting a deletion that did not
// happen, which is the exact failure the feature exists to prevent.
func TestYAMLHandler_DeleteNullsRefusesAliasedDocuments(t *testing.T) {
	// Both fixtures are refused. The error names whichever disqualifying
	// feature the walk reaches first, and a merge key necessarily aliases an
	// anchor defined earlier in the document, so "an anchor" is what a
	// merge-key file reports in practice — the refusal, not the label, is the
	// contract being pinned here.
	for _, tc := range []struct {
		name     string
		existing string
	}{
		{"merge key", "base: &b\n  password: inherited\napp:\n  <<: *b\n"},
		{"anchor", "app: &a\n  password: shared\ncopy: *a\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &YAMLHandler{DeleteNulls: true}
			ex, err := h.Parse(tc.existing)
			if err != nil {
				t.Fatalf("Parse(existing): %v", err)
			}
			in, _ := h.Parse("password: null\n")
			if _, err := h.Merge(ex, in); err == nil {
				t.Fatal("expected Merge to refuse an aliased document")
			} else if !strings.Contains(err.Error(), "delete_nulls cannot guarantee removal") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestUnsafeForDeletionNamesMergeKey covers the merge-key branch directly,
// since a real document always trips the anchor check first.
func TestUnsafeForDeletionNamesMergeKey(t *testing.T) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte("app:\n  token: t\n"), &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// Rename the key in place to "<<" without introducing an anchor.
	doc.Content[0].Content[0].Value = "<<"
	feature, unsafe := unsafeForDeletion(&doc)
	if !unsafe {
		t.Fatal("merge key not detected")
	}
	if !strings.Contains(feature, "merge key") {
		t.Errorf("feature = %q, want it to name the merge key", feature)
	}
}

// TestYAMLHandler_DeleteNullsAllowsAliasesWithoutTombstones pins that the
// refusal is scoped to merges that actually delete something: a rule with the
// flag on whose template renders no null must keep working on such a file.
func TestYAMLHandler_DeleteNullsAllowsAliasesWithoutTombstones(t *testing.T) {
	h := &YAMLHandler{DeleteNulls: true}
	ex, err := h.Parse("app: &a\n  token: old\ncopy: *a\n")
	if err != nil {
		t.Fatalf("Parse(existing): %v", err)
	}
	in, _ := h.Parse("app:\n  token: new\n")
	if _, err := h.Merge(ex, in); err != nil {
		t.Fatalf("Merge refused a document it deletes nothing from: %v", err)
	}
}

// TestYAMLHandler_NullsWrittenWhenFlagOff pins the default. This is the
// case that makes delete_nulls opt-in: `key: {{ .missing }}` renders a bare
// `key:`, so always-on deletion would silently remove live credentials.
func TestYAMLHandler_NullsWrittenWhenFlagOff(t *testing.T) {
	h := &YAMLHandler{}

	existing, _ := h.Parse("password: live\n")
	incoming, _ := h.Parse("password:\n")

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "out.yaml")
	if err := h.Write(out, merged, 0600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !strings.Contains(string(got), "password") {
		t.Errorf("key was deleted without DeleteNulls set:\n%s", got)
	}
}
