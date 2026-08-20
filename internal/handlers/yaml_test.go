package handlers

import (
	"os"
	"path/filepath"
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

// TestYAMLHandler_DeleteNulls mirrors the JSON contract on the node-based
// merge path, where a tombstone splices the key/value pair out of the
// mapping node. Assertions are made on the rendered output because that is
// what lands on disk, and it also proves the pair is genuinely gone rather
// than present-and-null.
func TestYAMLHandler_DeleteNulls(t *testing.T) {
	for _, tc := range []struct {
		name       string
		existing   string
		incoming   string
		wantHas    []string
		wantAbsent []string
	}{
		{
			name:       "removes the tombstoned key and keeps the rest",
			existing:   "keep: yes\nKEY_I_USED_TO_FILL: secret\n",
			incoming:   "KEY_I_USED_TO_FILL: null\n",
			wantHas:    []string{"keep"},
			wantAbsent: []string{"KEY_I_USED_TO_FILL", "secret"},
		},
		{
			// `key: ~` and the bare `key:` an empty template substitution
			// produces both resolve to the null tag, so all three spellings
			// must behave identically.
			name:       "tilde spelling is a tombstone",
			existing:   "gone: secret\n",
			incoming:   "gone: ~\n",
			wantAbsent: []string{"gone", "secret"},
		},
		{
			name:       "bare key spelling is a tombstone",
			existing:   "gone: secret\n",
			incoming:   "gone:\n",
			wantAbsent: []string{"gone", "secret"},
		},
		{
			name:       "nested tombstone removes only that key",
			existing:   "auth:\n  token: t\n  legacy: old\n",
			incoming:   "auth:\n  legacy: null\n",
			wantHas:    []string{"token"},
			wantAbsent: []string{"legacy", "old"},
		},
		{
			name:       "deleting an absent key is a no-op",
			existing:   "keep: yes\n",
			incoming:   "KEY_I_USED_TO_FILL: null\n",
			wantHas:    []string{"keep"},
			wantAbsent: []string{"KEY_I_USED_TO_FILL"},
		},
		{
			name:       "tombstone under an absent parent is not created",
			existing:   "other: 1\n",
			incoming:   "auth:\n  token: t\n  legacy: null\n",
			wantHas:    []string{"other", "token"},
			wantAbsent: []string{"legacy", "null"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &YAMLHandler{DeleteNulls: true}
			existing, err := h.Parse(tc.existing)
			if err != nil {
				t.Fatalf("Parse(existing): %v", err)
			}
			incoming, err := h.Parse(tc.incoming)
			if err != nil {
				t.Fatalf("Parse(incoming): %v", err)
			}
			merged, err := h.Merge(existing, incoming)
			if err != nil {
				t.Fatalf("Merge() error: %v", err)
			}

			dir := t.TempDir()
			out := filepath.Join(dir, "out.yaml")
			if err := h.Write(out, merged, 0600); err != nil {
				t.Fatalf("Write: %v", err)
			}
			got, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			for _, want := range tc.wantHas {
				if !strings.Contains(string(got), want) {
					t.Errorf("output missing %q:\n%s", want, got)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(string(got), absent) {
					t.Errorf("output still contains %q:\n%s", absent, got)
				}
			}
		})
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
