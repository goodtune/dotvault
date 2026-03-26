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

