package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestJSONHandler_ReadExisting(t *testing.T) {
	h := &JSONHandler{}
	data, err := h.Read("testdata/existing.json")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	m, ok := data.(map[string]any)
	if !ok {
		t.Fatalf("Read() returned %T, want map[string]any", data)
	}
	if _, ok := m["auths"]; !ok {
		t.Error("missing key 'auths' in parsed data")
	}
}

func TestJSONHandler_ReadMissing(t *testing.T) {
	h := &JSONHandler{}
	data, err := h.Read("testdata/nonexistent.json")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	m, ok := data.(map[string]any)
	if !ok {
		t.Fatalf("Read() returned %T, want map[string]any", data)
	}
	if len(m) != 0 {
		t.Errorf("expected empty map, got %v", m)
	}
}

func TestJSONHandler_Parse(t *testing.T) {
	h := &JSONHandler{}
	data, err := h.Parse(`{"key": "value"}`)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	m := data.(map[string]any)
	if m["key"] != "value" {
		t.Errorf("parsed key = %v, want 'value'", m["key"])
	}
}

func TestJSONHandler_MergeDeep(t *testing.T) {
	h := &JSONHandler{}

	existing, _ := h.Read("testdata/existing.json")
	incoming, _ := h.Read("testdata/incoming.json")

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "merged.json")
	if err := h.Write(outPath, merged, 0644); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	got, _ := os.ReadFile(outPath)
	want, _ := os.ReadFile("testdata/merged.json")

	// Compare as parsed JSON to ignore whitespace differences
	var gotMap, wantMap map[string]any
	json.Unmarshal(got, &gotMap)
	json.Unmarshal(want, &wantMap)

	gotJSON, _ := json.Marshal(gotMap)
	wantJSON, _ := json.Marshal(wantMap)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("merged output:\n%s\nwant:\n%s", got, want)
	}
}

func TestJSONHandler_MergePreservesExistingKeys(t *testing.T) {
	h := &JSONHandler{}

	existing, _ := h.Parse(`{"a": {"keep": "yes", "update": "old"}, "b": "stays"}`)
	incoming, _ := h.Parse(`{"a": {"update": "new", "add": "added"}}`)

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	m := merged.(map[string]any)

	// Top-level "b" preserved
	if m["b"] != "stays" {
		t.Errorf("top-level 'b' = %v, want 'stays'", m["b"])
	}

	a := m["a"].(map[string]any)
	if a["keep"] != "yes" {
		t.Errorf("a.keep = %v, want 'yes'", a["keep"])
	}
	if a["update"] != "new" {
		t.Errorf("a.update = %v, want 'new'", a["update"])
	}
	if a["add"] != "added" {
		t.Errorf("a.add = %v, want 'added'", a["add"])
	}
}

func TestJSONHandler_MergeArraysReplaced(t *testing.T) {
	h := &JSONHandler{}

	existing, _ := h.Parse(`{"items": [1, 2, 3]}`)
	incoming, _ := h.Parse(`{"items": [4, 5]}`)

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	m := merged.(map[string]any)
	items := m["items"].([]any)
	if len(items) != 2 {
		t.Errorf("items length = %d, want 2 (arrays replaced wholesale)", len(items))
	}
}

func TestJSONHandler_WriteTrailingNewline(t *testing.T) {
	h := &JSONHandler{}
	data, _ := h.Parse(`{"key": "value"}`)

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.json")
	h.Write(outPath, data, 0644)

	got, _ := os.ReadFile(outPath)
	if got[len(got)-1] != '\n' {
		t.Error("output missing trailing newline")
	}
}
