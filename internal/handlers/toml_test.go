package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTOMLHandler_ReadExisting(t *testing.T) {
	h := &TOMLHandler{}
	data, err := h.Read("testdata/existing.toml")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	m, ok := data.(map[string]any)
	if !ok {
		t.Fatalf("Read() returned %T, want map[string]any", data)
	}
	if _, ok := m["database"]; !ok {
		t.Error("missing key 'database' in parsed data")
	}
	if _, ok := m["credentials"]; !ok {
		t.Error("missing key 'credentials' in parsed data")
	}
}

func TestTOMLHandler_ReadMissing(t *testing.T) {
	h := &TOMLHandler{}
	data, err := h.Read("testdata/nonexistent.toml")
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

func TestTOMLHandler_Parse(t *testing.T) {
	h := &TOMLHandler{}
	data, err := h.Parse("key = \"value\"\ncount = 42")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	m := data.(map[string]any)
	if m["key"] != "value" {
		t.Errorf("parsed key = %v, want 'value'", m["key"])
	}
	if m["count"] != int64(42) {
		t.Errorf("parsed count = %v (%T), want 42", m["count"], m["count"])
	}
}

func TestTOMLHandler_ParseEmpty(t *testing.T) {
	h := &TOMLHandler{}
	data, err := h.Parse("")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	m := data.(map[string]any)
	if len(m) != 0 {
		t.Errorf("expected empty map, got %v", m)
	}
}

func TestTOMLHandler_MergeDeep(t *testing.T) {
	h := &TOMLHandler{}

	existing, err := h.Read("testdata/existing.toml")
	if err != nil {
		t.Fatalf("Read existing: %v", err)
	}
	incoming, err := h.Read("testdata/incoming.toml")
	if err != nil {
		t.Fatalf("Read incoming: %v", err)
	}

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "merged.toml")
	if err := h.Write(outPath, merged, 0644); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	got, _ := os.ReadFile(outPath)
	s := string(got)

	// Password should be updated
	if !strings.Contains(s, `"new-password"`) {
		t.Errorf("merged output missing updated password:\n%s", s)
	}
	// Old password should be gone
	if strings.Contains(s, "old-password") {
		t.Errorf("merged output still contains old password:\n%s", s)
	}
	// Database section preserved
	if !strings.Contains(s, "database") {
		t.Errorf("merged output missing preserved database section:\n%s", s)
	}
	if !strings.Contains(s, "localhost") {
		t.Errorf("merged output missing preserved host:\n%s", s)
	}
	// New token added
	if !strings.Contains(s, "vault-token-123") {
		t.Errorf("merged output missing new token:\n%s", s)
	}
	// Username preserved
	if !strings.Contains(s, "admin") {
		t.Errorf("merged output missing preserved username:\n%s", s)
	}
}

func TestTOMLHandler_MergePreservesExistingKeys(t *testing.T) {
	h := &TOMLHandler{}

	existing, _ := h.Parse("[section]\nkeep = \"yes\"\nupdate = \"old\"")
	incoming, _ := h.Parse("[section]\nupdate = \"new\"\nadd = \"added\"")

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	m := merged.(map[string]any)
	section := m["section"].(map[string]any)

	if section["keep"] != "yes" {
		t.Errorf("section.keep = %v, want 'yes'", section["keep"])
	}
	if section["update"] != "new" {
		t.Errorf("section.update = %v, want 'new'", section["update"])
	}
	if section["add"] != "added" {
		t.Errorf("section.add = %v, want 'added'", section["add"])
	}
}

func TestTOMLHandler_WriteTrailingNewline(t *testing.T) {
	h := &TOMLHandler{}
	data, _ := h.Parse("key = \"value\"")

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.toml")
	h.Write(outPath, data, 0644)

	got, _ := os.ReadFile(outPath)
	if got[len(got)-1] != '\n' {
		t.Error("output missing trailing newline")
	}
}

func TestTOMLHandler_RoundTrip(t *testing.T) {
	h := &TOMLHandler{}
	dir := t.TempDir()
	path := filepath.Join(dir, "test.toml")

	initial, _ := h.Parse("key1 = \"value1\"\nkey2 = \"value2\"")
	h.Write(path, initial, 0644)

	data, err := h.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	incoming, _ := h.Parse("key2 = \"updated\"\nkey3 = \"added\"")
	merged, err := h.Merge(data, incoming)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	h.Write(path, merged, 0644)

	got, _ := os.ReadFile(path)
	s := string(got)
	for _, want := range []string{`"value1"`, `"updated"`, `"added"`} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
}

func TestTOMLHandler_ParseBooleans(t *testing.T) {
	h := &TOMLHandler{}
	data, err := h.Parse("enabled = true\ndisabled = false")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	m := data.(map[string]any)
	if m["enabled"] != true {
		t.Errorf("enabled = %v, want true", m["enabled"])
	}
	if m["disabled"] != false {
		t.Errorf("disabled = %v, want false", m["disabled"])
	}
}

func TestTOMLHandler_ParseArray(t *testing.T) {
	h := &TOMLHandler{}
	data, err := h.Parse(`ports = [8080, 8443, 9090]`)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	m := data.(map[string]any)
	arr, ok := m["ports"].([]any)
	if !ok {
		t.Fatalf("ports is %T, want []any", m["ports"])
	}
	if len(arr) != 3 {
		t.Errorf("ports length = %d, want 3", len(arr))
	}
}
