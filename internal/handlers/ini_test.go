package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestINIHandler_ReadExisting(t *testing.T) {
	h := &INIHandler{}
	data, err := h.Read("testdata/existing.ini")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if data == nil {
		t.Fatal("Read() returned nil")
	}
}

func TestINIHandler_ReadMissing(t *testing.T) {
	h := &INIHandler{}
	data, err := h.Read("testdata/nonexistent.ini")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if data == nil {
		t.Fatal("Read() returned nil for missing file")
	}
}

func TestINIHandler_Parse(t *testing.T) {
	h := &INIHandler{}
	data, err := h.Parse("key=value\nother=thing")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if data == nil {
		t.Fatal("Parse() returned nil")
	}
}

func TestINIHandler_MergeLineReplace(t *testing.T) {
	h := &INIHandler{}

	existing, _ := h.Read("testdata/existing.ini")
	incoming, _ := h.Parse("//registry.npmjs.org/:_authToken=new-token-from-vault")

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "merged.ini")
	if err := h.Write(outPath, merged, 0644); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	got, _ := os.ReadFile(outPath)
	s := string(got)

	// Token should be updated
	if !strings.Contains(s, "new-token-from-vault") {
		t.Errorf("merged output missing updated token:\n%s", s)
	}
	// Old token should be gone
	if strings.Contains(s, "old-token") {
		t.Errorf("merged output still contains old token:\n%s", s)
	}
	// Registry setting preserved (ini library may add spaces around =)
	if !strings.Contains(s, "registry") || !strings.Contains(s, "https://registry.npmjs.org/") {
		t.Errorf("merged output missing preserved registry setting:\n%s", s)
	}
}

func TestINIHandler_MergeAppendsNewKey(t *testing.T) {
	h := &INIHandler{}

	existing, _ := h.Parse("existing_key=existing_value")
	incoming, _ := h.Parse("new_key=new_value")

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.ini")
	h.Write(outPath, merged, 0644)

	got, _ := os.ReadFile(outPath)
	s := string(got)

	if !strings.Contains(s, "existing_key") || !strings.Contains(s, "existing_value") {
		t.Errorf("missing existing key:\n%s", s)
	}
	if !strings.Contains(s, "new_key") || !strings.Contains(s, "new_value") {
		t.Errorf("missing new key:\n%s", s)
	}
}

func TestINIHandler_MergeWithSections(t *testing.T) {
	h := &INIHandler{}

	existing, _ := h.Parse("[section1]\nkey1=old\nkey2=keep\n\n[section2]\nkey3=stays")
	incoming, _ := h.Parse("[section1]\nkey1=new\nkey4=added")

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.ini")
	h.Write(outPath, merged, 0644)

	got, _ := os.ReadFile(outPath)
	s := string(got)

	// ini library may write "key = value" with spaces
	if !iniContainsKeyValue(s, "key1", "new") {
		t.Errorf("key1 not updated:\n%s", s)
	}
	if !iniContainsKeyValue(s, "key2", "keep") {
		t.Errorf("key2 not preserved:\n%s", s)
	}
	if !iniContainsKeyValue(s, "key3", "stays") {
		t.Errorf("key3 not preserved:\n%s", s)
	}
	if !iniContainsKeyValue(s, "key4", "added") {
		t.Errorf("key4 not added:\n%s", s)
	}
}

// iniContainsKeyValue checks if a string contains a key=value pair,
// allowing for spaces around the = sign as produced by gopkg.in/ini.v1.
func iniContainsKeyValue(s, key, value string) bool {
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) == 2 {
			if strings.TrimSpace(parts[0]) == key && strings.TrimSpace(parts[1]) == value {
				return true
			}
		}
	}
	return false
}
