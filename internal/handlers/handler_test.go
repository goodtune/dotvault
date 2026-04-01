package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandlerFor(t *testing.T) {
	tests := []struct {
		format  string
		wantErr bool
	}{
		{"yaml", false},
		{"json", false},
		{"ini", false},
		{"toml", false},
		{"text", false},
		{"netrc", false},
		{"xml", true},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			h, err := HandlerFor(tt.format)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if h == nil {
				t.Fatal("handler is nil")
			}
		})
	}
}

func TestYAMLRoundTrip(t *testing.T) {
	h, _ := HandlerFor("yaml")
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yml")

	// Write initial content
	yh := h.(*YAMLHandler)
	initial, _ := yh.Parse("key1: value1\nkey2: value2")
	h.Write(path, initial, 0644)

	// Read it back
	data, err := h.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	// Merge new data
	incoming, _ := yh.Parse("key2: updated\nkey3: added")
	merged, err := h.Merge(data, incoming)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	// Write merged
	h.Write(path, merged, 0644)

	// Verify final content
	got, _ := os.ReadFile(path)
	s := string(got)
	for _, want := range []string{"key1: value1", "key2: updated", "key3: added"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
}

func TestJSONRoundTrip(t *testing.T) {
	h, _ := HandlerFor("json")
	jh := h.(*JSONHandler)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	initial, _ := jh.Parse(`{"a": "1", "b": "2"}`)
	h.Write(path, initial, 0644)

	data, _ := h.Read(path)
	incoming, _ := jh.Parse(`{"b": "updated", "c": "added"}`)
	merged, _ := h.Merge(data, incoming)
	h.Write(path, merged, 0644)

	got, _ := os.ReadFile(path)
	s := string(got)
	for _, want := range []string{`"a": "1"`, `"b": "updated"`, `"c": "added"`} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
}

func TestTOMLRoundTrip(t *testing.T) {
	h, err := HandlerFor("toml")
	if err != nil {
		t.Fatalf("HandlerFor(toml): %v", err)
	}
	th, ok := h.(*TOMLHandler)
	if !ok {
		t.Fatalf("handler is not *TOMLHandler, got %T", h)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "test.toml")

	initial, err := th.Parse("key1 = \"value1\"\nkey2 = \"value2\"")
	if err != nil {
		t.Fatalf("Parse initial TOML: %v", err)
	}
	if err := h.Write(path, initial, 0644); err != nil {
		t.Fatalf("Write initial TOML: %v", err)
	}

	data, err := h.Read(path)
	if err != nil {
		t.Fatalf("Read initial TOML: %v", err)
	}
	incoming, err := th.Parse("key2 = \"updated\"\nkey3 = \"added\"")
	if err != nil {
		t.Fatalf("Parse incoming TOML: %v", err)
	}
	merged, err := h.Merge(data, incoming)
	if err != nil {
		t.Fatalf("Merge TOML: %v", err)
	}
	if err := h.Write(path, merged, 0644); err != nil {
		t.Fatalf("Write merged TOML: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	s := string(got)
	for _, want := range []string{`"value1"`, `"updated"`, `"added"`} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
}

func TestTextRoundTrip(t *testing.T) {
	h, err := HandlerFor("text")
	if err != nil {
		t.Fatalf("HandlerFor(text): %v", err)
	}
	th, ok := h.(*TextHandler)
	if !ok {
		t.Fatalf("handler is not *TextHandler, got %T", h)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "id_rsa")

	initial, err := th.Parse("initial key content")
	if err != nil {
		t.Fatalf("Parse initial: %v", err)
	}
	if err := h.Write(path, initial, 0600); err != nil {
		t.Fatalf("Write initial: %v", err)
	}

	data, err := h.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	incoming, err := th.Parse("replaced key content")
	if err != nil {
		t.Fatalf("Parse incoming: %v", err)
	}
	merged, err := h.Merge(data, incoming)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if err := h.Write(path, merged, 0600); err != nil {
		t.Fatalf("Write merged: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "replaced key content" {
		t.Errorf("output = %q, want 'replaced key content'", string(got))
	}
}
