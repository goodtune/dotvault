package handlers

import (
	"os"
	"path/filepath"
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
		if !containsStr(s, want) {
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
		if !containsStr(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
}
