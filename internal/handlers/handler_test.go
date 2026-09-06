package handlers

import (
	"gopkg.in/yaml.v3"
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

// TestHandlerWithOptionsDeleteNulls pins the factory's second gate: asking a
// null-less format for null deletion is an error, not a silent no-op that
// would hand the caller additive-only merges when it asked for deletions.
func TestHandlerWithOptionsDeleteNulls(t *testing.T) {
	for _, tt := range []struct {
		format  string
		wantErr bool
	}{
		{"json", false},
		{"yaml", false},
		{"ini", true},
		{"toml", true},
		{"text", true},
		{"netrc", true},
		{"ssh_config", true},
	} {
		t.Run(tt.format, func(t *testing.T) {
			h, err := HandlerWithOptions(tt.format, Options{DeleteNulls: true})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for delete_nulls with format %q", tt.format)
				}
				if !strings.Contains(err.Error(), "delete_nulls") {
					t.Errorf("error should name the offending option, got: %v", err)
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

// TestHandlerForLeavesDeleteNullsOff pins that the plain factory is still
// the historical default for every format.
func TestHandlerForLeavesDeleteNullsOff(t *testing.T) {
	j, err := HandlerFor("json")
	if err != nil {
		t.Fatalf("HandlerFor(json): %v", err)
	}
	if j.(*JSONHandler).DeleteNulls {
		t.Error("JSONHandler.DeleteNulls set by HandlerFor")
	}
	y, err := HandlerFor("yaml")
	if err != nil {
		t.Fatalf("HandlerFor(yaml): %v", err)
	}
	if y.(*YAMLHandler).DeleteNulls {
		t.Error("YAMLHandler.DeleteNulls set by HandlerFor")
	}
}

// TestDeleteNullsTreatsArraysAsOpaque pins that json and yaml agree: the
// merge replaces arrays wholesale rather than merging into them, so there is
// nothing inside one for a tombstone to remove and a null there is written as
// a value. The two handlers diverged here at one point — the same logical rule
// stripped the key under yaml and wrote a literal null under json.
func TestDeleteNullsTreatsArraysAsOpaque(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		h := &JSONHandler{DeleteNulls: true}
		existing, _ := h.Parse(`{}`)
		incoming, _ := h.Parse(`{"servers": [{"host": "h", "port": null}]}`)
		merged, err := h.Merge(existing, incoming)
		if err != nil {
			t.Fatalf("Merge: %v", err)
		}
		servers, ok := merged.(map[string]any)["servers"].([]any)
		if !ok || len(servers) != 1 {
			t.Fatalf("servers = %#v", merged.(map[string]any)["servers"])
		}
		elem := servers[0].(map[string]any)
		if _, present := elem["port"]; !present {
			t.Error("json stripped a null inside an array element; arrays are opaque values")
		}
	})

	t.Run("yaml", func(t *testing.T) {
		h := &YAMLHandler{DeleteNulls: true}
		existing, _ := h.Parse("")
		incoming, _ := h.Parse("servers:\n  - host: h\n    port: null\n")
		merged, err := h.Merge(existing, incoming)
		if err != nil {
			t.Fatalf("Merge: %v", err)
		}
		out := filepath.Join(t.TempDir(), "out.yaml")
		if err := h.Write(out, merged, 0600); err != nil {
			t.Fatalf("Write: %v", err)
		}
		raw, _ := os.ReadFile(out)
		var got struct {
			Servers []map[string]any `yaml:"servers"`
		}
		if err := yaml.Unmarshal(raw, &got); err != nil {
			t.Fatalf("re-parse: %v\n%s", err, raw)
		}
		if len(got.Servers) != 1 {
			t.Fatalf("servers = %#v\n%s", got.Servers, raw)
		}
		if _, present := got.Servers[0]["port"]; !present {
			t.Errorf("yaml stripped a null inside a sequence element; arrays are opaque values:\n%s", raw)
		}
	})
}
