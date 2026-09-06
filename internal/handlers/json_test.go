package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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

// TestJSONHandler_DeleteNulls covers the field-nullification contract: with
// DeleteNulls set, a null in the incoming (template-rendered) document is a
// tombstone that removes the key from the target rather than a value written
// into it.
func TestJSONHandler_DeleteNulls(t *testing.T) {
	for _, tc := range []struct {
		name     string
		existing string
		incoming string
		want     map[string]any
	}{
		{
			name:     "removes the tombstoned key and keeps the rest",
			existing: `{"keep": "yes", "KEY_I_USED_TO_FILL": "secret"}`,
			incoming: `{"keep": "yes", "KEY_I_USED_TO_FILL": null}`,
			want:     map[string]any{"keep": "yes"},
		},
		{
			name:     "unmanaged keys are still preserved",
			existing: `{"hand_written": "mine", "gone": "secret"}`,
			incoming: `{"gone": null}`,
			want:     map[string]any{"hand_written": "mine"},
		},
		{
			name:     "nested tombstone removes only that key",
			existing: `{"auth": {"token": "t", "legacy": "old"}}`,
			incoming: `{"auth": {"legacy": null}}`,
			want:     map[string]any{"auth": map[string]any{"token": "t"}},
		},
		{
			name:     "tombstoning a subtree removes the whole subtree",
			existing: `{"auth": {"token": "t"}, "other": 1.0}`,
			incoming: `{"auth": null}`,
			want:     map[string]any{"other": 1.0},
		},
		{
			// The idempotency case: a tombstone left in a template forever
			// must keep producing an unchanged file once the key is gone.
			name:     "deleting an absent key is a no-op",
			existing: `{"keep": "yes"}`,
			incoming: `{"KEY_I_USED_TO_FILL": null}`,
			want:     map[string]any{"keep": "yes"},
		},
		{
			// Regression: the !exists branch assigns src wholesale, so a
			// tombstone nested under a key the target lacks must be pruned
			// rather than written out as a literal null.
			name:     "tombstone under an absent parent is not created",
			existing: `{}`,
			incoming: `{"auth": {"token": "t", "legacy": null}}`,
			want:     map[string]any{"auth": map[string]any{"token": "t"}},
		},
		{
			// Same hazard on the replace branch: dst holds a scalar, src a map.
			name:     "tombstone in a map replacing a scalar is not created",
			existing: `{"auth": "flat"}`,
			incoming: `{"auth": {"token": "t", "legacy": null}}`,
			want:     map[string]any{"auth": map[string]any{"token": "t"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &JSONHandler{DeleteNulls: true}
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
			if !reflect.DeepEqual(merged, tc.want) {
				t.Errorf("merged =\n  %#v\nwant\n  %#v", merged, tc.want)
			}
		})
	}
}

// TestJSONHandler_NullsWrittenWhenFlagOff pins the default: without the
// opt-in, a null keeps its historical meaning and is written as a value.
func TestJSONHandler_NullsWrittenWhenFlagOff(t *testing.T) {
	h := &JSONHandler{}

	existing, _ := h.Parse(`{"KEY_I_USED_TO_FILL": "secret"}`)
	incoming, _ := h.Parse(`{"KEY_I_USED_TO_FILL": null}`)

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}
	m := merged.(map[string]any)
	v, ok := m["KEY_I_USED_TO_FILL"]
	if !ok {
		t.Fatal("key was deleted without DeleteNulls set")
	}
	if v != nil {
		t.Errorf("value = %v, want nil", v)
	}
}
