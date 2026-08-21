package handlers

import (
	"encoding/json"
	"fmt"
	"os"
)

// JSONHandler handles JSON files with deep merge.
type JSONHandler struct {
	// DeleteNulls makes a null in the incoming document a tombstone: the
	// matching key is removed from the target file rather than written as
	// null. See config.Target.DeleteNulls for why it is opt-in.
	DeleteNulls bool
}

func (h *JSONHandler) Read(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		return map[string]any{}, nil
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse json %s: %w", path, err)
	}
	return m, nil
}

func (h *JSONHandler) Parse(content string) (any, error) {
	if content == "" {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(content), &m); err != nil {
		return nil, fmt.Errorf("parse json content: %w", err)
	}
	return m, nil
}

func (h *JSONHandler) Merge(existing any, incoming any) (any, error) {
	dst, ok := existing.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("existing: expected map[string]any, got %T", existing)
	}
	src, ok := incoming.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("incoming: expected map[string]any, got %T", incoming)
	}

	return deepMergeJSON(dst, src, h.DeleteNulls), nil
}

func (h *JSONHandler) Write(path string, data any, perm os.FileMode) error {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("expected map[string]any, got %T", data)
	}

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	// Trailing newline
	out = append(out, '\n')

	return atomicWrite(path, out, perm)
}

// deepMergeJSON recursively merges src into dst.
// Maps are merged recursively. All other types (arrays, scalars) are replaced.
//
// When deleteNulls is set, a null in src is a tombstone rather than a value:
// the key is removed from dst instead of being written. Deleting a key that is
// not there is a no-op, which is what makes a tombstone safe to leave in a
// template forever — every subsequent sync re-applies it against a file that
// no longer has the key and produces no change.
func deepMergeJSON(dst, src map[string]any, deleteNulls bool) map[string]any {
	for key, srcVal := range src {
		if deleteNulls && srcVal == nil {
			delete(dst, key)
			continue
		}

		dstVal, exists := dst[key]
		if !exists {
			dst[key] = pruneNullsJSON(srcVal, deleteNulls)
			continue
		}

		// If both are maps, recurse
		dstMap, dstOk := dstVal.(map[string]any)
		srcMap, srcOk := srcVal.(map[string]any)
		if dstOk && srcOk {
			dst[key] = deepMergeJSON(dstMap, srcMap, deleteNulls)
		} else {
			// Replace (arrays, scalars, type mismatch)
			dst[key] = pruneNullsJSON(srcVal, deleteNulls)
		}
	}
	return dst
}

// pruneNullsJSON strips tombstones from a src value that is about to be
// assigned into dst wholesale, rather than merged key-by-key.
//
// Without this, a tombstone for a key the target does not have would be
// *written* instead of ignored: `{"a": {"b": null}}` against a file with no
// "a" takes the !exists branch and would assign the map verbatim, creating
// the very `"b": null` the rule asked to delete. The same applies on the
// replace branch, where dst holds a scalar and src a map.
func pruneNullsJSON(v any, deleteNulls bool) any {
	if !deleteNulls {
		return v
	}
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	for key, val := range m {
		if val == nil {
			delete(m, key)
			continue
		}
		m[key] = pruneNullsJSON(val, deleteNulls)
	}
	return m
}
