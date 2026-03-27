package handlers

import (
	"encoding/json"
	"fmt"
	"os"
)

// JSONHandler handles JSON files with deep merge.
type JSONHandler struct{}

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

	return deepMergeJSON(dst, src), nil
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
func deepMergeJSON(dst, src map[string]any) map[string]any {
	for key, srcVal := range src {
		dstVal, exists := dst[key]
		if !exists {
			dst[key] = srcVal
			continue
		}

		// If both are maps, recurse
		dstMap, dstOk := dstVal.(map[string]any)
		srcMap, srcOk := srcVal.(map[string]any)
		if dstOk && srcOk {
			dst[key] = deepMergeJSON(dstMap, srcMap)
		} else {
			// Replace (arrays, scalars, type mismatch)
			dst[key] = srcVal
		}
	}
	return dst
}
