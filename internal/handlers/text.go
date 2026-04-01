package handlers

import (
	"fmt"
	"os"
)

// TextHandler handles plain text files with full overwrite (no merge).
// This is intended for literal file content such as SSH private keys
// or PEM certificates.
type TextHandler struct{}

func (h *TextHandler) Read(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return string(data), nil
}

func (h *TextHandler) Parse(content string) (any, error) {
	return content, nil
}

func (h *TextHandler) Merge(existing any, incoming any) (any, error) {
	// Text format always overwrites — no merge.
	s, ok := incoming.(string)
	if !ok {
		return nil, fmt.Errorf("incoming: expected string, got %T", incoming)
	}
	return s, nil
}

func (h *TextHandler) Write(path string, data any, perm os.FileMode) error {
	s, ok := data.(string)
	if !ok {
		return fmt.Errorf("expected string, got %T", data)
	}
	return atomicWrite(path, []byte(s), perm)
}
