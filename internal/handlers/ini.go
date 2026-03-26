package handlers

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/ini.v1"
)

// INIHandler handles INI files with line-replace merge.
type INIHandler struct{}

func (h *INIHandler) Read(path string) (any, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ini.Empty(), nil
		}
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	cfg, err := ini.LoadSources(ini.LoadOptions{
		AllowBooleanKeys:        true,
		SkipUnrecognizableLines: true,
	}, path)
	if err != nil {
		return nil, fmt.Errorf("parse ini %s: %w", path, err)
	}
	return cfg, nil
}

func (h *INIHandler) Parse(content string) (any, error) {
	if content == "" {
		return ini.Empty(), nil
	}
	cfg, err := ini.LoadSources(ini.LoadOptions{
		AllowBooleanKeys:        true,
		SkipUnrecognizableLines: true,
	}, []byte(content))
	if err != nil {
		return nil, fmt.Errorf("parse ini content: %w", err)
	}
	return cfg, nil
}

func (h *INIHandler) Merge(existing any, incoming any) (any, error) {
	dst, ok := existing.(*ini.File)
	if !ok {
		return nil, fmt.Errorf("existing: expected *ini.File, got %T", existing)
	}
	src, ok := incoming.(*ini.File)
	if !ok {
		return nil, fmt.Errorf("incoming: expected *ini.File, got %T", incoming)
	}

	// Iterate over all sections in incoming
	for _, srcSec := range src.Sections() {
		dstSec := dst.Section(srcSec.Name())

		// Iterate over all keys in the incoming section
		for _, srcKey := range srcSec.Keys() {
			if dstSec.HasKey(srcKey.Name()) {
				dstSec.Key(srcKey.Name()).SetValue(srcKey.Value())
			} else {
				dstSec.NewKey(srcKey.Name(), srcKey.Value())
			}
		}
	}

	return dst, nil
}

func (h *INIHandler) Write(path string, data any, perm os.FileMode) error {
	cfg, ok := data.(*ini.File)
	if !ok {
		return fmt.Errorf("expected *ini.File, got %T", data)
	}

	var buf bytes.Buffer
	if _, err := cfg.WriteTo(&buf); err != nil {
		return fmt.Errorf("marshal ini: %w", err)
	}

	return atomicWrite(path, buf.Bytes(), perm)
}
