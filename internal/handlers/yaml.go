package handlers

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// YAMLHandler handles YAML files with deep merge using yaml.Node trees.
type YAMLHandler struct{}

func (h *YAMLHandler) Read(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return emptyYAMLDoc(), nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		return emptyYAMLDoc(), nil
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse yaml %s: %w", path, err)
	}
	return &doc, nil
}

func (h *YAMLHandler) Parse(content string) (any, error) {
	if content == "" {
		return emptyYAMLDoc(), nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil, fmt.Errorf("parse yaml content: %w", err)
	}
	return &doc, nil
}

func (h *YAMLHandler) Merge(existing any, incoming any) (any, error) {
	existDoc, ok := existing.(*yaml.Node)
	if !ok {
		return nil, fmt.Errorf("existing: expected *yaml.Node, got %T", existing)
	}
	incDoc, ok := incoming.(*yaml.Node)
	if !ok {
		return nil, fmt.Errorf("incoming: expected *yaml.Node, got %T", incoming)
	}

	// Both should be DocumentNodes wrapping the actual content
	if existDoc.Kind != yaml.DocumentNode || incDoc.Kind != yaml.DocumentNode {
		return nil, fmt.Errorf("expected DocumentNode, got kinds %d and %d", existDoc.Kind, incDoc.Kind)
	}

	// Empty existing doc — just return incoming
	if len(existDoc.Content) == 0 {
		return incDoc, nil
	}
	// Empty incoming — return existing unchanged
	if len(incDoc.Content) == 0 {
		return existDoc, nil
	}

	mergeNodes(existDoc.Content[0], incDoc.Content[0])
	return existDoc, nil
}

func (h *YAMLHandler) Write(path string, data any, perm os.FileMode) error {
	doc, ok := data.(*yaml.Node)
	if !ok {
		return fmt.Errorf("expected *yaml.Node, got %T", data)
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}
	enc.Close()

	return atomicWrite(path, buf.Bytes(), perm)
}

// mergeNodes recursively merges src into dst.
// For MappingNodes: add/update keys from src, preserve existing keys not in src.
// For other node types: replace dst with src.
func mergeNodes(dst, src *yaml.Node) {
	if dst.Kind != yaml.MappingNode || src.Kind != yaml.MappingNode {
		// Replace entirely for non-mapping nodes
		*dst = *src
		return
	}

	// Iterate over src key/value pairs
	for i := 0; i < len(src.Content); i += 2 {
		srcKey := src.Content[i]
		srcVal := src.Content[i+1]

		found := false
		for j := 0; j < len(dst.Content); j += 2 {
			dstKey := dst.Content[j]
			if dstKey.Value == srcKey.Value {
				// Key exists — recurse if both values are mappings, else replace
				if dst.Content[j+1].Kind == yaml.MappingNode && srcVal.Kind == yaml.MappingNode {
					mergeNodes(dst.Content[j+1], srcVal)
				} else {
					dst.Content[j+1] = srcVal
				}
				found = true
				break
			}
		}

		if !found {
			dst.Content = append(dst.Content, srcKey, srcVal)
		}
	}
}

func emptyYAMLDoc() *yaml.Node {
	return &yaml.Node{
		Kind: yaml.DocumentNode,
	}
}

// atomicWrite writes data to a temp file then renames for atomic replacement.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".dotvault-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}
