package handlers

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// YAMLHandler handles YAML files with deep merge using yaml.Node trees.
type YAMLHandler struct {
	// DeleteNulls makes a null in the incoming document a tombstone: the
	// matching key/value pair is spliced out of the target's mapping node
	// rather than written as null. See config.Target.DeleteNulls for why it
	// is opt-in — YAML in particular renders a null from an empty template
	// value (`key: {{ .missing }}` becomes `key:`), so always-on deletion
	// here would be actively dangerous.
	DeleteNulls bool
}

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
		// The incoming document is adopted wholesale rather than merged
		// key-by-key, so tombstones in it are never matched against anything
		// and would otherwise be written out as literal nulls.
		pruneNullNodes(incDoc, h.DeleteNulls)
		return incDoc, nil
	}
	// Empty incoming — return existing unchanged
	if len(incDoc.Content) == 0 {
		return existDoc, nil
	}

	// A tombstone promises the key is gone from the file. YAML has three
	// features that can make that promise false or destructive, and none can
	// be honoured by a key-name comparison, so a document using any of them
	// is refused outright rather than half-deleted:
	//
	//   - a merge key (`<<: *base`) can supply the key from another mapping,
	//     so splicing the literal pair — or finding none to splice — leaves
	//     the value in effect while reporting success;
	//   - an anchor on a mapping means the pair is shared, so removing it
	//     deletes from every alias site, not just the one addressed;
	//   - removing a pair that carries an anchor still referenced elsewhere
	//     leaves a dangling alias, corrupting the file on the next parse.
	//
	// The check runs only when a deletion is actually about to happen, so a
	// rule whose template renders no tombstone this pass is unaffected.
	if h.DeleteNulls && hasTombstone(incDoc) {
		if feature, unsafe := unsafeForDeletion(existDoc); unsafe {
			return nil, fmt.Errorf("delete_nulls cannot guarantee removal from a YAML file containing %s: a key may be inherited or shared rather than written literally, so deleting it here would either leave the value in effect or corrupt an alias elsewhere", feature)
		}
	}

	mergeNodes(existDoc.Content[0], incDoc.Content[0], h.DeleteNulls)
	return existDoc, nil
}

// hasTombstone reports whether n contains at least one null-valued mapping
// pair — that is, whether this merge would delete anything.
func hasTombstone(n *yaml.Node) bool {
	if n == nil {
		return false
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if isNullNode(n.Content[i+1]) {
				return true
			}
		}
	}
	for _, child := range n.Content {
		if hasTombstone(child) {
			return true
		}
	}
	return false
}

// unsafeForDeletion reports whether n uses a YAML feature that makes
// delete-by-key-name unsound, naming the feature for the error message.
// See the call site in Merge for why each is disqualifying.
func unsafeForDeletion(n *yaml.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	if n.Kind == yaml.AliasNode {
		return "an alias", true
	}
	if n.Anchor != "" {
		return "an anchor", true
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "<<" {
				return "a merge key (<<)", true
			}
		}
	}
	for _, child := range n.Content {
		if feature, unsafe := unsafeForDeletion(child); unsafe {
			return feature, true
		}
	}
	return "", false
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
//
// When deleteNulls is set, a null value in src is a tombstone rather than a
// value: the whole key/value pair is spliced out of dst instead of written.
// Splicing a key dst does not have is a no-op, so a tombstone left in a
// template indefinitely keeps producing an unchanged file.
func mergeNodes(dst, src *yaml.Node, deleteNulls bool) {
	if dst.Kind != yaml.MappingNode || src.Kind != yaml.MappingNode {
		// Replace entirely for non-mapping nodes
		pruneNullNodes(src, deleteNulls)
		*dst = *src
		return
	}

	// Iterate over src key/value pairs. The bound guards the value index
	// rather than the key index, matching pruneNullNodes: a well-formed
	// mapping always has even Content, and an orphan trailing key is dropped
	// rather than panicking.
	for i := 0; i+1 < len(src.Content); i += 2 {
		srcKey := src.Content[i]
		srcVal := src.Content[i+1]

		if deleteNulls && isNullNode(srcVal) {
			// Every matching pair goes, not just the first. yaml.v3 does not
			// reject duplicate keys, and most consumers take the *last*
			// occurrence — so stopping at the first match would report a
			// deletion while leaving the value that actually gets read.
			kept := dst.Content[:0]
			for j := 0; j+1 < len(dst.Content); j += 2 {
				if dst.Content[j].Value == srcKey.Value {
					continue
				}
				kept = append(kept, dst.Content[j], dst.Content[j+1])
			}
			dst.Content = kept
			continue
		}

		found := false
		for j := 0; j+1 < len(dst.Content); j += 2 {
			dstKey := dst.Content[j]
			if dstKey.Value == srcKey.Value {
				// Key exists — recurse if both values are mappings, else replace
				if dst.Content[j+1].Kind == yaml.MappingNode && srcVal.Kind == yaml.MappingNode {
					mergeNodes(dst.Content[j+1], srcVal, deleteNulls)
				} else {
					pruneNullNodes(srcVal, deleteNulls)
					dst.Content[j+1] = srcVal
				}
				found = true
				break
			}
		}

		if !found {
			// srcVal is adopted rather than merged, so any tombstone nested
			// inside it has nothing to match and must be dropped rather than
			// written out as a literal null.
			pruneNullNodes(srcVal, deleteNulls)
			dst.Content = append(dst.Content, srcKey, srcVal)
		}
	}
}

// isNullNode reports whether n is a YAML null. This covers every spelling the
// parser resolves to the null tag — `key: null`, `key: ~`, and the bare
// `key:` an empty template substitution produces — so all three behave
// identically as tombstones.
func isNullNode(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.ScalarNode && n.Tag == "!!null"
}

// pruneNullNodes recursively strips null-valued pairs from mapping nodes,
// for src subtrees that are adopted into dst wholesale instead of merged
// key-by-key. It is the yaml.Node counterpart of pruneNullsJSON.
func pruneNullNodes(n *yaml.Node, deleteNulls bool) {
	if !deleteNulls || n == nil {
		return
	}
	switch n.Kind {
	case yaml.DocumentNode:
		for _, child := range n.Content {
			pruneNullNodes(child, deleteNulls)
		}
	// Sequences are deliberately not descended into. The merge replaces
	// arrays wholesale rather than merging into them, so there is nothing
	// inside one for a tombstone to remove — stripping keys from a sequence
	// element would silently mutate data the template author wrote, and would
	// diverge from the JSON handler, which treats arrays as opaque values.
	case yaml.MappingNode:
		kept := n.Content[:0]
		for i := 0; i+1 < len(n.Content); i += 2 {
			if isNullNode(n.Content[i+1]) {
				continue
			}
			pruneNullNodes(n.Content[i+1], deleteNulls)
			kept = append(kept, n.Content[i], n.Content[i+1])
		}
		n.Content = kept
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
