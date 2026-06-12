package configsvc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/configsvc/store"
)

// SeedSummary reports what a Seed run wrote.
type SeedSummary struct {
	// Layers are the layer keys written, in write order.
	Layers []string
	// Users are the usernames whose static group membership was written.
	Users []string
}

// Seed publishes a directory of layer YAMLs into the store — the
// config-as-code path: layers live in a git repository and CI seeds the
// backend on merge. The layout mirrors the layer-key grammar: global.yaml,
// an optional groups.yaml (static membership, user → group list), and one
// directory per kind, nested one level per dimension value:
//
//	global.yaml
//	groups.yaml
//	os/linux.yaml                 → os/linux
//	group/sydney.yaml             → group/sydney
//	os+group/linux/sydney.yaml    → os+group/linux/sydney
//
// Every document is validated before any write — including that each
// layer's kind appears in the composition order, so a layer that would
// never be served is refused at publish time. An invalid layer aborts the
// whole publish with nothing written. (A backend failure mid-publish can
// still leave earlier writes applied — re-running the seed converges, since
// writes are idempotent puts.) Stray YAML files and unknown directories are
// errors — a typo'd directory silently not being served is the failure mode
// this guards against.
func Seed(ctx context.Context, st store.Store, dir string, comp *Composition) (*SeedSummary, error) {
	if comp == nil {
		comp = DefaultComposition()
	}
	layers, membership, err := loadSeedDir(dir, comp)
	if err != nil {
		return nil, err
	}

	summary := &SeedSummary{}
	for _, l := range layers {
		if err := st.PutLayer(ctx, l.key, l.doc); err != nil {
			return nil, fmt.Errorf("write layer %q: %w", l.key, err)
		}
		summary.Layers = append(summary.Layers, l.key)
	}
	users := make([]string, 0, len(membership))
	for user := range membership {
		users = append(users, user)
	}
	sort.Strings(users)
	for _, user := range users {
		if err := st.PutGroups(ctx, user, membership[user]); err != nil {
			return nil, fmt.Errorf("write groups for %q: %w", user, err)
		}
		summary.Users = append(summary.Users, user)
	}
	return summary, nil
}

type seedLayer struct {
	key string
	doc []byte
}

// loadSeedDir reads and validates the whole seed directory without writing
// anything. Layers come back in deterministic order: global first, then the
// remaining keys sorted.
func loadSeedDir(dir string, comp *Composition) ([]seedLayer, map[string][]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("read seed directory: %w", err)
	}

	var layers []seedLayer
	membership := map[string][]string{}
	for _, entry := range entries {
		name := entry.Name()
		full := filepath.Join(dir, name)
		if entry.IsDir() {
			kind, kerr := ParseKind(name)
			if kerr != nil || len(kind) == 0 {
				if hasYAMLDeep(full) {
					return nil, nil, fmt.Errorf("unexpected directory %s: layer directories are named after a kind (os, group, device, user, or a canonical combination like os+group)", full)
				}
				continue
			}
			sub, err := loadKindLevel(full, kind, comp, nil)
			if err != nil {
				return nil, nil, err
			}
			layers = append(layers, sub...)
			continue
		}
		if !isYAML(name) {
			continue
		}
		switch trimYAMLExt(name) {
		case "global":
			if err := comp.AllowsKey("global"); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", full, err)
			}
			l, err := loadLayerFile(full, "global")
			if err != nil {
				return nil, nil, err
			}
			layers = append(layers, l)
		case "groups":
			raw, err := os.ReadFile(full)
			if err != nil {
				return nil, nil, fmt.Errorf("read %s: %w", full, err)
			}
			if err := yaml.Unmarshal(raw, &membership); err != nil {
				return nil, nil, fmt.Errorf("parse %s: %w", full, err)
			}
		default:
			return nil, nil, fmt.Errorf("unexpected file %s: top-level layer files are global.yaml and groups.yaml", full)
		}
	}

	sort.Slice(layers, func(i, j int) bool {
		// global sorts before everything; the rest lexicographically.
		if layers[i].key == "global" || layers[j].key == "global" {
			return layers[i].key == "global"
		}
		return layers[i].key < layers[j].key
	})
	return layers, membership, nil
}

// loadKindLevel walks one value level of a kind directory: intermediate
// levels hold one directory per dimension value, and the final level holds
// <value>.yaml files. A layer file at the wrong depth is an error, never
// silently skipped.
func loadKindLevel(dir string, kind Kind, comp *Composition, values []string) ([]seedLayer, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	last := len(values) == len(kind)-1
	var layers []seedLayer
	for _, entry := range entries {
		name := entry.Name()
		full := filepath.Join(dir, name)
		if entry.IsDir() {
			if last {
				if hasYAMLDeep(full) {
					return nil, fmt.Errorf("unexpected directory %s: kind %q takes %d value level(s)", full, kind.String(), len(kind))
				}
				continue
			}
			// Copy before extending: append on the shared slice would let
			// sibling iterations scribble over each other's backing array.
			next := append(append([]string{}, values...), name)
			sub, err := loadKindLevel(full, kind, comp, next)
			if err != nil {
				return nil, err
			}
			layers = append(layers, sub...)
			continue
		}
		if !isYAML(name) {
			continue
		}
		if !last {
			return nil, fmt.Errorf("unexpected file %s: kind %q expects %d value level(s), so layer files belong %d directory level(s) deeper", full, kind.String(), len(kind), len(kind)-1-len(values))
		}
		key := kind.String() + "/" + strings.Join(append(values, trimYAMLExt(name)), "/")
		if err := ValidLayerKey(key); err != nil {
			return nil, fmt.Errorf("%s: %w", full, err)
		}
		if err := comp.AllowsKey(key); err != nil {
			return nil, fmt.Errorf("%s: %w", full, err)
		}
		l, err := loadLayerFile(full, key)
		if err != nil {
			return nil, err
		}
		layers = append(layers, l)
	}
	return layers, nil
}

// loadLayerFile reads a layer document and validates it exactly the way the
// serve path will: ParsePartial (static-section rejection, case checks) plus
// per-entry Validate.
func loadLayerFile(path, key string) (seedLayer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return seedLayer{}, fmt.Errorf("read %s: %w", path, err)
	}
	p, err := config.ParsePartial(raw)
	if err != nil {
		return seedLayer{}, fmt.Errorf("layer %q (%s): %w", key, path, err)
	}
	if err := p.Validate(); err != nil {
		return seedLayer{}, fmt.Errorf("layer %q (%s): %w", key, path, err)
	}
	return seedLayer{key: key, doc: raw}, nil
}

// isYAML matches the extension case-insensitively so a Global.YAML on a
// case-insensitive filesystem is recognised (and then caught by the
// stray-file guard) rather than silently skipped.
func isYAML(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml"
}

func trimYAMLExt(name string) string {
	return strings.TrimSuffix(name, filepath.Ext(name))
}

// hasYAMLDeep reports whether any YAML file exists under dir, at any depth.
func hasYAMLDeep(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			if hasYAMLDeep(filepath.Join(dir, entry.Name())) {
				return true
			}
			continue
		}
		if isYAML(entry.Name()) {
			return true
		}
	}
	return false
}
