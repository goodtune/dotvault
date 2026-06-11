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
// backend on merge. The layout is global.yaml, os/<os>.yaml,
// group/<g>.yaml, user/<u>.yaml, plus an optional groups.yaml carrying
// static membership (user → group list). Everything is validated before
// any write, so an invalid layer aborts the whole publish with nothing
// written. (A backend failure mid-publish can still leave earlier writes
// applied — re-running the seed converges, since writes are idempotent
// puts.) Stray YAML files and unknown subdirectories are errors — a typo'd
// directory silently not being served is the failure mode this guards
// against.
func Seed(ctx context.Context, st store.Store, dir string) (*SeedSummary, error) {
	layers, membership, err := loadSeedDir(dir)
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

// seedSubdirs maps the recognised layer subdirectories to their key prefix.
var seedSubdirs = map[string]bool{"os": true, "group": true, "user": true}

// loadSeedDir reads and validates the whole seed directory without writing
// anything. Layers come back in deterministic order: global first, then the
// remaining keys sorted.
func loadSeedDir(dir string) ([]seedLayer, map[string][]string, error) {
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
			if !seedSubdirs[name] {
				if hasYAML(full) {
					return nil, nil, fmt.Errorf("unexpected directory %s: layer subdirectories are os/, group/, and user/", full)
				}
				continue
			}
			sub, err := loadSeedSubdir(full, name)
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

func loadSeedSubdir(dir, prefix string) ([]seedLayer, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	var layers []seedLayer
	for _, entry := range entries {
		name := entry.Name()
		full := filepath.Join(dir, name)
		if entry.IsDir() {
			if hasYAML(full) {
				return nil, fmt.Errorf("unexpected nested directory %s: layer keys are one level deep", full)
			}
			continue
		}
		if !isYAML(name) {
			continue
		}
		key := prefix + "/" + trimYAMLExt(name)
		if err := ValidLayerKey(key); err != nil {
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

func hasYAML(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() && isYAML(entry.Name()) {
			return true
		}
	}
	return false
}
