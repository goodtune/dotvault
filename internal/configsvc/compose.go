// Package configsvc implements the dotvault-config service: layer
// composition, the HTTP API, the seed (config-as-code publish) path, and the
// service's own configuration. Layers are config.Partial documents stored
// under canonical keys and folded with config.MergePartial — the exact merge
// the client applies onto its base config, so the service composes precisely
// the way clients merge.
package configsvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/configsvc/store"
)

// ValidIdentitySegment reports whether a value is safe to embed as one
// segment of a layer key. The OS and user dimensions arrive as
// client-asserted headers on an unauthenticated endpoint, and the Vault
// store builds read paths with path.Join — which collapses ".." — so an
// unvalidated value like "../../users/alice/gh" would escape the service's
// layers/ namespace and probe arbitrary KVv2 paths reachable by the service
// token. Rejected: empty values, path separators, "..", and control
// characters. Anything else (spaces, unicode) is allowed — Windows account
// names legitimately contain spaces, and none of that enables traversal.
func ValidIdentitySegment(s string) bool {
	if s == "" || strings.Contains(s, "/") || strings.Contains(s, `\`) || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// LayerKeys returns the canonical composition order for a request identity:
// global → os/<os> → group/<g> (each, sorted) → user/<user>. Groups are
// sorted for determinism — the composed bytes must be stable so the ETag is
// stable. The OS value is lowercased; header values are client-asserted and
// arrive in whatever case the client chose. Callers are responsible for
// rejecting segments that fail ValidIdentitySegment before composing.
func LayerKeys(osName, user string, groups []string) []string {
	keys := make([]string, 0, len(groups)+3)
	keys = append(keys, "global", "os/"+strings.ToLower(osName))
	sorted := append([]string(nil), groups...)
	sort.Strings(sorted)
	for _, g := range sorted {
		keys = append(keys, "group/"+g)
	}
	return append(keys, "user/"+user)
}

// LayerError marks a present-but-unusable layer. The key is surfaced in the
// 500 response so the operator learns which layer to fix; a corrupt layer is
// never silently dropped (that would serve a silently wrong composition).
type LayerError struct {
	Key string
	Err error
}

func (e *LayerError) Error() string {
	return fmt.Sprintf("layer %q: %v", e.Key, e.Err)
}

func (e *LayerError) Unwrap() error {
	return e.Err
}

// Composer folds stored layers into the served document.
type Composer struct {
	Store store.Store
}

// Compose reads the given layer keys in order, parses and validates each
// present layer as a Partial, folds them with MergePartial, and returns the
// marshalled YAML document with its strong ETag (quoted sha256 of the
// bytes). Missing layers skip silently — an unknown user composes to
// global+os, which is valid. yaml.v3 marshals map keys in sorted order, so
// the bytes (and therefore the ETag) are deterministic for a given store
// state and identity.
func (c *Composer) Compose(ctx context.Context, keys []string) ([]byte, string, error) {
	var acc *config.Partial
	for _, key := range keys {
		raw, ok, err := c.Store.GetLayer(ctx, key)
		if err != nil {
			return nil, "", fmt.Errorf("read layer %q: %w", key, err)
		}
		if !ok {
			continue
		}
		p, err := config.ParsePartial(raw)
		if err != nil {
			return nil, "", &LayerError{Key: key, Err: err}
		}
		if err := p.Validate(); err != nil {
			return nil, "", &LayerError{Key: key, Err: err}
		}
		acc = config.MergePartial(acc, p)
	}
	if acc == nil {
		acc = &config.Partial{}
	}
	doc, err := yaml.Marshal(acc)
	if err != nil {
		return nil, "", fmt.Errorf("marshal composed document: %w", err)
	}
	sum := sha256.Sum256(doc)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	return doc, etag, nil
}
