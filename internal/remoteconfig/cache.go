package remoteconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// cacheSchema versions the envelope so a future shape change invalidates old
// caches instead of misparsing them.
const cacheSchema = 1

// envelope is the on-disk last-known-good record. Body is the raw document
// bytes exactly as served, so a 304 revalidation and a fetch-failure fallback
// both reparse what the service originally sent. Identity binds the entry to
// the (URL, dimension headers) tuple that produced it.
type envelope struct {
	Schema    int       `json:"schema"`
	URL       string    `json:"url"`
	Identity  string    `json:"identity"`
	ETag      string    `json:"etag,omitempty"`
	FetchedAt time.Time `json:"fetched_at"`
	Body      string    `json:"body"`
}

// readCache loads the envelope at path. A missing file, a schema from a
// different version, or an identity mismatch all return (nil, nil) — those
// are "no usable cache", not errors. Only an unreadable or unparseable file
// is an error, and callers treat that as no-cache too (after logging).
func readCache(path, identity string) (*envelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read cache: %w", err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse cache: %w", err)
	}
	if env.Schema != cacheSchema || env.Identity != identity {
		return nil, nil
	}
	return &env, nil
}

// writeCache persists the envelope atomically (temp file + rename, the same
// pattern as the sync engine's state.json). os.CreateTemp creates the file
// 0600, so the rename target keeps owner-only permissions.
func writeCache(path string, env envelope) error {
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".remote-config-*")
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
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename cache file: %w", err)
	}
	return nil
}
