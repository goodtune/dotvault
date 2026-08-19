package vaultfs

import (
	"context"
	"errors"
	"maps"
	"sort"
	"strings"
	"sync"
	"time"
)

// memStore is an in-memory Store standing in for Vault. It reproduces the two
// KVv2 behaviours the tree depends on: a LIST returns immediate children with
// folders suffixed by "/", and a read of a missing path is (nil, nil) rather
// than an error.
type memStore struct {
	mu sync.Mutex

	// secrets maps a relative path to its data.
	secrets map[string]map[string]any
	// created maps a relative path to its version's created_time.
	created map[string]time.Time
	// version maps a relative path to its KVv2 version.
	version map[string]int

	// listErr, if set, is returned by every List — the "policy grants read
	// but not list" case the tree is expected to degrade through.
	listErr error
	// readErr, writeErr and deleteErr do the same for the other operations.
	readErr, writeErr, deleteErr error

	// counters record how often each operation reached the store, which is
	// how the cache's behaviour is observed.
	lists, reads, writes, deletes int
}

func newMemStore() *memStore {
	return &memStore{
		secrets: map[string]map[string]any{},
		created: map[string]time.Time{},
		version: map[string]int{},
	}
}

// put seeds a secret without going through the Store interface, so tests can
// set up state that a read-only tree could never create.
func (m *memStore) put(path string, data map[string]any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[path] = maps.Clone(data)
	m.version[path]++
	if _, ok := m.created[path]; !ok {
		m.created[path] = time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC)
	}
}

func (m *memStore) counts() (lists, reads, writes, deletes int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lists, m.reads, m.writes, m.deletes
}

func (m *memStore) List(ctx context.Context, relPath string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lists++
	if m.listErr != nil {
		return nil, m.listErr
	}
	prefix := ""
	if relPath != "" {
		prefix = relPath + "/"
	}
	seen := map[string]bool{}
	var out []string
	for p := range m.secrets {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		rest := p[len(prefix):]
		if rest == "" {
			continue
		}
		name := rest
		if i := strings.Index(rest, "/"); i >= 0 {
			name = rest[:i] + "/"
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *memStore) Read(ctx context.Context, relPath string) (*Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	if m.readErr != nil {
		return nil, m.readErr
	}
	data, ok := m.secrets[relPath]
	if !ok {
		return nil, nil
	}
	return &Secret{
		Data:        maps.Clone(data),
		Version:     m.version[relPath],
		CreatedTime: m.created[relPath],
	}, nil
}

func (m *memStore) Write(ctx context.Context, relPath string, data map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writes++
	if m.writeErr != nil {
		return m.writeErr
	}
	m.secrets[relPath] = maps.Clone(data)
	m.version[relPath]++
	m.created[relPath] = time.Date(2026, 8, 19, 11, 0, 0, 0, time.UTC)
	return nil
}

func (m *memStore) Delete(ctx context.Context, relPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.secrets, relPath)
	delete(m.created, relPath)
	delete(m.version, relPath)
	return nil
}

var errDenied = errors.New("permission denied")
