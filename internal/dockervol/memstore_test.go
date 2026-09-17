package dockervol

import (
	"context"
	"maps"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
	"github.com/goodtune/dotvault/internal/vaultfs"
)

// memStore is an in-memory vaultfs.Store: LIST returns immediate children
// with folders suffixed "/", and a missing path reads as (nil, nil).
type memStore struct {
	mu      sync.Mutex
	secrets map[string]map[string]any
	version map[string]int
	listErr error
	readErr error
	reads   int
	lists   int
}

func newMemStore() *memStore {
	return &memStore{secrets: map[string]map[string]any{}, version: map[string]int{}}
}

func (m *memStore) put(path string, data map[string]any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[path] = maps.Clone(data)
	m.version[path]++
}

func (m *memStore) remove(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.secrets, path)
}

func (m *memStore) counts() (reads, lists int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reads, m.lists
}

func (m *memStore) setErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listErr, m.readErr = err, err
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

func (m *memStore) Read(ctx context.Context, relPath string) (*vaultfs.Secret, error) {
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
	return &vaultfs.Secret{
		Data:        maps.Clone(data),
		Version:     m.version[relPath],
		CreatedTime: time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC),
	}, nil
}

func (m *memStore) Write(ctx context.Context, relPath string, data map[string]any) error {
	m.put(relPath, data)
	return nil
}

func (m *memStore) Delete(ctx context.Context, relPath string) error {
	m.remove(relPath)
	return nil
}

// fakeEvents is an EventSource whose edition and stream the test controls.
type fakeEvents struct {
	mu         sync.Mutex
	enterprise bool
	healthErr  error
	subErr     error
	subscribes int
	evCh       chan vault.Event
	errCh      chan error
}

func (f *fakeEvents) ServerHealth(ctx context.Context) (*vault.HealthResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.healthErr != nil {
		return nil, f.healthErr
	}
	return &vault.HealthResponse{Enterprise: f.enterprise}, nil
}

func (f *fakeEvents) SubscribeEvents(ctx context.Context, eventType string) (<-chan vault.Event, <-chan error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subscribes++
	if f.subErr != nil {
		return nil, nil, f.subErr
	}
	f.evCh = make(chan vault.Event, 16)
	f.errCh = make(chan error, 1)
	return f.evCh, f.errCh, nil
}

func (f *fakeEvents) subscribed() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.subscribes
}

func (f *fakeEvents) send(evt vault.Event) {
	f.mu.Lock()
	ch := f.evCh
	f.mu.Unlock()
	ch <- evt
}

// drop ends the current stream with an error, as a closed WebSocket would.
func (f *fakeEvents) drop(err error) {
	f.mu.Lock()
	ch := f.errCh
	f.mu.Unlock()
	ch <- err
}
