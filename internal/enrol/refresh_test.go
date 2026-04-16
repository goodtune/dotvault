package enrol

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
)

// fakeRefresher is a Refresher test double whose Refresh implementation
// is controlled per-call via a channel of responses.
type fakeRefresher struct {
	name   string
	fields []string

	mu       sync.Mutex
	calls    []fakeRefresherCall
	response func(call fakeRefresherCall) (map[string]string, error)
}

type fakeRefresherCall struct {
	Settings map[string]any
	Existing map[string]string
}

func (f *fakeRefresher) Name() string     { return f.name }
func (f *fakeRefresher) Fields() []string { return f.fields }
func (f *fakeRefresher) Run(ctx context.Context, settings map[string]any, io IO) (map[string]string, error) {
	return nil, errors.New("fakeRefresher.Run should not be called in these tests")
}
func (f *fakeRefresher) Refresh(ctx context.Context, settings map[string]any, existing map[string]string) (map[string]string, error) {
	f.mu.Lock()
	call := fakeRefresherCall{Settings: settings, Existing: copyMap(existing)}
	f.calls = append(f.calls, call)
	resp := f.response
	f.mu.Unlock()
	if resp == nil {
		return nil, errors.New("fakeRefresher has no response configured")
	}
	return resp(call)
}

func (f *fakeRefresher) Calls() []fakeRefresherCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeRefresherCall, len(f.calls))
	copy(out, f.calls)
	return out
}

func copyMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// fakeVault is a minimal stand-in for Vault's KV-v2 HTTP API. It stores
// secrets in-memory keyed by the KV mount path and supports read, write,
// and delete-metadata operations, which is everything the RefreshManager
// exercises.
type fakeVault struct {
	mu      sync.Mutex
	mount   string                       // e.g. "kv"
	secrets map[string]map[string]string // path -> data
	writes  []fakeVaultWrite
	deletes []string
	// When non-zero, DELETE on the metadata endpoint returns this status
	// code and leaves the secret in place. Used to exercise the
	// refresh-manager's revocation-cleanup-failure path.
	deleteStatus int
}

type fakeVaultWrite struct {
	Path string
	Data map[string]string
}

func newFakeVault(mount string) *fakeVault {
	return &fakeVault{mount: mount, secrets: map[string]map[string]string{}}
}

// serve returns an httptest.Server speaking a KVv2 subset for this fake.
func (fv *fakeVault) serve(t *testing.T) *vault.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(fv.handle))
	t.Cleanup(srv.Close)
	vc, err := vault.NewClient(vault.Config{Address: srv.URL})
	if err != nil {
		t.Fatalf("vault.NewClient: %v", err)
	}
	vc.SetToken("root") // token value is irrelevant for the fake
	return vc
}

func (fv *fakeVault) handle(w http.ResponseWriter, r *http.Request) {
	// KVv2 data path: /v1/<mount>/data/<path>
	// KVv2 metadata path: /v1/<mount>/metadata/<path>
	dataPrefix := "/v1/" + fv.mount + "/data/"
	metaPrefix := "/v1/" + fv.mount + "/metadata/"

	switch {
	case strings.HasPrefix(r.URL.Path, dataPrefix):
		path := strings.TrimPrefix(r.URL.Path, dataPrefix)
		switch r.Method {
		case http.MethodGet:
			fv.mu.Lock()
			data, ok := fv.secrets[path]
			fv.mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			body, _ := json.Marshal(map[string]any{
				"data": map[string]any{
					"data":     stringMapToAny(data),
					"metadata": map[string]any{"version": 1},
				},
			})
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		case http.MethodPost, http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Data map[string]any `json:"data"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			data := make(map[string]string, len(req.Data))
			for k, v := range req.Data {
				if s, ok := v.(string); ok {
					data[k] = s
				}
			}
			fv.mu.Lock()
			fv.secrets[path] = data
			fv.writes = append(fv.writes, fakeVaultWrite{Path: path, Data: copyMap(data)})
			fv.mu.Unlock()
			_, _ = w.Write([]byte(`{"data":{"version":1}}`))
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case strings.HasPrefix(r.URL.Path, metaPrefix):
		path := strings.TrimPrefix(r.URL.Path, metaPrefix)
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		fv.mu.Lock()
		status := fv.deleteStatus
		fv.mu.Unlock()
		if status != 0 {
			http.Error(w, "delete refused by fake", status)
			return
		}
		fv.mu.Lock()
		delete(fv.secrets, path)
		fv.deletes = append(fv.deletes, path)
		fv.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func stringMapToAny(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (fv *fakeVault) seed(path string, data map[string]string) {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	fv.secrets[path] = copyMap(data)
}

func (fv *fakeVault) secret(path string) map[string]string {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	if s, ok := fv.secrets[path]; ok {
		return copyMap(s)
	}
	return nil
}

func (fv *fakeVault) deleted() []string {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	out := make([]string, len(fv.deletes))
	copy(out, fv.deletes)
	return out
}

// fixedClock is a deterministic Clock that returns a pinned time.
type fixedClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fixedClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// registerFake installs a fakeRefresher in the engine registry under the
// given engine name and arranges for teardown when the test finishes.
func registerFake(t *testing.T, engineName string, f *fakeRefresher) {
	t.Helper()
	RegisterEngine(engineName, f)
	t.Cleanup(func() { UnregisterEngine(engineName) })
}

// ---------- tick(): happy / skip paths ----------

func TestRefreshManager_SkipsWhenNoExpiresAt(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)

	issued := time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC)
	// Legacy secret: no expires_at / issued_at fields at all.
	fv.seed("users/alice/legacy", map[string]string{
		"access_token":  "a",
		"refresh_token": "r",
	})

	fake := &fakeRefresher{name: "legacy-engine", fields: []string{"access_token"}}
	fake.response = func(fakeRefresherCall) (map[string]string, error) {
		return nil, errors.New("should not be called for legacy secrets")
	}
	registerFake(t, "legacy-engine", fake)

	m := NewRefreshManager(vc, "kv", "users/alice/", map[string]config.Enrolment{
		"legacy": {Engine: "legacy-engine"},
	}, time.Hour,
		WithClock(&fixedClock{now: issued.Add(48 * time.Hour)}),
	)
	m.tick(context.Background())

	if got := len(fake.Calls()); got != 0 {
		t.Errorf("fake.Calls() = %d, want 0 (legacy secrets must be skipped)", got)
	}
}

func TestRefreshManager_SkipsBeforeHalfLife(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)

	issued := time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC)
	expires := issued.Add(6 * time.Hour)
	fv.seed("users/alice/jfrog", map[string]string{
		"access_token":  "a",
		"refresh_token": "r",
		"issued_at":     issued.Format(time.RFC3339),
		"expires_at":    expires.Format(time.RFC3339),
	})

	fake := &fakeRefresher{name: "jfrog", fields: []string{"access_token"}}
	fake.response = func(fakeRefresherCall) (map[string]string, error) {
		return nil, errors.New("should not be called before half-life")
	}
	registerFake(t, "jfrog-fake", fake)

	// Now is 1h in — well before the 3h half-life.
	m := NewRefreshManager(vc, "kv", "users/alice/", map[string]config.Enrolment{
		"jfrog": {Engine: "jfrog-fake"},
	}, time.Hour,
		WithClock(&fixedClock{now: issued.Add(1 * time.Hour)}),
	)
	m.tick(context.Background())

	if got := len(fake.Calls()); got != 0 {
		t.Errorf("fake.Calls() = %d, want 0 (pre-half-life must be skipped)", got)
	}
}

func TestRefreshManager_RotatesPastHalfLife(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)

	issued := time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC)
	expires := issued.Add(6 * time.Hour)
	fv.seed("users/alice/jfrog", map[string]string{
		"access_token":  "old-a",
		"refresh_token": "old-r",
		"url":           "http://jf",
		"server_id":     "jf",
		"user":          "alice",
		"issued_at":     issued.Format(time.RFC3339),
		"expires_at":    expires.Format(time.RFC3339),
	})

	newIssued := issued.Add(4 * time.Hour)
	newExpires := newIssued.Add(6 * time.Hour)
	fake := &fakeRefresher{name: "jfrog", fields: []string{"access_token"}}
	fake.response = func(call fakeRefresherCall) (map[string]string, error) {
		if call.Existing["access_token"] != "old-a" {
			return nil, errors.New("engine saw wrong access_token")
		}
		if call.Existing["refresh_token"] != "old-r" {
			return nil, errors.New("engine saw wrong refresh_token")
		}
		return map[string]string{
			"access_token":  "new-a",
			"refresh_token": "new-r",
			"url":           "http://jf",
			"server_id":     "jf",
			"user":          "alice",
			"issued_at":     newIssued.Format(time.RFC3339),
			"expires_at":    newExpires.Format(time.RFC3339),
		}, nil
	}
	registerFake(t, "jfrog-fake", fake)

	// Now is 4h in — past the 3h half-life.
	m := NewRefreshManager(vc, "kv", "users/alice/", map[string]config.Enrolment{
		"jfrog": {Engine: "jfrog-fake"},
	}, time.Hour,
		WithClock(&fixedClock{now: newIssued}),
	)
	m.tick(context.Background())

	calls := fake.Calls()
	if len(calls) != 1 {
		t.Fatalf("fake.Calls() = %d, want 1", len(calls))
	}

	got := fv.secret("users/alice/jfrog")
	if got["access_token"] != "new-a" {
		t.Errorf("vault access_token = %q, want new-a", got["access_token"])
	}
	if got["refresh_token"] != "new-r" {
		t.Errorf("vault refresh_token = %q, want new-r", got["refresh_token"])
	}
	if got["issued_at"] != newIssued.Format(time.RFC3339) {
		t.Errorf("vault issued_at = %q, want %q", got["issued_at"], newIssued.Format(time.RFC3339))
	}
}

func TestRefreshManager_ErrRevokedWipesSecret(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)

	issued := time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC)
	expires := issued.Add(6 * time.Hour)
	fv.seed("users/alice/jfrog", map[string]string{
		"access_token":  "a",
		"refresh_token": "r",
		"issued_at":     issued.Format(time.RFC3339),
		"expires_at":    expires.Format(time.RFC3339),
	})

	fake := &fakeRefresher{name: "jfrog", fields: []string{"access_token"}}
	fake.response = func(fakeRefresherCall) (map[string]string, error) { return nil, ErrRevoked }
	registerFake(t, "jfrog-fake", fake)

	m := NewRefreshManager(vc, "kv", "users/alice/", map[string]config.Enrolment{
		"jfrog": {Engine: "jfrog-fake"},
	}, time.Hour,
		WithClock(&fixedClock{now: issued.Add(4 * time.Hour)}),
	)
	m.tick(context.Background())

	if got := fv.secret("users/alice/jfrog"); got != nil {
		t.Errorf("secret still present after ErrRevoked: %v", got)
	}
	deleted := fv.deleted()
	if len(deleted) != 1 || deleted[0] != "users/alice/jfrog" {
		t.Errorf("deleted = %v, want [users/alice/jfrog]", deleted)
	}
}

func TestRefreshManager_MalformedSecretBumpsBackoff(t *testing.T) {
	// A secret that has expires_at but is otherwise malformed (missing
	// issued_at, unparseable RFC3339, etc.) must bump backoff so the ERROR
	// doesn't re-log every tick.
	cases := []struct {
		name string
		data map[string]string
	}{
		{
			name: "MissingIssuedAt",
			data: map[string]string{
				"access_token":  "a",
				"refresh_token": "r",
				"expires_at":    "2026-04-17T12:00:00Z",
				// issued_at absent
			},
		},
		{
			name: "BadExpiresAt",
			data: map[string]string{
				"access_token":  "a",
				"refresh_token": "r",
				"issued_at":     "2026-04-17T00:00:00Z",
				"expires_at":    "not-an-rfc3339-timestamp",
			},
		},
		{
			name: "BadIssuedAt",
			data: map[string]string{
				"access_token":  "a",
				"refresh_token": "r",
				"issued_at":     "not-an-rfc3339-timestamp",
				"expires_at":    "2026-04-17T12:00:00Z",
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fv := newFakeVault("kv")
			vc := fv.serve(t)
			fv.seed("users/alice/jfrog", tc.data)

			fake := &fakeRefresher{name: "jfrog", fields: []string{"access_token"}}
			fake.response = func(fakeRefresherCall) (map[string]string, error) {
				return nil, errors.New("should not be called for malformed secret")
			}
			registerFake(t, "jfrog-fake", fake)

			m := NewRefreshManager(vc, "kv", "users/alice/", map[string]config.Enrolment{
				"jfrog": {Engine: "jfrog-fake"},
			}, 10*time.Second,
				WithClock(&fixedClock{now: time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC)}),
			)
			m.tick(context.Background())

			m.mu.Lock()
			b := m.backoffs["jfrog"]
			m.mu.Unlock()
			if b.delay == 0 {
				t.Errorf("backoff delay should be set after malformed-secret skip, got %v", b)
			}
		})
	}
}

func TestRefreshManager_ErrRevokedDeleteFailureBumpsBackoff(t *testing.T) {
	// If the Vault cleanup for a revoked credential fails, the manager
	// must NOT clear backoff — otherwise the next tick re-calls Refresh
	// against a known-revoked token every cycle.
	fv := newFakeVault("kv")
	vc := fv.serve(t)
	fv.deleteStatus = http.StatusInternalServerError

	issued := time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC)
	expires := issued.Add(6 * time.Hour)
	fv.seed("users/alice/jfrog", map[string]string{
		"access_token":  "a",
		"refresh_token": "r",
		"issued_at":     issued.Format(time.RFC3339),
		"expires_at":    expires.Format(time.RFC3339),
	})

	fake := &fakeRefresher{name: "jfrog", fields: []string{"access_token"}}
	fake.response = func(fakeRefresherCall) (map[string]string, error) { return nil, ErrRevoked }
	registerFake(t, "jfrog-fake", fake)

	clk := &fixedClock{now: issued.Add(4 * time.Hour)}
	m := NewRefreshManager(vc, "kv", "users/alice/", map[string]config.Enrolment{
		"jfrog": {Engine: "jfrog-fake"},
	}, 10*time.Second,
		WithClock(clk),
	)
	m.tick(context.Background())

	// Secret must still be present (delete failed).
	if got := fv.secret("users/alice/jfrog"); got == nil {
		t.Fatal("secret unexpectedly gone after failed delete")
	}
	// Backoff must be set so the next tick within the window skips Refresh.
	m.mu.Lock()
	b := m.backoffs["jfrog"]
	m.mu.Unlock()
	if b.delay == 0 {
		t.Errorf("backoff delay should be set after failed delete, got %v", b)
	}
	callsBefore := len(fake.Calls())
	m.tick(context.Background())
	if len(fake.Calls()) != callsBefore {
		t.Errorf("Refresh called %d additional times within backoff window, want 0",
			len(fake.Calls())-callsBefore)
	}
}

func TestRefreshManager_TransientErrorKeepsSecret(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)

	issued := time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC)
	expires := issued.Add(6 * time.Hour)
	fv.seed("users/alice/jfrog", map[string]string{
		"access_token":  "a",
		"refresh_token": "r",
		"issued_at":     issued.Format(time.RFC3339),
		"expires_at":    expires.Format(time.RFC3339),
	})

	fake := &fakeRefresher{name: "jfrog", fields: []string{"access_token"}}
	fake.response = func(fakeRefresherCall) (map[string]string, error) {
		return nil, errors.New("network is down")
	}
	registerFake(t, "jfrog-fake", fake)

	// Use a small checkInterval relative to maxBackoff so we can verify
	// both the initial seed and the doubling step before saturation.
	clk := &fixedClock{now: issued.Add(4 * time.Hour)}
	m := NewRefreshManager(vc, "kv", "users/alice/", map[string]config.Enrolment{
		"jfrog": {Engine: "jfrog-fake"},
	}, 10*time.Second,
		WithClock(clk),
		WithMaxBackoff(10*time.Minute),
	)
	m.tick(context.Background())

	got := fv.secret("users/alice/jfrog")
	if got == nil || got["access_token"] != "a" {
		t.Errorf("secret should be untouched after transient error, got %v", got)
	}

	// Backoff state should have been bumped to checkInterval on first failure.
	m.mu.Lock()
	b := m.backoffs["jfrog"]
	m.mu.Unlock()
	if b.delay != 10*time.Second {
		t.Errorf("backoff delay after first failure = %v, want %v (checkInterval)", b.delay, 10*time.Second)
	}
	wantDeadline := clk.Now().Add(10 * time.Second)
	if !b.nextAttempt.Equal(wantDeadline) {
		t.Errorf("nextAttempt after first failure = %v, want %v", b.nextAttempt, wantDeadline)
	}

	// A tick *inside* the backoff window must not call Refresh again.
	callsBefore := len(fake.Calls())
	m.tick(context.Background())
	if len(fake.Calls()) != callsBefore {
		t.Errorf("Refresh called %d times within backoff window, want 0 additional calls",
			len(fake.Calls())-callsBefore)
	}

	// Advance past the deadline; next tick should bump delay from 10s to 20s.
	clk.Advance(11 * time.Second)
	m.tick(context.Background())
	m.mu.Lock()
	b2 := m.backoffs["jfrog"]
	m.mu.Unlock()
	if b2.delay != 20*time.Second {
		t.Errorf("backoff delay after second failure = %v, want 20s (doubled)", b2.delay)
	}
}

func TestRefreshManager_BackoffCappedAtMax(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)

	issued := time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC)
	expires := issued.Add(6 * time.Hour)
	fv.seed("users/alice/jfrog", map[string]string{
		"access_token":  "a",
		"refresh_token": "r",
		"issued_at":     issued.Format(time.RFC3339),
		"expires_at":    expires.Format(time.RFC3339),
	})

	fake := &fakeRefresher{name: "jfrog", fields: []string{"access_token"}}
	fake.response = func(fakeRefresherCall) (map[string]string, error) {
		return nil, errors.New("still down")
	}
	registerFake(t, "jfrog-fake", fake)

	clk := &fixedClock{now: issued.Add(4 * time.Hour)}
	m := NewRefreshManager(vc, "kv", "users/alice/", map[string]config.Enrolment{
		"jfrog": {Engine: "jfrog-fake"},
	}, 30*time.Second,
		WithClock(clk),
		WithMaxBackoff(2*time.Minute),
	)

	// Advance time past the current backoff window each iteration so the
	// rotation actually runs; otherwise the backoff gate would skip it.
	// Delay sequence: 30s → 60s → 120s (cap). A big enough jump forces
	// saturation regardless of the exact doubling count.
	for i := 0; i < 10; i++ {
		m.tick(context.Background())
		clk.Advance(5 * time.Minute)
	}
	m.mu.Lock()
	b := m.backoffs["jfrog"]
	m.mu.Unlock()
	if b.delay != 2*time.Minute {
		t.Errorf("saturated backoff delay = %v, want 2m", b.delay)
	}
}

func TestRefreshManager_SuccessResetsBackoff(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)

	issued := time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC)
	expires := issued.Add(6 * time.Hour)
	fv.seed("users/alice/jfrog", map[string]string{
		"access_token":  "a",
		"refresh_token": "r",
		"issued_at":     issued.Format(time.RFC3339),
		"expires_at":    expires.Format(time.RFC3339),
	})

	callCount := 0
	fake := &fakeRefresher{name: "jfrog", fields: []string{"access_token"}}
	fake.response = func(fakeRefresherCall) (map[string]string, error) {
		callCount++
		if callCount == 1 {
			return nil, errors.New("first call fails")
		}
		// Second call succeeds. Issue a brand new token pair.
		n := issued.Add(4 * time.Hour)
		return map[string]string{
			"access_token":  "new",
			"refresh_token": "new-r",
			"url":           "http://jf",
			"server_id":     "jf",
			"user":          "alice",
			"issued_at":     n.Format(time.RFC3339),
			"expires_at":    n.Add(6 * time.Hour).Format(time.RFC3339),
		}, nil
	}
	registerFake(t, "jfrog-fake", fake)

	clk := &fixedClock{now: issued.Add(4 * time.Hour)}
	m := NewRefreshManager(vc, "kv", "users/alice/", map[string]config.Enrolment{
		"jfrog": {Engine: "jfrog-fake"},
	}, 10*time.Second,
		WithClock(clk),
	)
	m.tick(context.Background())
	m.mu.Lock()
	first := m.backoffs["jfrog"]
	m.mu.Unlock()
	if first.delay == 0 {
		t.Fatal("backoff delay should be non-zero after failure")
	}
	// Advance past the backoff deadline so the next tick actually runs.
	clk.Advance(11 * time.Second)
	m.tick(context.Background())
	m.mu.Lock()
	_, stillInBackoffs := m.backoffs["jfrog"]
	m.mu.Unlock()
	if stillInBackoffs {
		t.Error("backoff entry should be cleared after a successful rotation")
	}
}

func TestNewRefreshManager_InvalidCheckInterval(t *testing.T) {
	// A non-positive checkInterval must be coerced to the fallback so
	// Start's time.NewTicker doesn't panic. Construct with zero and with
	// a negative duration; both should yield a usable manager.
	fv := newFakeVault("kv")
	vc := fv.serve(t)
	for _, d := range []time.Duration{0, -time.Second} {
		m := NewRefreshManager(vc, "kv", "users/alice/", nil, d)
		if m.checkInterval != defaultRefreshInterval {
			t.Errorf("NewRefreshManager(checkInterval=%v) kept it as-is; want coerced to %v",
				d, defaultRefreshInterval)
		}
	}
}

func TestRefreshManager_NonRefresherEngineIgnored(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)
	fv.seed("users/alice/ssh", map[string]string{
		"private_key": "blob",
	})

	m := NewRefreshManager(vc, "kv", "users/alice/", map[string]config.Enrolment{
		// ssh is a real engine but does not implement Refresher.
		"ssh": {Engine: "ssh"},
	}, time.Hour,
		WithClock(&fixedClock{now: time.Now()}),
	)
	// Should not panic or error; simply a no-op.
	m.tick(context.Background())
}
