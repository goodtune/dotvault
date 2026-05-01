package enrol

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
)

// fakeWatcher is a Watcher test double whose Run is fully scripted via a
// callback so tests can assert exact invocations and inject errors. It
// also records the last IO it saw, which the WatchManager must populate
// with the live Vault client and resolved TargetPath.
type fakeWatcher struct {
	name    string
	fields  []string
	sources []WatchSource

	mu      sync.Mutex
	calls   int32
	lastIO  IO
	respond func(call int) (map[string]string, error)
}

func (f *fakeWatcher) Name() string     { return f.name }
func (f *fakeWatcher) Fields() []string { return f.fields }
func (f *fakeWatcher) Run(ctx context.Context, settings map[string]any, io IO) (map[string]string, error) {
	n := atomic.AddInt32(&f.calls, 1)
	f.mu.Lock()
	f.lastIO = io
	resp := f.respond
	f.mu.Unlock()
	if resp == nil {
		return map[string]string{f.fields[0]: "default"}, nil
	}
	return resp(int(n))
}

func (f *fakeWatcher) WatchSources(settings map[string]any, username string) []WatchSource {
	return f.sources
}

func (f *fakeWatcher) Calls() int32 { return atomic.LoadInt32(&f.calls) }

// fakeClock is a deterministic clock for tests that need to advance
// time without sleeping.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newWatchManagerForTest(vc *vault.Client, enrolments map[string]config.Enrolment) (*WatchManager, *fakeClock) {
	clk := &fakeClock{now: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)}
	m := NewWatchManager(
		vc,
		"kv",
		"users/alice/",
		"alice",
		enrolments,
		time.Minute,
		WithWatchClock(clk),
		WithWatchMaxBackoff(time.Hour),
	)
	return m, clk
}

func TestWatchManager_Tick_WritesWhenTargetMissing(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)

	w := &fakeWatcher{
		name:    "fake",
		fields:  []string{"token"},
		sources: []WatchSource{{Mount: "kv", Path: "apps/x/keys/alice"}},
		respond: func(int) (map[string]string, error) {
			return map[string]string{"token": "v1"}, nil
		},
	}
	RegisterEngine("test-watch-write", w)
	t.Cleanup(func() { UnregisterEngine("test-watch-write") })

	m, _ := newWatchManagerForTest(vc, map[string]config.Enrolment{
		"someapp": {Engine: "test-watch-write"},
	})

	m.tickAll(context.Background())

	if w.Calls() != 1 {
		t.Errorf("engine calls = %d, want 1", w.Calls())
	}
	got := fv.secret("users/alice/someapp")
	if got["token"] != "v1" {
		t.Errorf("target token = %q, want %q", got["token"], "v1")
	}
}

func TestWatchManager_Tick_SkipsWriteWhenTargetMatches(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)
	fv.seed("users/alice/someapp", map[string]string{"token": "v1"})

	w := &fakeWatcher{
		name:    "fake",
		fields:  []string{"token"},
		sources: []WatchSource{{Mount: "kv", Path: "apps/x/keys/alice"}},
		respond: func(int) (map[string]string, error) {
			return map[string]string{"token": "v1"}, nil
		},
	}
	RegisterEngine("test-watch-skip", w)
	t.Cleanup(func() { UnregisterEngine("test-watch-skip") })

	m, _ := newWatchManagerForTest(vc, map[string]config.Enrolment{
		"someapp": {Engine: "test-watch-skip"},
	})

	// Track writes before the tick.
	fv.mu.Lock()
	writesBefore := len(fv.writes)
	fv.mu.Unlock()

	m.tickAll(context.Background())

	fv.mu.Lock()
	writesAfter := len(fv.writes)
	fv.mu.Unlock()
	if writesAfter != writesBefore {
		t.Errorf("writes after tick = %d, before = %d (want no new writes)", writesAfter, writesBefore)
	}
}

func TestWatchManager_Tick_WritesWhenTargetDiffers(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)
	fv.seed("users/alice/someapp", map[string]string{"token": "old"})

	w := &fakeWatcher{
		name:    "fake",
		fields:  []string{"token"},
		sources: []WatchSource{{Mount: "kv", Path: "apps/x/keys/alice"}},
		respond: func(int) (map[string]string, error) {
			return map[string]string{"token": "new"}, nil
		},
	}
	RegisterEngine("test-watch-update", w)
	t.Cleanup(func() { UnregisterEngine("test-watch-update") })

	m, _ := newWatchManagerForTest(vc, map[string]config.Enrolment{
		"someapp": {Engine: "test-watch-update"},
	})

	m.tickAll(context.Background())

	got := fv.secret("users/alice/someapp")
	if got["token"] != "new" {
		t.Errorf("target token = %q, want %q", got["token"], "new")
	}
}

func TestWatchManager_Tick_PopulatesIO(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)

	w := &fakeWatcher{
		name:    "fake",
		fields:  []string{"token"},
		sources: []WatchSource{{Mount: "kv", Path: "apps/x/keys/alice"}},
		respond: func(int) (map[string]string, error) {
			return map[string]string{"token": "v"}, nil
		},
	}
	RegisterEngine("test-watch-io", w)
	t.Cleanup(func() { UnregisterEngine("test-watch-io") })

	m, _ := newWatchManagerForTest(vc, map[string]config.Enrolment{
		"someapp": {Engine: "test-watch-io"},
	})
	m.tickAll(context.Background())

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lastIO.Vault != vc {
		t.Errorf("io.Vault not populated")
	}
	if w.lastIO.KVMount != "kv" {
		t.Errorf("io.KVMount = %q, want %q", w.lastIO.KVMount, "kv")
	}
	if w.lastIO.Username != "alice" {
		t.Errorf("io.Username = %q, want %q", w.lastIO.Username, "alice")
	}
	if w.lastIO.TargetPath != "users/alice/someapp" {
		t.Errorf("io.TargetPath = %q, want %q", w.lastIO.TargetPath, "users/alice/someapp")
	}
}

func TestWatchManager_BackoffOnEngineFailure(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)

	w := &fakeWatcher{
		name:    "fake",
		fields:  []string{"token"},
		sources: []WatchSource{{Mount: "kv", Path: "apps/x/keys/alice"}},
		respond: func(call int) (map[string]string, error) {
			return nil, errIntentional
		},
	}
	RegisterEngine("test-watch-fail", w)
	t.Cleanup(func() { UnregisterEngine("test-watch-fail") })

	m, clk := newWatchManagerForTest(vc, map[string]config.Enrolment{
		"someapp": {Engine: "test-watch-fail"},
	})

	ctx := context.Background()
	m.tickAll(ctx)
	if w.Calls() != 1 {
		t.Fatalf("after first tick, calls = %d, want 1", w.Calls())
	}
	// Immediate next tick must be skipped due to backoff.
	m.tickAll(ctx)
	if w.Calls() != 1 {
		t.Errorf("after second tick (in-backoff), calls = %d, want 1", w.Calls())
	}
	// Advance past the backoff window: pollInterval is 1m, so first
	// failure sets nextAttempt = now + 1m. Advance by >1m and re-tick.
	clk.Advance(2 * time.Minute)
	m.tickAll(ctx)
	if w.Calls() != 2 {
		t.Errorf("after backoff window elapsed, calls = %d, want 2", w.Calls())
	}
}

func TestWatchManager_NonWatcherEngineSkipped(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)

	// mockEngine doesn't implement Watcher.
	eng := &mockEngine{name: "mock", fields: []string{"f"}, creds: map[string]string{"f": "v"}}
	RegisterEngine("test-watch-non-watcher", eng)
	t.Cleanup(func() { UnregisterEngine("test-watch-non-watcher") })

	m, _ := newWatchManagerForTest(vc, map[string]config.Enrolment{
		"someapp": {Engine: "test-watch-non-watcher"},
	})

	m.tickAll(context.Background())
	if eng.called != 0 {
		t.Errorf("non-Watcher engine was invoked %d times, want 0", eng.called)
	}
}

func TestWatchManager_DispatchEvent_TriggersMatching(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)

	w := &fakeWatcher{
		name:    "fake",
		fields:  []string{"token"},
		sources: []WatchSource{{Mount: "kv", Path: "apps/x/keys/alice"}},
		respond: func(int) (map[string]string, error) {
			return map[string]string{"token": "v"}, nil
		},
	}
	RegisterEngine("test-watch-event", w)
	t.Cleanup(func() { UnregisterEngine("test-watch-event") })

	m, _ := newWatchManagerForTest(vc, map[string]config.Enrolment{
		"someapp": {Engine: "test-watch-event"},
	})

	m.dispatchEvent(vault.Event{
		EventType: "kv-v2/data-write",
		MountPath: "kv/",
		Path:      "apps/x/keys/alice",
	})

	select {
	case key := <-m.triggerCh:
		if key != "someapp" {
			t.Errorf("triggered key = %q, want %q", key, "someapp")
		}
	default:
		t.Fatal("expected trigger for matching event, got none")
	}
}

func TestWatchManager_DispatchEvent_IgnoresNonMatching(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)

	w := &fakeWatcher{
		name:    "fake",
		fields:  []string{"token"},
		sources: []WatchSource{{Mount: "kv", Path: "apps/x/keys/alice"}},
	}
	RegisterEngine("test-watch-event-miss", w)
	t.Cleanup(func() { UnregisterEngine("test-watch-event-miss") })

	m, _ := newWatchManagerForTest(vc, map[string]config.Enrolment{
		"someapp": {Engine: "test-watch-event-miss"},
	})

	m.dispatchEvent(vault.Event{
		EventType: "kv-v2/data-write",
		MountPath: "kv/",
		Path:      "apps/y/keys/alice",
	})

	select {
	case key := <-m.triggerCh:
		t.Fatalf("unexpected trigger for non-matching event: key=%q", key)
	default:
	}
}

func TestTargetMatches(t *testing.T) {
	tests := []struct {
		name     string
		existing map[string]any
		desired  map[string]any
		want     bool
	}{
		{
			name:     "exact match",
			existing: map[string]any{"a": "1"},
			desired:  map[string]any{"a": "1"},
			want:     true,
		},
		{
			name:     "extra keys in existing are ignored",
			existing: map[string]any{"a": "1", "extra": "preserved"},
			desired:  map[string]any{"a": "1"},
			want:     true,
		},
		{
			name:     "missing desired key",
			existing: map[string]any{"b": "1"},
			desired:  map[string]any{"a": "1"},
			want:     false,
		},
		{
			name:     "value mismatch",
			existing: map[string]any{"a": "1"},
			desired:  map[string]any{"a": "2"},
			want:     false,
		},
		{
			name:     "empty desired matches anything",
			existing: map[string]any{"a": "1"},
			desired:  map[string]any{},
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := targetMatches(tt.existing, tt.desired); got != tt.want {
				t.Errorf("targetMatches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasAllFields(t *testing.T) {
	tests := []struct {
		name   string
		data   map[string]any
		fields []string
		want   bool
	}{
		{"all present", map[string]any{"a": "1", "b": "2"}, []string{"a", "b"}, true},
		{"missing field", map[string]any{"a": "1"}, []string{"a", "b"}, false},
		{"empty value", map[string]any{"a": "1", "b": ""}, []string{"a", "b"}, false},
		{"nil fields treated as incomplete", map[string]any{"a": "1"}, nil, false},
		{"empty fields treated as incomplete", map[string]any{"a": "1"}, []string{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasAllFields(tt.data, tt.fields); got != tt.want {
				t.Errorf("HasAllFields() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEventMatchesSource(t *testing.T) {
	tests := []struct {
		name string
		evt  vault.Event
		src  WatchSource
		want bool
	}{
		{"exact match", vault.Event{MountPath: "kv/", Path: "a/b"}, WatchSource{Mount: "kv", Path: "a/b"}, true},
		{"different mount", vault.Event{MountPath: "secret/", Path: "a/b"}, WatchSource{Mount: "kv", Path: "a/b"}, false},
		{"different path", vault.Event{MountPath: "kv/", Path: "a/c"}, WatchSource{Mount: "kv", Path: "a/b"}, false},
		{"mount without trailing slash", vault.Event{MountPath: "kv", Path: "a/b"}, WatchSource{Mount: "kv", Path: "a/b"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eventMatchesSource(tt.evt, tt.src); got != tt.want {
				t.Errorf("eventMatchesSource() = %v, want %v", got, tt.want)
			}
		})
	}
}

// errIntentional is returned by test doubles to exercise error paths.
var errIntentional = errIntentionalT("intentional test failure")

type errIntentionalT string

func (e errIntentionalT) Error() string { return string(e) }
