package main

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	gosync "sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/enrol"
	"github.com/goodtune/dotvault/internal/sync"
)

// TestRunConfigRefreshAppliesRuleChanges drives the mode-agnostic refresh
// loop with a fake loader and observes the fan-out through the sync engine's
// state store: a rule set change must prune state entries for removed rules.
func TestRunConfigRefreshAppliesRuleChanges(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")

	initial := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{
			{Name: "old", VaultKey: "old", Target: config.Target{Path: "/tmp/old", Format: "text"}},
		},
	}
	engine := sync.NewEngine(initial, nil, "user", statePath)
	engine.State().Set("old", sync.RuleState{VaultVersion: 1, LastSynced: time.Now()})

	updated := &config.Config{
		Vault: initial.Vault,
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{
			{Name: "new", VaultKey: "new", Target: config.Target{Path: "/tmp/new", Format: "text"}},
		},
		Enrolments: map[string]config.Enrolment{"gh": {Engine: "github"}},
	}
	loader := func() (*config.Config, error) { return updated, nil }

	rm := enrol.NewRefreshManager(nil, "kv", "users/user/", initial.Enrolments, time.Minute)
	wm := enrol.NewWatchManager(nil, "kv", "users/user/", "user", initial.Enrolments, time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runConfigRefresh(ctx, refreshDeps{
			load:           loader,
			interval:       10 * time.Millisecond,
			initial:        initial,
			initialStatic:  staticSectionsOf(initial),
			engine:         engine,
			refreshManager: rm,
			watchManager:   wm,
		})
	}()

	deadline := time.After(3 * time.Second)
	for {
		if _, ok := engine.State().Rules()["old"]; !ok {
			break
		}
		select {
		case <-deadline:
			t.Fatal("state entry for removed rule was never pruned by the refresh loop")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	<-done
}

// TestRunConfigRefreshManualReload drives the refresh loop with a ticker
// interval far beyond the test's lifetime and asserts that a manual reload
// request (the SIGHUP / tray path) runs a refresh pass immediately.
func TestRunConfigRefreshManualReload(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")

	initial := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{
			{Name: "old", VaultKey: "old", Target: config.Target{Path: "/tmp/old", Format: "text"}},
		},
	}
	engine := sync.NewEngine(initial, nil, "user", statePath)
	engine.State().Set("old", sync.RuleState{VaultVersion: 1, LastSynced: time.Now()})

	updated := &config.Config{
		Vault: initial.Vault,
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{
			{Name: "new", VaultKey: "new", Target: config.Target{Path: "/tmp/new", Format: "text"}},
		},
	}
	loader := func() (*config.Config, error) { return updated, nil }

	rm := enrol.NewRefreshManager(nil, "kv", "users/user/", initial.Enrolments, time.Minute)
	wm := enrol.NewWatchManager(nil, "kv", "users/user/", "user", initial.Enrolments, time.Minute)

	reloadCh := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runConfigRefresh(ctx, refreshDeps{
			load:           loader,
			interval:       time.Hour, // never ticks within the test
			initial:        initial,
			initialStatic:  staticSectionsOf(initial),
			reload:         reloadCh,
			engine:         engine,
			refreshManager: rm,
			watchManager:   wm,
		})
	}()

	reloadCh <- struct{}{}

	deadline := time.After(3 * time.Second)
	for {
		if _, ok := engine.State().Rules()["old"]; !ok {
			break
		}
		select {
		case <-deadline:
			t.Fatal("manual reload request did not trigger an immediate refresh pass")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	<-done
}

// TestChangedStaticSections exercises the restart-required diff: each static
// section must be reported by its YAML name, dynamic sections must never
// appear, and observability header changes must be visible through the
// digest even though the snapshot does not retain the header values.
func TestChangedStaticSections(t *testing.T) {
	base := &config.Config{
		Vault:         config.VaultConfig{Address: "https://vault.example.com:8200"},
		Sync:          config.SyncConfig{Interval: time.Hour},
		Web:           config.WebConfig{Enabled: true, Listen: "127.0.0.1:9000"},
		Observability: config.ObservabilityConfig{Enabled: true, Endpoint: "https://otel.example", Headers: map[string]string{"Authorization": "Bearer s3cret"}},
		Rules: []config.Rule{
			{Name: "r", VaultKey: "k", Target: config.Target{Path: "/tmp/r", Format: "text"}},
		},
	}

	snap := staticSectionsOf(base)
	if snap.Observability.Headers != nil {
		t.Fatal("staticSectionsOf must not retain observability header values")
	}
	if snap.HeadersDigest == ([32]byte{}) {
		t.Fatal("non-empty headers must produce a non-zero digest")
	}

	// Same static content, different dynamic content: no change reported.
	// remote_config is dynamic — the loader rebuilds the overlay fetcher
	// and the refresh loop re-derives its cadence — so it must not be
	// reported either.
	dynamicOnly := *base
	dynamicOnly.Sync = config.SyncConfig{Interval: time.Minute}
	dynamicOnly.Rules = nil
	dynamicOnly.RemoteConfig.URL = "https://config.example/doc"
	if got := changedStaticSections(snap, staticSectionsOf(&dynamicOnly)); len(got) != 0 {
		t.Errorf("dynamic-only change reported static sections: %v", got)
	}

	cases := []struct {
		name   string
		mutate func(*config.Config)
		want   string
	}{
		{"vault", func(c *config.Config) { c.Vault.Address = "https://other.example.com:8200" }, "vault"},
		{"web", func(c *config.Config) { c.Web.Listen = "127.0.0.1:9001" }, "web"},
		{"agent", func(c *config.Config) { c.Agent.Enabled = true }, "agent"},
		{"observability scalar", func(c *config.Config) { c.Observability.Endpoint = "https://elsewhere.example" }, "observability"},
		{"observability headers", func(c *config.Config) { c.Observability.Headers = map[string]string{"Authorization": "Bearer rotated"} }, "observability"},
		{"bypass_system_config", func(c *config.Config) { c.BypassSystemConfig = true }, "bypass_system_config"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := *base
			// Copy the nested headers map so mutations don't alias base's.
			mutated.Observability.Headers = map[string]string{}
			for k, v := range base.Observability.Headers {
				mutated.Observability.Headers[k] = v
			}
			tc.mutate(&mutated)
			got := changedStaticSections(snap, staticSectionsOf(&mutated))
			if len(got) != 1 || got[0] != tc.want {
				t.Errorf("changedStaticSections = %v, want [%s]", got, tc.want)
			}
		})
	}
}

// TestStaticSectionsCoverConfig guards the static/dynamic split against
// drift: every top-level config.Config field must be explicitly classified
// here. A section added to config.Config without a decision fails this test
// instead of silently being neither applied on reload nor named in the
// restart-required warning.
func TestStaticSectionsCoverConfig(t *testing.T) {
	classified := map[string]string{
		"Vault":              "static",
		"Sync":               "dynamic", // sync.interval applies in place on reload
		"Web":                "static",
		"Observability":      "static",
		"Agent":              "static",
		"RemoteConfig":       "dynamic", // fetcher rebuilt by the loader, cadence re-derived by the loop
		"Rules":              "dynamic",
		"Enrolments":         "dynamic",
		"BypassSystemConfig": "static",
		"Managed":            "derived", // set by the loader from the config source, not a section
	}
	typ := reflect.TypeOf(config.Config{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if _, ok := classified[name]; !ok {
			t.Errorf("config.Config field %q is not classified as static or dynamic; decide, then update staticSectionsOf/changedStaticSections (cmd/dotvault/main.go) or the refresh loop's dynamic fan-out, and record the decision here", name)
		}
	}
	for name := range classified {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("classified field %q no longer exists on config.Config; prune it from this test", name)
		}
	}
}

// syncBuffer is a goroutine-safe bytes.Buffer for capturing slog output from
// the refresh-loop goroutine.
type syncBuffer struct {
	mu  gosync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestRunConfigRefreshStaticChangeWarns drives the loop through a static
// config change, a repeat of the same change, and a revert, asserting the
// restart-required warning fires exactly once per edit and that reverting to
// the running configuration produces the all-clear rather than a second
// (false) restart-required warning.
func TestRunConfigRefreshStaticChangeWarns(t *testing.T) {
	logBuf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logBuf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	statePath := filepath.Join(t.TempDir(), "state.json")
	initial := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{
			{Name: "r", VaultKey: "k", Target: config.Target{Path: "/tmp/r", Format: "text"}},
		},
	}
	edited := *initial
	edited.Vault.Address = "https://other.example.com:8200"

	var current atomic.Pointer[config.Config]
	current.Store(&edited)
	loader := func() (*config.Config, error) { return current.Load(), nil }

	engine := sync.NewEngine(initial, nil, "user", statePath)
	rm := enrol.NewRefreshManager(nil, "kv", "users/user/", nil, time.Minute)
	wm := enrol.NewWatchManager(nil, "kv", "users/user/", "user", nil, time.Minute)

	// Unbuffered on purpose: each send returns only once the loop has
	// received it, i.e. once the previous refresh pass fully completed and
	// the loop is back at its select. That makes the log assertions below
	// race-free without polling.
	reloadCh := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runConfigRefresh(ctx, refreshDeps{
			load:           loader,
			interval:       time.Hour, // never ticks within the test
			initial:        initial,
			initialStatic:  staticSectionsOf(initial),
			reload:         reloadCh,
			engine:         engine,
			refreshManager: rm,
			watchManager:   wm,
		})
	}()

	reloadCh <- struct{}{} // pass 1: static change -> warn
	reloadCh <- struct{}{} // pass 2: same content -> deduplicated, no second warn
	current.Store(initial)
	reloadCh <- struct{}{} // pass 3: reverted -> all-clear, no restart-required warn
	reloadCh <- struct{}{} // pass 4: barrier so pass 3's logging is complete
	cancel()
	<-done

	logs := logBuf.String()
	if got := strings.Count(logs, "restart the daemon to apply them"); got != 1 {
		t.Errorf("restart-required warning logged %d times, want exactly 1\nlogs:\n%s", got, logs)
	}
	if !strings.Contains(logs, "sections=vault") {
		t.Errorf("restart-required warning does not name the changed section\nlogs:\n%s", logs)
	}
	if !strings.Contains(logs, "restart no longer needed") {
		t.Errorf("revert to the running configuration did not log the all-clear\nlogs:\n%s", logs)
	}
}

// TestRunConfigRefreshCadenceFollowsReload pins remote_config's dynamic
// classification: a reloaded remote_config.refresh_interval must retune the
// loop's own ticker. The loop starts with an effectively-infinite cadence, a
// manual nudge delivers a config carrying a fast refresh_interval, and then
// — with no further nudges — a subsequent config change must be picked up by
// the retuned ticker alone.
func TestRunConfigRefreshCadenceFollowsReload(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")

	initial := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{
			{Name: "old", VaultKey: "old", Target: config.Target{Path: "/tmp/old", Format: "text"}},
		},
	}
	engine := sync.NewEngine(initial, nil, "user", statePath)
	engine.State().Set("old", sync.RuleState{VaultVersion: 1, LastSynced: time.Now()})

	// Same rules as initial, but a fast refresh cadence.
	retuned := *initial
	retuned.RemoteConfig.RefreshInterval = 10 * time.Millisecond

	// Different rules; only reachable once the retuned ticker fires.
	swapped := retuned
	swapped.Rules = []config.Rule{
		{Name: "new", VaultKey: "new", Target: config.Target{Path: "/tmp/new", Format: "text"}},
	}

	var current atomic.Pointer[config.Config]
	current.Store(&retuned)
	loader := func() (*config.Config, error) { return current.Load(), nil }

	rm := enrol.NewRefreshManager(nil, "kv", "users/user/", nil, time.Minute)
	wm := enrol.NewWatchManager(nil, "kv", "users/user/", "user", nil, time.Minute)

	reloadCh := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runConfigRefresh(ctx, refreshDeps{
			load:           loader,
			interval:       time.Hour, // start effectively tickless
			initial:        initial,
			initialStatic:  staticSectionsOf(initial),
			reload:         reloadCh,
			engine:         engine,
			refreshManager: rm,
			watchManager:   wm,
		})
	}()

	reloadCh <- struct{}{} // applies the 10ms cadence
	current.Store(&swapped)

	// No further nudges: only the retuned ticker can deliver this.
	deadline := time.After(3 * time.Second)
	for {
		if _, ok := engine.State().Rules()["old"]; !ok {
			break
		}
		select {
		case <-deadline:
			t.Fatal("reloaded remote_config.refresh_interval did not retune the refresh ticker")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	<-done
}
