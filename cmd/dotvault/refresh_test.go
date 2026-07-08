package main

import (
	"context"
	"path/filepath"
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
	dynamicOnly := *base
	dynamicOnly.Sync = config.SyncConfig{Interval: time.Minute}
	dynamicOnly.Rules = nil
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
		{"remote_config", func(c *config.Config) { c.RemoteConfig.URL = "https://config.example/doc" }, "remote_config"},
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
