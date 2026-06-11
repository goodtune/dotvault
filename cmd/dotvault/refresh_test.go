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
