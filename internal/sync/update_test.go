package sync

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/config"
)

func updateTestEngine(t *testing.T) *Engine {
	t.Helper()
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{
			{Name: "a", VaultKey: "a", Target: config.Target{Path: "/tmp/a", Format: "text"}},
		},
	}
	return NewEngine(cfg, nil, "user", filepath.Join(t.TempDir(), "state.json"))
}

func TestEngineUpdateConfigSwapsRulesAndPrunesState(t *testing.T) {
	e := updateTestEngine(t)
	e.State().Set("a", RuleState{VaultVersion: 1, LastSynced: time.Now()})
	e.State().Set("stale", RuleState{VaultVersion: 7, LastSynced: time.Now()})

	newRules := []config.Rule{
		{Name: "b", VaultKey: "b", Target: config.Target{Path: "/tmp/b", Format: "text"}},
	}
	e.UpdateConfig(newRules, 30*time.Minute)

	if got := e.currentInterval(); got != 30*time.Minute {
		t.Errorf("interval = %v, want 30m", got)
	}
	states := e.State().Rules()
	if _, ok := states["a"]; ok {
		t.Errorf("state entry for removed rule %q not pruned", "a")
	}
	if _, ok := states["stale"]; ok {
		t.Errorf("orphaned state entry %q not pruned", "stale")
	}

	// A rule change queues an immediate sync; an interval change signals the
	// run loop to reset its ticker.
	select {
	case <-e.triggerCh:
	default:
		t.Error("expected a queued sync trigger after rule change")
	}
	select {
	case <-e.cfgCh:
	default:
		t.Error("expected an interval-change signal")
	}

	// Re-applying the same config is a no-op: no new signals.
	e.UpdateConfig(newRules, 30*time.Minute)
	select {
	case <-e.triggerCh:
		t.Error("no-op update queued a sync trigger")
	default:
	}
	select {
	case <-e.cfgCh:
		t.Error("no-op update signalled an interval change")
	default:
	}
}

func TestEngineUpdateConfigZeroIntervalIgnored(t *testing.T) {
	e := updateTestEngine(t)
	e.UpdateConfig(e.cfg.Rules, 0)
	if got := e.currentInterval(); got != time.Hour {
		t.Errorf("interval = %v, want unchanged 1h", got)
	}
}

func TestStateStorePrune(t *testing.T) {
	s := NewStateStore(filepath.Join(t.TempDir(), "state.json"))
	s.Set("keep", RuleState{VaultVersion: 1})
	s.Set("drop1", RuleState{VaultVersion: 2})
	s.Set("drop2", RuleState{VaultVersion: 3})

	if removed := s.Prune(map[string]bool{"keep": true}); removed != 2 {
		t.Errorf("Prune removed %d, want 2", removed)
	}
	rules := s.Rules()
	if len(rules) != 1 {
		t.Errorf("Rules = %v, want only keep", rules)
	}
	if _, ok := rules["keep"]; !ok {
		t.Error("kept entry was pruned")
	}

	if removed := s.Prune(map[string]bool{"keep": true}); removed != 0 {
		t.Errorf("second Prune removed %d, want 0", removed)
	}
}
