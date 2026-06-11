package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	gosync "sync"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// TestUpdateDynamicConfigConcurrentReads swaps rules while handlers read
// them; run with -race this pins the rulesMu discipline at the four read
// sites converted to getRules/getSyncCfg.
func TestUpdateDynamicConfigConcurrentReads(t *testing.T) {
	s := testServer(t)
	s.rules = []config.Rule{
		{Name: "r0", VaultKey: "r0", Target: config.Target{Path: "/tmp/r0", Format: "text"}},
	}
	s.syncCfg = config.SyncConfig{RawInterval: "15m"}

	var wg gosync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			s.UpdateDynamicConfig([]config.Rule{
				{Name: fmt.Sprintf("r%d", i), VaultKey: "k", Target: config.Target{Path: "/tmp/k", Format: "text"}},
			}, config.SyncConfig{RawInterval: "5m"})
		}
	}()

	for i := 0; i < 200; i++ {
		req := httptest.NewRequest("GET", "/api/v1/rules", nil)
		w := httptest.NewRecorder()
		s.handleRules(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("handleRules status = %d", w.Code)
		}
	}
	close(stop)
	wg.Wait()

	rules := s.getRules()
	if len(rules) != 1 {
		t.Fatalf("rules = %+v, want one", rules)
	}
	if s.getSyncCfg().RawInterval != "5m" {
		t.Errorf("syncCfg.RawInterval = %q, want 5m", s.getSyncCfg().RawInterval)
	}
}

func TestUpdateEnrolmentsRefusedWhileRunning(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))

	runner := NewEnrolmentRunner(map[string]config.Enrolment{
		"gh": {Engine: "github"},
	})
	// Force the running state directly — driving a real engine here would
	// couple this test to engine behaviour.
	runner.mu.RLock()
	st := runner.states["gh"]
	runner.mu.RUnlock()
	st.mu.Lock()
	st.status = "running"
	st.mu.Unlock()

	s.enrolRunnerMu.Lock()
	s.enrolRunner = runner
	s.enrolments = map[string]config.Enrolment{"gh": {Engine: "github"}}
	s.enrolRunnerMu.Unlock()

	updated := map[string]config.Enrolment{
		"gh":  {Engine: "github"},
		"ssh": {Engine: "ssh"},
	}
	if s.UpdateEnrolments(context.Background(), updated) {
		t.Fatal("UpdateEnrolments applied while an enrolment was running")
	}
	if len(s.getEnrolments()) != 1 {
		t.Errorf("enrolments swapped despite refusal: %+v", s.getEnrolments())
	}

	st.mu.Lock()
	st.status = "complete"
	st.mu.Unlock()

	if !s.UpdateEnrolments(context.Background(), updated) {
		t.Fatal("UpdateEnrolments refused with nothing running")
	}
	if len(s.getEnrolments()) != 2 {
		t.Errorf("enrolments = %+v, want the updated map", s.getEnrolments())
	}
}

// TestUpdateEnrolmentsToEmptyClearsRunner pins the empty-set transition: a
// runtime update that removes every enrolment also drops the runner, so the
// status surfaces stop reporting states for enrolments that no longer exist.
func TestUpdateEnrolmentsToEmptyClearsRunner(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.InitEnrolments(context.Background(), map[string]config.Enrolment{"gh": {Engine: "github"}})
	if s.getEnrolRunner() == nil {
		t.Fatal("expected a runner after InitEnrolments")
	}

	if !s.UpdateEnrolments(context.Background(), nil) {
		t.Fatal("UpdateEnrolments to empty set refused")
	}
	if s.getEnrolRunner() != nil {
		t.Error("stale runner survived removal of all enrolments")
	}
	if len(s.getEnrolments()) != 0 {
		t.Errorf("enrolments = %+v, want empty", s.getEnrolments())
	}
}
