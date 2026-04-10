package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/enrol"
)

// mockEngine is a test engine that returns fixed credentials.
type mockEngine struct {
	name   string
	fields []string
	creds  map[string]string
	err    error
}

func (e *mockEngine) Name() string      { return e.name }
func (e *mockEngine) Fields() []string   { return e.fields }
func (e *mockEngine) Run(_ context.Context, _ map[string]any, _ enrol.IO) (map[string]string, error) {
	if e.err != nil {
		return nil, e.err
	}
	return e.creds, nil
}

func TestNewEnrolmentRunner(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{name: "Mock", fields: []string{"token"}})
	defer enrol.UnregisterEngine("mock")

	enrolments := map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	}

	runner := NewEnrolmentRunner(enrolments)
	states := runner.States()

	if len(states) != 1 {
		t.Fatalf("len(states) = %d, want 1", len(states))
	}
	if states[0].Key != "svc" {
		t.Errorf("key = %q, want %q", states[0].Key, "svc")
	}
	if states[0].Status != "pending" {
		t.Errorf("status = %q, want %q", states[0].Status, "pending")
	}
	if states[0].EngineName != "Mock" {
		t.Errorf("engine_name = %q, want %q", states[0].EngineName, "Mock")
	}
}

func TestEnrolmentRunner_Skip(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{name: "Mock", fields: []string{"token"}})
	defer enrol.UnregisterEngine("mock")

	runner := NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	})

	err := runner.Skip("svc")
	if err != nil {
		t.Fatalf("Skip() error: %v", err)
	}

	states := runner.States()
	if states[0].Status != "skipped" {
		t.Errorf("status = %q, want %q", states[0].Status, "skipped")
	}
}

func TestEnrolmentRunner_SkipUnknownKey(t *testing.T) {
	runner := NewEnrolmentRunner(nil)
	err := runner.Skip("nonexistent")
	if err == nil {
		t.Error("expected error for unknown key")
	}
}

func TestEnrolmentRunner_GetState(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{name: "Mock", fields: []string{"token"}})
	defer enrol.UnregisterEngine("mock")

	runner := NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	})

	info, err := runner.GetState("svc")
	if err != nil {
		t.Fatalf("GetState() error: %v", err)
	}
	if info.Status != "pending" {
		t.Errorf("status = %q, want %q", info.Status, "pending")
	}

	_, err = runner.GetState("nonexistent")
	if err == nil {
		t.Error("expected error for unknown key")
	}
}

func TestEnrolmentRunner_HasPending(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{name: "Mock", fields: []string{"token"}})
	defer enrol.UnregisterEngine("mock")

	runner := NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	})

	if !runner.HasPending() {
		t.Error("HasPending() = false, want true")
	}

	runner.MarkComplete("svc")
	if runner.HasPending() {
		t.Error("HasPending() = true after MarkComplete, want false")
	}
}

func TestEnrolmentRunner_HasPending_Empty(t *testing.T) {
	runner := NewEnrolmentRunner(nil)
	if runner.HasPending() {
		t.Error("HasPending() = true for empty runner, want false")
	}
}

func TestEnrolmentRunner_Complete(t *testing.T) {
	runner := NewEnrolmentRunner(nil)

	runner.Complete()

	select {
	case <-runner.done:
		// expected
	default:
		t.Error("done channel not signalled")
	}
}

func fakeVaultHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]any{
			"data":     map[string]any{},
			"metadata": map[string]any{"version": 1},
		},
	})
}

func TestEnrolmentRunner_Start_Success(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{
		name:   "Mock",
		fields: []string{"token"},
		creds:  map[string]string{"token": "abc123"},
	})
	defer enrol.UnregisterEngine("mock")

	vc := newFakeVaultServer(t, fakeVaultHandler)

	runner := NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	})

	err := runner.Start(context.Background(), "svc", vc, "kv", "users/gary/", "gary", nil)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	runner.WaitForKey("svc")

	info, _ := runner.GetState("svc")
	if info.Status != "complete" {
		t.Errorf("status = %q, want %q", info.Status, "complete")
	}
}

func TestEnrolmentRunner_Start_Failure(t *testing.T) {
	enrol.RegisterEngine("failmock", &mockEngine{
		name:   "FailMock",
		fields: []string{"token"},
		err:    fmt.Errorf("device flow timeout"),
	})
	defer enrol.UnregisterEngine("failmock")

	runner := NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "failmock"},
	})

	err := runner.Start(context.Background(), "svc", nil, "", "", "", nil)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	runner.WaitForKey("svc")

	info, _ := runner.GetState("svc")
	if info.Status != "failed" {
		t.Errorf("status = %q, want %q", info.Status, "failed")
	}
	if info.Error != "device flow timeout" {
		t.Errorf("error = %q, want %q", info.Error, "device flow timeout")
	}
}

func TestEnrolmentRunner_Start_AlreadyRunning(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{name: "Mock", fields: []string{"token"}})
	defer enrol.UnregisterEngine("mock")

	runner := NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	})

	// Manually set running state.
	runner.mu.RLock()
	s := runner.states["svc"]
	runner.mu.RUnlock()
	s.mu.Lock()
	s.status = "running"
	s.mu.Unlock()

	err := runner.Start(context.Background(), "svc", nil, "", "", "", nil)
	if err == nil {
		t.Error("expected error for already running enrolment")
	}
}

func TestEnrolmentRunner_Start_Retry(t *testing.T) {
	retryEngine := &mockEngine{
		name:   "Retry",
		fields: []string{"token"},
		creds:  map[string]string{"token": "retry-token"},
	}
	enrol.RegisterEngine("retry", retryEngine)
	defer enrol.UnregisterEngine("retry")

	runner := NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "retry"},
	})

	// Manually set to failed.
	runner.mu.RLock()
	s := runner.states["svc"]
	runner.mu.RUnlock()
	s.mu.Lock()
	s.status = "failed"
	s.errMsg = "previous failure"
	s.doneCh = make(chan struct{})
	s.mu.Unlock()

	vc := newFakeVaultServer(t, fakeVaultHandler)

	err := runner.Start(context.Background(), "svc", vc, "kv", "users/gary/", "gary", nil)
	if err != nil {
		t.Fatalf("Start() error on retry: %v", err)
	}

	runner.WaitForKey("svc")

	info, _ := runner.GetState("svc")
	if info.Status != "complete" {
		t.Errorf("status = %q, want %q", info.Status, "complete")
	}
}
