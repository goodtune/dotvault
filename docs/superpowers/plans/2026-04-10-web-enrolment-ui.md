# Web-Based Enrolment UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the terminal-based enrolment wizard with a web UI that lets users start, skip, and monitor each enrolment interactively after authentication.

**Architecture:** New `EnrolmentRunner` in `internal/web/` manages per-enrolment lifecycle (pending/running/complete/skipped/failed). New API endpoints expose enrolment state and actions. New Preact components render the enrolment page with engine-specific inline UI. The daemon blocks on `EnrolmentRunner.Wait()` in web mode instead of calling `CheckAll()` directly.

**Tech Stack:** Go 1.22+ (net/http routing), Preact (h() calls, no JSX transform), esbuild

---

## File Structure

| File | Responsibility |
|------|---------------|
| `internal/web/enrol_runner.go` | New — `EnrolmentRunner` struct: per-enrolment state machine, engine execution, Vault writes, `Wait()` blocking |
| `internal/web/enrol_runner_test.go` | New — unit tests for runner state transitions, concurrent access, Vault write |
| `internal/web/enrol_api.go` | New — HTTP handlers for enrolment endpoints (start, skip, status, complete) |
| `internal/web/enrol_api_test.go` | New — HTTP handler tests |
| `internal/web/server.go` | Modify — add `EnrolmentRunner` field, register new routes, add `InitEnrolments()` method |
| `internal/web/api.go` | Modify — add `enrolments` array to `handleStatus` response |
| `internal/web/auth.go` | Modify — change auth success handlers to redirect to `/` |
| `internal/web/frontend/src/api.js` | Modify — add enrolment API methods |
| `internal/web/frontend/src/components/enrol-page.jsx` | New — enrolment page with card list and continue button |
| `internal/web/frontend/src/components/enrol-card.jsx` | New — per-enrolment card with state-dependent rendering |
| `internal/web/frontend/src/app.jsx` | Modify — add enrolment page view routing |
| `internal/web/frontend/src/components/status-bar.jsx` | Modify — add pending enrolments indicator |
| `internal/web/static/style.css` | Modify — add enrolment page styles |
| `cmd/dotvault/main.go` | Modify — wire `EnrolmentRunner` in web mode, keep terminal wizard for CLI |

---

### Task 1: `EnrolmentRunner` Core State Machine

**Files:**
- Create: `internal/web/enrol_runner.go`
- Create: `internal/web/enrol_runner_test.go`

- [ ] **Step 1: Write failing test for `NewEnrolmentRunner` and state initialization**

```go
// internal/web/enrol_runner_test.go
package web

import (
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

func (e *mockEngine) Name() string     { return e.name }
func (e *mockEngine) Fields() []string { return e.fields }
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/web/ -run TestNewEnrolmentRunner -v`
Expected: FAIL — `NewEnrolmentRunner` undefined

- [ ] **Step 3: Write `EnrolmentRunner` struct and constructor**

```go
// internal/web/enrol_runner.go
package web

import (
	"sort"
	"sync"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/enrol"
)

// EnrolStateInfo is the JSON-serializable view of an enrolment's state.
type EnrolStateInfo struct {
	Key        string   `json:"key"`
	Engine     string   `json:"engine"`
	EngineName string   `json:"name"`
	Status     string   `json:"status"`
	Fields     []string `json:"fields"`
	Output     []string `json:"output,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type enrolState struct {
	key      string
	engine   enrol.Engine
	settings map[string]any
	status   string   // pending, running, complete, skipped, failed
	output   []string // captured IO.Out lines
	errMsg   string
	mu       sync.Mutex
}

// EnrolmentRunner manages per-enrolment lifecycle for web mode.
type EnrolmentRunner struct {
	states map[string]*enrolState
	order  []string // sorted keys for stable ordering
	done   chan struct{}
	mu     sync.RWMutex
}

// NewEnrolmentRunner creates a runner from the enrolments config.
// All enrolments start as "pending". Call MarkComplete() for enrolments
// that are already satisfied in Vault before exposing to the frontend.
func NewEnrolmentRunner(enrolments map[string]config.Enrolment) *EnrolmentRunner {
	keys := make([]string, 0, len(enrolments))
	for k := range enrolments {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	states := make(map[string]*enrolState, len(keys))
	for _, key := range keys {
		e := enrolments[key]
		engine, ok := enrol.GetEngine(e.Engine)
		if !ok {
			continue
		}
		states[key] = &enrolState{
			key:      key,
			engine:   engine,
			settings: e.Settings,
			status:   "pending",
		}
	}

	return &EnrolmentRunner{
		states: states,
		order:  keys,
		done:   make(chan struct{}, 1),
	}
}

// MarkComplete sets an enrolment to "complete" (e.g. already in Vault).
func (r *EnrolmentRunner) MarkComplete(key string) {
	r.mu.RLock()
	s, ok := r.states[key]
	r.mu.RUnlock()
	if !ok {
		return
	}
	s.mu.Lock()
	s.status = "complete"
	s.mu.Unlock()
}

// States returns the current state of all enrolments in stable order.
func (r *EnrolmentRunner) States() []EnrolStateInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]EnrolStateInfo, 0, len(r.order))
	for _, key := range r.order {
		s, ok := r.states[key]
		if !ok {
			continue
		}
		s.mu.Lock()
		info := EnrolStateInfo{
			Key:        s.key,
			Engine:     s.settings["engine_id"].(string), // we'll fix this
			EngineName: s.engine.Name(),
			Status:     s.status,
			Fields:     s.engine.Fields(),
			Output:     append([]string{}, s.output...),
			Error:      s.errMsg,
		}
		s.mu.Unlock()
		result = append(result, info)
	}
	return result
}
```

Wait — the `Engine` field in `EnrolStateInfo` should be the engine config string (e.g. "github"), not from settings. Let me fix the constructor to store it properly.

```go
// Replace the enrolState struct with:
type enrolState struct {
	key        string
	engineName string // config engine string, e.g. "github"
	engine     enrol.Engine
	settings   map[string]any
	status     string
	output     []string
	errMsg     string
	mu         sync.Mutex
}

// In NewEnrolmentRunner, store it:
states[key] = &enrolState{
	key:        key,
	engineName: e.Engine,
	engine:     engine,
	settings:   e.Settings,
	status:     "pending",
}

// In States(), use it:
info := EnrolStateInfo{
	Key:        s.key,
	Engine:     s.engineName,
	EngineName: s.engine.Name(),
	Status:     s.status,
	Fields:     s.engine.Fields(),
	Output:     append([]string{}, s.output...),
	Error:      s.errMsg,
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/web/ -run TestNewEnrolmentRunner -v`
Expected: PASS

- [ ] **Step 5: Write failing test for `Skip`**

```go
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
```

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./internal/web/ -run TestEnrolmentRunner_Skip -v`
Expected: FAIL — `Skip` undefined

- [ ] **Step 7: Implement `Skip`**

Add to `enrol_runner.go`:

```go
import "fmt"

// Skip marks an enrolment as skipped. Returns error if key not found or running.
func (r *EnrolmentRunner) Skip(key string) error {
	r.mu.RLock()
	s, ok := r.states[key]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("enrolment %q not found", key)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status == "running" {
		return fmt.Errorf("enrolment %q is currently running", key)
	}
	s.status = "skipped"
	return nil
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `go test ./internal/web/ -run TestEnrolmentRunner_Skip -v`
Expected: PASS

- [ ] **Step 9: Write failing test for `GetState` (single enrolment status)**

```go
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
```

- [ ] **Step 10: Run test to verify it fails**

Run: `go test ./internal/web/ -run TestEnrolmentRunner_GetState -v`
Expected: FAIL — `GetState` undefined

- [ ] **Step 11: Implement `GetState`**

```go
// GetState returns the state of a single enrolment.
func (r *EnrolmentRunner) GetState(key string) (EnrolStateInfo, error) {
	r.mu.RLock()
	s, ok := r.states[key]
	r.mu.RUnlock()
	if !ok {
		return EnrolStateInfo{}, fmt.Errorf("enrolment %q not found", key)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return EnrolStateInfo{
		Key:        s.key,
		Engine:     s.engineName,
		EngineName: s.engine.Name(),
		Status:     s.status,
		Fields:     s.engine.Fields(),
		Output:     append([]string{}, s.output...),
		Error:      s.errMsg,
	}, nil
}
```

- [ ] **Step 12: Run test to verify it passes**

Run: `go test ./internal/web/ -run TestEnrolmentRunner_GetState -v`
Expected: PASS

- [ ] **Step 13: Write failing test for `HasPending`**

```go
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
```

- [ ] **Step 14: Run test to verify it fails**

Run: `go test ./internal/web/ -run TestEnrolmentRunner_HasPending -v`
Expected: FAIL — `HasPending` undefined

- [ ] **Step 15: Implement `HasPending`**

```go
// HasPending returns true if any enrolment is pending, running, or failed.
func (r *EnrolmentRunner) HasPending() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.states {
		s.mu.Lock()
		status := s.status
		s.mu.Unlock()
		if status == "pending" || status == "running" || status == "failed" {
			return true
		}
	}
	return false
}
```

- [ ] **Step 16: Run test to verify it passes**

Run: `go test ./internal/web/ -run TestEnrolmentRunner_HasPending -v`
Expected: PASS

- [ ] **Step 17: Write failing test for `Complete` (signals done channel)**

```go
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
```

- [ ] **Step 18: Implement `Complete` and `Wait`**

```go
// Complete signals that the user is done with enrolments.
func (r *EnrolmentRunner) Complete() {
	select {
	case r.done <- struct{}{}:
	default:
	}
}

// Wait blocks until Complete() is called. Returns immediately if there
// are no pending enrolments.
func (r *EnrolmentRunner) Wait() {
	if !r.HasPending() {
		return
	}
	<-r.done
}
```

- [ ] **Step 19: Run all runner tests**

Run: `go test ./internal/web/ -run TestEnrolmentRunner -v`
Expected: all PASS

- [ ] **Step 20: Commit**

```
git add internal/web/enrol_runner.go internal/web/enrol_runner_test.go
git commit -m "Add EnrolmentRunner core state machine for web-based enrolment"
```

---

### Task 2: Engine Execution in `EnrolmentRunner`

**Files:**
- Modify: `internal/web/enrol_runner.go`
- Modify: `internal/web/enrol_runner_test.go`

- [ ] **Step 1: Write failing test for `Start` — successful engine run**

```go
import (
	"context"
	"testing"
	// ... existing imports
)

func TestEnrolmentRunner_Start_Success(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{
		name:   "Mock",
		fields: []string{"token"},
		creds:  map[string]string{"token": "abc123"},
	})
	defer enrol.UnregisterEngine("mock")

	// Fake Vault that accepts writes
	var writtenPath string
	var writtenData map[string]any
	vaultHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" || r.Method == "PUT" {
			writtenPath = r.URL.Path
			json.NewDecoder(r.Body).Decode(&writtenData)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data":     writtenData,
					"metadata": map[string]any{"version": 1},
				},
			})
			return
		}
		w.WriteHeader(404)
	})
	ts := httptest.NewServer(vaultHandler)
	defer ts.Close()

	vc, _ := vault.NewClient(vault.Config{Address: ts.URL, Token: "test"})

	runner := NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	})

	ctx := context.Background()
	err := runner.Start(ctx, "svc", vc, "kv", "users/gary/", "gary", nil)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Wait for completion
	runner.WaitForKey("svc")

	info, _ := runner.GetState("svc")
	if info.Status != "complete" {
		t.Errorf("status = %q, want %q", info.Status, "complete")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/web/ -run TestEnrolmentRunner_Start_Success -v`
Expected: FAIL — `Start` undefined

- [ ] **Step 3: Implement `Start` and supporting types**

Add to `enrol_runner.go`:

```go
import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/enrol"
	"github.com/goodtune/dotvault/internal/vault"
)

// lineCapture is an io.Writer that captures lines for the status endpoint.
type lineCapture struct {
	state *enrolState
	buf   bytes.Buffer
}

func (lc *lineCapture) Write(p []byte) (int, error) {
	lc.buf.Write(p)
	for {
		line, err := lc.buf.ReadString('\n')
		if err != nil {
			// Incomplete line — put it back
			lc.buf.WriteString(line)
			break
		}
		trimmed := strings.TrimRight(line, "\n\r")
		if trimmed != "" {
			lc.state.mu.Lock()
			lc.state.output = append(lc.state.output, trimmed)
			lc.state.mu.Unlock()
		}
	}
	return len(p), nil
}

// flush captures any remaining partial line.
func (lc *lineCapture) flush() {
	remaining := strings.TrimSpace(lc.buf.String())
	if remaining != "" {
		lc.state.mu.Lock()
		lc.state.output = append(lc.state.output, remaining)
		lc.state.mu.Unlock()
	}
}

// PromptSecretFunc is the function signature for web-based secret prompting.
type PromptSecretFunc func(ctx context.Context, label string) (string, error)

// Start launches an enrolment engine in a background goroutine.
// Returns error if the key is unknown or the enrolment is already running.
func (r *EnrolmentRunner) Start(ctx context.Context, key string, vc *vault.Client, kvMount, userPrefix, username string, promptSecret PromptSecretFunc) error {
	r.mu.RLock()
	s, ok := r.states[key]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("enrolment %q not found", key)
	}

	s.mu.Lock()
	if s.status == "running" {
		s.mu.Unlock()
		return fmt.Errorf("enrolment %q is already running", key)
	}
	s.status = "running"
	s.output = nil
	s.errMsg = ""
	s.mu.Unlock()

	capture := &lineCapture{state: s}

	io := enrol.IO{
		Out:      capture,
		In:       strings.NewReader("\n"), // auto-proceed for engines that wait for Enter
		Browser:  func(url string) error { return nil }, // no-op; frontend opens tabs
		Log:      slog.Default(),
		Username: username,
	}
	if promptSecret != nil {
		io.PromptSecret = func(label string) (string, error) {
			return promptSecret(ctx, label)
		}
	}

	go func() {
		creds, err := s.engine.Run(ctx, s.settings, io)
		capture.flush()

		if err != nil {
			s.mu.Lock()
			s.status = "failed"
			s.errMsg = err.Error()
			s.mu.Unlock()
			return
		}

		// Validate all fields present
		data := make(map[string]any, len(creds))
		for k, v := range creds {
			data[k] = v
		}
		for _, f := range s.engine.Fields() {
			v, ok := data[f]
			if !ok || v == nil || strings.TrimSpace(v.(string)) == "" {
				s.mu.Lock()
				s.status = "failed"
				s.errMsg = "engine returned incomplete credentials"
				s.mu.Unlock()
				return
			}
		}

		// Write to Vault
		vaultPath := userPrefix + key
		if err := vc.WriteKVv2(ctx, kvMount, vaultPath, data); err != nil {
			s.mu.Lock()
			s.status = "failed"
			s.errMsg = fmt.Sprintf("vault write failed: %v", err)
			s.mu.Unlock()
			return
		}

		s.mu.Lock()
		s.status = "complete"
		s.mu.Unlock()
	}()

	return nil
}

// WaitForKey blocks until the given enrolment is no longer "running".
// Used in tests.
func (r *EnrolmentRunner) WaitForKey(key string) {
	r.mu.RLock()
	s, ok := r.states[key]
	r.mu.RUnlock()
	if !ok {
		return
	}
	for {
		s.mu.Lock()
		status := s.status
		s.mu.Unlock()
		if status != "running" {
			return
		}
	}
}
```

Note: `WaitForKey` uses a spin loop which is fine for tests but we should use a channel. Let me refine:

```go
// Add to enrolState:
type enrolState struct {
	// ... existing fields ...
	doneCh chan struct{} // closed when engine finishes
}

// In NewEnrolmentRunner, initialize it:
states[key] = &enrolState{
	// ... existing fields ...
	doneCh: make(chan struct{}),
}

// At the end of the Start goroutine (after setting complete or failed):
close(s.doneCh)

// Also reset doneCh at the start of Start (for retry):
s.doneCh = make(chan struct{})

// WaitForKey becomes:
func (r *EnrolmentRunner) WaitForKey(key string) {
	r.mu.RLock()
	s, ok := r.states[key]
	r.mu.RUnlock()
	if !ok {
		return
	}
	s.mu.Lock()
	ch := s.doneCh
	s.mu.Unlock()
	<-ch
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/web/ -run TestEnrolmentRunner_Start_Success -v`
Expected: PASS

- [ ] **Step 5: Write failing test for `Start` — engine failure**

```go
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

	ctx := context.Background()
	err := runner.Start(ctx, "svc", nil, "", "", "", nil)
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
```

- [ ] **Step 6: Run test to verify it passes** (should pass with existing implementation)

Run: `go test ./internal/web/ -run TestEnrolmentRunner_Start_Failure -v`
Expected: PASS

- [ ] **Step 7: Write failing test for `Start` — returns 409 when already running**

```go
func TestEnrolmentRunner_Start_AlreadyRunning(t *testing.T) {
	// Use a slow engine that blocks
	slowEngine := &mockEngine{name: "Slow", fields: []string{"token"}}
	enrol.RegisterEngine("slow", slowEngine)
	defer enrol.UnregisterEngine("slow")

	runner := NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "slow"},
	})

	// Manually set running state
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
```

- [ ] **Step 8: Run test to verify it passes**

Run: `go test ./internal/web/ -run TestEnrolmentRunner_Start_AlreadyRunning -v`
Expected: PASS

- [ ] **Step 9: Write failing test for retry (start after failure)**

```go
func TestEnrolmentRunner_Start_Retry(t *testing.T) {
	callCount := 0
	retryEngine := &mockEngine{name: "Retry", fields: []string{"token"}}
	enrol.RegisterEngine("retry", retryEngine)
	defer enrol.UnregisterEngine("retry")

	runner := NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "retry"},
	})

	// Manually set to failed
	runner.mu.RLock()
	s := runner.states["svc"]
	runner.mu.RUnlock()
	s.mu.Lock()
	s.status = "failed"
	s.errMsg = "previous failure"
	s.doneCh = make(chan struct{}) // reset done channel
	s.mu.Unlock()

	// Set credentials for success on retry
	retryEngine.creds = map[string]string{"token": "retry-token"}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{}, "metadata": map[string]any{"version": 1}}})
	}))
	defer ts.Close()
	vc, _ := vault.NewClient(vault.Config{Address: ts.URL, Token: "test"})

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
```

- [ ] **Step 10: Run test to verify it passes**

Run: `go test ./internal/web/ -run TestEnrolmentRunner_Start_Retry -v`
Expected: PASS

- [ ] **Step 11: Run all runner tests**

Run: `go test ./internal/web/ -run TestEnrolmentRunner -v`
Expected: all PASS

- [ ] **Step 12: Commit**

```
git add internal/web/enrol_runner.go internal/web/enrol_runner_test.go
git commit -m "Add engine execution, Vault write, and retry to EnrolmentRunner"
```

---

### Task 3: Enrolment API Handlers

**Files:**
- Create: `internal/web/enrol_api.go`
- Create: `internal/web/enrol_api_test.go`
- Modify: `internal/web/server.go`
- Modify: `internal/web/api.go`

- [ ] **Step 1: Write failing test for `handleEnrolStart`**

```go
// internal/web/enrol_api_test.go
package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/enrol"
)

func TestHandleEnrolStart(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{
		name:   "Mock",
		fields: []string{"token"},
		creds:  map[string]string{"token": "abc"},
	})
	defer enrol.UnregisterEngine("mock")

	s := testServer(t)
	s.enrolRunner = NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	})

	req := httptest.NewRequest("POST", "/api/v1/enrol/svc/start", nil)
	req.SetPathValue("key", "svc")
	w := httptest.NewRecorder()

	s.handleEnrolStart(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "running" {
		t.Errorf("status = %v, want %q", resp["status"], "running")
	}
}

func TestHandleEnrolStart_NotFound(t *testing.T) {
	s := testServer(t)
	s.enrolRunner = NewEnrolmentRunner(nil)

	req := httptest.NewRequest("POST", "/api/v1/enrol/bogus/start", nil)
	req.SetPathValue("key", "bogus")
	w := httptest.NewRecorder()

	s.handleEnrolStart(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/web/ -run TestHandleEnrolStart -v`
Expected: FAIL — `enrolRunner` field and `handleEnrolStart` undefined

- [ ] **Step 3: Add `enrolRunner` field to `Server` and register routes**

In `internal/web/server.go`, add the field to the `Server` struct:

```go
// Add after the enrolPromptCh field:
enrolRunner    *EnrolmentRunner
```

Add route registrations in `registerRoutes()`, after the existing enrolment prompt routes:

```go
// Enrolment runner routes
s.mux.HandleFunc("POST /api/v1/enrol/{key}/start", s.requireCSRF(s.handleEnrolStart))
s.mux.HandleFunc("POST /api/v1/enrol/{key}/skip", s.requireCSRF(s.handleEnrolSkip))
s.mux.HandleFunc("GET /api/v1/enrol/{key}/status", s.handleEnrolStatus)
s.mux.HandleFunc("POST /api/v1/enrol/complete", s.requireCSRF(s.handleEnrolComplete))
```

- [ ] **Step 4: Write `handleEnrolStart` handler**

```go
// internal/web/enrol_api.go
package web

import (
	"net/http"
)

func (s *Server) handleEnrolStart(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")

	if s.enrolRunner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}

	err := s.enrolRunner.Start(
		r.Context(), key, s.vault,
		s.kvMount, s.userKVPrefix(), s.username,
		s.EnrolPromptSecret,
	)
	if err != nil {
		if err.Error() == "enrolment \""+key+"\" not found" {
			writeError(w, "enrolment not found", http.StatusNotFound)
			return
		}
		if err.Error() == "enrolment \""+key+"\" is already running" {
			writeError(w, "enrolment already running", http.StatusConflict)
			return
		}
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{"status": "running"})
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/web/ -run TestHandleEnrolStart -v`
Expected: PASS

- [ ] **Step 6: Write failing test for `handleEnrolSkip`**

```go
func TestHandleEnrolSkip(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{name: "Mock", fields: []string{"token"}})
	defer enrol.UnregisterEngine("mock")

	s := testServer(t)
	s.enrolRunner = NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	})

	req := httptest.NewRequest("POST", "/api/v1/enrol/svc/skip", nil)
	req.SetPathValue("key", "svc")
	w := httptest.NewRecorder()

	s.handleEnrolSkip(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "skipped" {
		t.Errorf("status = %v, want %q", resp["status"], "skipped")
	}
}
```

- [ ] **Step 7: Implement `handleEnrolSkip`**

Add to `enrol_api.go`:

```go
func (s *Server) handleEnrolSkip(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")

	if s.enrolRunner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}

	err := s.enrolRunner.Skip(key)
	if err != nil {
		if err.Error() == "enrolment \""+key+"\" not found" {
			writeError(w, "enrolment not found", http.StatusNotFound)
			return
		}
		writeError(w, err.Error(), http.StatusConflict)
		return
	}

	writeJSON(w, map[string]any{"status": "skipped"})
}
```

- [ ] **Step 8: Run test to verify it passes**

Run: `go test ./internal/web/ -run TestHandleEnrolSkip -v`
Expected: PASS

- [ ] **Step 9: Write failing test for `handleEnrolStatus`**

```go
func TestHandleEnrolStatus(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{name: "Mock", fields: []string{"token"}})
	defer enrol.UnregisterEngine("mock")

	s := testServer(t)
	s.enrolRunner = NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	})

	req := httptest.NewRequest("GET", "/api/v1/enrol/svc/status", nil)
	req.SetPathValue("key", "svc")
	w := httptest.NewRecorder()

	s.handleEnrolStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "pending" {
		t.Errorf("status = %v, want %q", resp["status"], "pending")
	}
}
```

- [ ] **Step 10: Implement `handleEnrolStatus`**

```go
func (s *Server) handleEnrolStatus(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")

	if s.enrolRunner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}

	info, err := s.enrolRunner.GetState(key)
	if err != nil {
		writeError(w, "enrolment not found", http.StatusNotFound)
		return
	}

	writeJSON(w, info)
}
```

- [ ] **Step 11: Run test to verify it passes**

Run: `go test ./internal/web/ -run TestHandleEnrolStatus -v`
Expected: PASS

- [ ] **Step 12: Write failing test for `handleEnrolComplete`**

```go
func TestHandleEnrolComplete(t *testing.T) {
	s := testServer(t)
	s.enrolRunner = NewEnrolmentRunner(nil)

	req := httptest.NewRequest("POST", "/api/v1/enrol/complete", nil)
	w := httptest.NewRecorder()

	s.handleEnrolComplete(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	// Verify done channel was signalled
	select {
	case <-s.enrolRunner.done:
	default:
		t.Error("done channel not signalled")
	}
}
```

- [ ] **Step 13: Implement `handleEnrolComplete`**

```go
func (s *Server) handleEnrolComplete(w http.ResponseWriter, r *http.Request) {
	if s.enrolRunner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}

	s.enrolRunner.Complete()
	writeJSON(w, map[string]any{"status": "ok"})
}
```

- [ ] **Step 14: Run test to verify it passes**

Run: `go test ./internal/web/ -run TestHandleEnrolComplete -v`
Expected: PASS

- [ ] **Step 15: Add enrolments to `handleStatus` response**

In `internal/web/api.go`, in `handleStatus`, after the rules block and before `writeJSON`:

```go
	if s.enrolRunner != nil {
		status["enrolments"] = s.enrolRunner.States()
	}
```

- [ ] **Step 16: Write test for enrolments in status response**

```go
// Add to enrol_api_test.go
func TestHandleStatus_IncludesEnrolments(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{name: "Mock", fields: []string{"token"}})
	defer enrol.UnregisterEngine("mock")

	s := testServer(t)
	s.enrolRunner = NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	})

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()

	s.handleStatus(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	enrolments, ok := resp["enrolments"].([]any)
	if !ok {
		t.Fatalf("enrolments is %T, want []any", resp["enrolments"])
	}
	if len(enrolments) != 1 {
		t.Fatalf("len(enrolments) = %d, want 1", len(enrolments))
	}
	first := enrolments[0].(map[string]any)
	if first["key"] != "svc" {
		t.Errorf("key = %v, want %q", first["key"], "svc")
	}
	if first["status"] != "pending" {
		t.Errorf("status = %v, want %q", first["status"], "pending")
	}
}
```

- [ ] **Step 17: Run all enrol API tests**

Run: `go test ./internal/web/ -run "TestHandleEnrol|TestHandleStatus_IncludesEnrolments" -v`
Expected: all PASS

- [ ] **Step 18: Run full web package tests**

Run: `go test ./internal/web/ -v`
Expected: all PASS

- [ ] **Step 19: Commit**

```
git add internal/web/enrol_api.go internal/web/enrol_api_test.go internal/web/server.go internal/web/api.go
git commit -m "Add enrolment API endpoints: start, skip, status, complete"
```

---

### Task 4: Auth Callback Redirect

**Files:**
- Modify: `internal/web/auth.go`
- Modify: `internal/web/auth_test.go`

- [ ] **Step 1: Change `handleAuthCallback` to redirect to `/`**

In `internal/web/auth.go`, replace the success response in `handleAuthCallback` (line 118):

```go
// Replace:
fmt.Fprint(w, "Authentication successful! You can close this window.")
// With:
http.Redirect(w, r, "/", http.StatusFound)
```

- [ ] **Step 2: Update the auth callback test**

In `internal/web/auth_test.go`, find the test that checks for "Authentication successful!" and update it to expect a 302 redirect to `/`. If the test uses `testServerWithVault`, the Vault handler needs to return auth data. Find the relevant test and adjust the assertion:

```go
// The test should now check:
if w.Code != http.StatusFound {
	t.Errorf("status = %d, want 302", w.Code)
}
if loc := w.Header().Get("Location"); loc != "/" {
	t.Errorf("Location = %q, want %q", loc, "/")
}
```

- [ ] **Step 3: Run auth tests**

Run: `go test ./internal/web/ -run TestHandleAuth -v`
Expected: PASS

- [ ] **Step 4: Commit**

```
git add internal/web/auth.go internal/web/auth_test.go
git commit -m "Redirect to / after auth success instead of showing static message"
```

---

### Task 5: Daemon Wiring

**Files:**
- Modify: `cmd/dotvault/main.go`
- Modify: `internal/web/server.go`

- [ ] **Step 1: Add `InitEnrolments` to `Server`**

In `internal/web/server.go`, add a method that initializes the `EnrolmentRunner` and checks Vault for already-complete enrolments:

```go
// InitEnrolments sets up the enrolment runner for web-driven enrolment.
// It checks Vault for already-completed enrolments and marks them as such.
func (s *Server) InitEnrolments(ctx context.Context, enrolments map[string]config.Enrolment) {
	if len(enrolments) == 0 {
		return
	}

	s.enrolRunner = NewEnrolmentRunner(enrolments)

	// Check Vault for already-complete enrolments
	for _, info := range s.enrolRunner.States() {
		engine, ok := enrol.GetEngine(info.Engine)
		if !ok {
			continue
		}
		vaultPath := s.userKVPrefix() + info.Key
		secret, err := s.vault.ReadKVv2(ctx, s.kvMount, vaultPath)
		if err != nil {
			slog.Warn("failed to check enrolment in vault", "key", info.Key, "error", err)
			continue
		}
		if secret != nil {
			allPresent := true
			for _, f := range engine.Fields() {
				v, ok := secret.Data[f]
				if !ok || v == nil {
					allPresent = false
					break
				}
				str, ok := v.(string)
				if !ok || strings.TrimSpace(str) == "" {
					allPresent = false
					break
				}
			}
			if allPresent {
				s.enrolRunner.MarkComplete(info.Key)
			}
		}
	}
}

// WaitForEnrolments blocks until the user completes the enrolment page.
// Returns immediately if there are no pending enrolments or no runner.
func (s *Server) WaitForEnrolments() {
	if s.enrolRunner == nil {
		return
	}
	s.enrolRunner.Wait()
}
```

Add the required import for `enrol` package at the top of server.go:

```go
"github.com/goodtune/dotvault/internal/enrol"
```

- [ ] **Step 2: Wire in `cmd/dotvault/main.go`**

In `cmd/dotvault/main.go`, replace the block starting at line 265 (the current enrolment section). The new flow when web is enabled:

```go
// After the WaitForAuth block and lifecycle manager setup:

if webServer != nil {
	// Web mode: let the frontend drive enrolments.
	webServer.InitEnrolments(ctx, cfg.Enrolments)
	webServer.WaitForEnrolments()
} else {
	// CLI mode: terminal-based wizard (unchanged).
	enrolIO := enrol.IO{
		Out:     os.Stderr,
		Browser: browser.OpenURL,
		Log:     slog.Default(),
		Username: username,
		PromptSecret: func(label string) (string, error) {
			fd := int(os.Stdin.Fd())
			if !term.IsTerminal(fd) {
				return "", fmt.Errorf("cannot prompt for passphrase: stdin is not a terminal (use web UI or set passphrase to unsafe)")
			}
			fmt.Fprintf(os.Stderr, "%s ", label)
			pass, err := term.ReadPassword(fd)
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return "", err
			}
			return string(pass), nil
		},
	}
	enrolMgr := enrol.NewManager(enrol.ManagerConfig{
		Enrolments: cfg.Enrolments,
		KVMount:    cfg.Vault.KVMount,
		UserPrefix: cfg.Vault.UserPrefix + username + "/",
	}, vc, enrolIO)
	if _, err := enrolMgr.CheckAll(ctx); err != nil {
		slog.Warn("enrolment check failed", "error", err)
	}
}
```

Keep the background goroutine for periodic enrolment re-check, but only for CLI mode. When web is enabled, the user can revisit the enrolment page via the header indicator.

- [ ] **Step 3: Build and verify**

Run: `go build ./cmd/dotvault/`
Expected: compiles successfully

- [ ] **Step 4: Commit**

```
git add internal/web/server.go cmd/dotvault/main.go
git commit -m "Wire EnrolmentRunner in web mode, keep terminal wizard for CLI"
```

---

### Task 6: Frontend API Methods

**Files:**
- Modify: `internal/web/frontend/src/api.js`

- [ ] **Step 1: Add enrolment API methods**

Add to the end of `api.js`:

```javascript
export async function startEnrolment(key) {
  const token = await getCSRFToken();
  return fetchJSON(`/api/v1/enrol/${encodeURIComponent(key)}/start`, {
    method: 'POST',
    headers: { 'X-CSRF-Token': token },
  });
}

export async function skipEnrolment(key) {
  const token = await getCSRFToken();
  return fetchJSON(`/api/v1/enrol/${encodeURIComponent(key)}/skip`, {
    method: 'POST',
    headers: { 'X-CSRF-Token': token },
  });
}

export async function getEnrolmentStatus(key) {
  return fetchJSON(`/api/v1/enrol/${encodeURIComponent(key)}/status`);
}

export async function completeEnrolments() {
  const token = await getCSRFToken();
  return fetchJSON('/api/v1/enrol/complete', {
    method: 'POST',
    headers: { 'X-CSRF-Token': token },
  });
}

export async function getEnrolPrompt() {
  return fetchJSON('/api/v1/enrol/prompt');
}

export async function submitEnrolSecret(value) {
  const token = await getCSRFToken();
  return fetchJSON('/api/v1/enrol/secret', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
    },
    body: JSON.stringify({ value }),
  });
}
```

- [ ] **Step 2: Commit**

```
git add internal/web/frontend/src/api.js
git commit -m "Add enrolment API methods to frontend client"
```

---

### Task 7: Enrolment Card Component

**Files:**
- Create: `internal/web/frontend/src/components/enrol-card.jsx`

- [ ] **Step 1: Create the `EnrolCard` component**

```jsx
import { h } from 'preact';
import { useState, useEffect, useRef } from 'preact/hooks';
import { startEnrolment, skipEnrolment, getEnrolmentStatus, getEnrolPrompt, submitEnrolSecret } from '../api.js';

export function EnrolCard({ enrolment, onUpdate }) {
  const [localStatus, setLocalStatus] = useState(enrolment.status);
  const [output, setOutput] = useState([]);
  const [error, setError] = useState(enrolment.error || null);
  const [promptLabel, setPromptLabel] = useState(null);
  const [secretValue, setSecretValue] = useState('');
  const [confirmValue, setConfirmValue] = useState('');
  const pollRef = useRef(null);

  useEffect(() => {
    setLocalStatus(enrolment.status);
    setError(enrolment.error || null);
  }, [enrolment.status, enrolment.error]);

  useEffect(() => {
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  function startPolling() {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const [statusData, promptData] = await Promise.all([
          getEnrolmentStatus(enrolment.key),
          getEnrolPrompt(),
        ]);
        setOutput(statusData.output || []);

        if (promptData.pending) {
          setPromptLabel(promptData.label);
        } else {
          setPromptLabel(null);
        }

        if (statusData.status !== 'running') {
          clearInterval(pollRef.current);
          pollRef.current = null;
          setLocalStatus(statusData.status);
          setError(statusData.error || null);
          setPromptLabel(null);
          if (onUpdate) onUpdate();
        }
      } catch (err) {
        console.error('poll error:', err);
      }
    }, 2000);
  }

  async function handleStart() {
    try {
      await startEnrolment(enrolment.key);
      setLocalStatus('running');
      setOutput([]);
      setError(null);
      startPolling();
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleSkip() {
    try {
      await skipEnrolment(enrolment.key);
      setLocalStatus('skipped');
      if (onUpdate) onUpdate();
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleSecretSubmit(e) {
    e.preventDefault();
    try {
      await submitEnrolSecret(secretValue);
      setSecretValue('');
      setConfirmValue('');
      setPromptLabel(null);
    } catch (err) {
      setError(err.message);
    }
  }

  // Parse device code from GitHub engine output
  const deviceCode = output.reduce((found, line) => {
    const match = line.match(/one-time code: (\S+)/);
    return match ? match[1] : found;
  }, null);

  const isGitHub = enrolment.engine === 'github';

  if (localStatus === 'complete') {
    return h('div', { class: 'enrol-card enrol-complete' },
      h('div', { class: 'enrol-card-header' },
        h('div', null,
          h('span', { class: 'enrol-check' }, '\u2713'),
          h('strong', null, enrolment.name),
        ),
        h('span', { class: 'enrol-status-text enrol-status-complete' }, 'Enrolled successfully'),
      ),
    );
  }

  if (localStatus === 'skipped') {
    return h('div', { class: 'enrol-card enrol-skipped' },
      h('div', { class: 'enrol-card-header' },
        h('div', null,
          h('strong', null, enrolment.name),
          h('span', { class: 'enrol-badge' }, 'SKIPPED'),
        ),
        h('span', { class: 'enrol-engine-desc' }, engineDescription(enrolment.engine)),
      ),
    );
  }

  if (localStatus === 'running') {
    return h('div', { class: 'enrol-card enrol-running' },
      h('div', { class: 'enrol-card-header' },
        h('div', null,
          h('strong', null, enrolment.name),
          h('span', { class: 'enrol-badge enrol-badge-running' }, 'RUNNING'),
        ),
      ),
      // GitHub device flow UI
      isGitHub && deviceCode && h('div', { class: 'enrol-device-flow' },
        h('p', { class: 'enrol-device-label' }, 'Enter this code on GitHub:'),
        h('div', { class: 'enrol-device-code' }, deviceCode),
        h('div', { class: 'enrol-device-actions' },
          h('button', {
            class: 'enrol-btn-secondary',
            onClick: () => navigator.clipboard.writeText(deviceCode),
          }, 'Copy Code'),
          h('a', {
            class: 'enrol-btn-secondary',
            href: 'https://github.com/login/device',
            target: '_blank',
            rel: 'noopener',
          }, 'Open GitHub \u2192'),
        ),
        h('p', { class: 'enrol-device-waiting' }, 'Waiting for approval...'),
      ),
      // Passphrase prompt UI
      promptLabel && !isGitHub && h('form', { class: 'enrol-prompt-form', onSubmit: handleSecretSubmit },
        h('label', { class: 'enrol-prompt-label' }, promptLabel),
        h('input', {
          type: 'password',
          class: 'enrol-prompt-input',
          value: secretValue,
          onInput: e => setSecretValue(e.target.value),
          placeholder: 'Enter passphrase',
          autofocus: true,
        }),
        h('div', { class: 'enrol-prompt-actions' },
          h('button', { type: 'submit', class: 'enrol-btn-primary' }, 'Submit'),
        ),
      ),
      // Generic output fallback
      !isGitHub && !promptLabel && output.length > 0 && h('div', { class: 'enrol-output' },
        output.map((line, i) => h('div', { key: i }, line)),
      ),
    );
  }

  if (localStatus === 'failed') {
    return h('div', { class: 'enrol-card enrol-failed' },
      h('div', { class: 'enrol-card-header' },
        h('div', null,
          h('strong', null, enrolment.name),
          h('span', { class: 'enrol-engine-desc' }, engineDescription(enrolment.engine)),
        ),
        h('div', { class: 'enrol-card-actions' },
          h('button', { class: 'enrol-btn-primary', onClick: handleStart }, 'Retry'),
          h('button', { class: 'enrol-btn-secondary', onClick: handleSkip }, 'Skip'),
        ),
      ),
      h('p', { class: 'enrol-error-text' }, error),
    );
  }

  // Pending
  return h('div', { class: 'enrol-card' },
    h('div', { class: 'enrol-card-header' },
      h('div', null,
        h('strong', null, enrolment.name),
        h('span', { class: 'enrol-engine-desc' }, engineDescription(enrolment.engine)),
      ),
      h('div', { class: 'enrol-card-actions' },
        h('button', { class: 'enrol-btn-primary', onClick: handleStart }, 'Start'),
        h('button', { class: 'enrol-btn-secondary', onClick: handleSkip }, 'Skip'),
      ),
    ),
    error && h('p', { class: 'enrol-error-text' }, error),
  );
}

function engineDescription(engine) {
  switch (engine) {
    case 'github': return 'OAuth token via device flow';
    case 'ssh': return 'Ed25519 key generation';
    default: return engine;
  }
}
```

- [ ] **Step 2: Commit**

```
git add internal/web/frontend/src/components/enrol-card.jsx
git commit -m "Add EnrolCard component with engine-specific UI"
```

---

### Task 8: Enrolment Page Component

**Files:**
- Create: `internal/web/frontend/src/components/enrol-page.jsx`

- [ ] **Step 1: Create the `EnrolPage` component**

```jsx
import { h } from 'preact';
import { EnrolCard } from './enrol-card.jsx';
import { completeEnrolments } from '../api.js';

export function EnrolPage({ enrolments, onComplete, onUpdate }) {
  const allAddressed = enrolments.every(
    e => e.status === 'complete' || e.status === 'skipped'
  );

  async function handleContinue() {
    try {
      await completeEnrolments();
      if (onComplete) onComplete();
    } catch (err) {
      console.error('complete error:', err);
    }
  }

  return h('div', { class: 'enrol-page' },
    h('div', { class: 'enrol-container' },
      h('h2', { class: 'enrol-heading' }, 'Complete your setup'),
      h('p', { class: 'enrol-subheading' },
        'The following credentials need to be configured before syncing can begin.',
      ),
      h('div', { class: 'enrol-list' },
        enrolments.map(e =>
          h(EnrolCard, { key: e.key, enrolment: e, onUpdate })
        ),
      ),
      h('div', { class: 'enrol-footer' },
        h('button', {
          class: 'enrol-continue-btn',
          onClick: handleContinue,
        }, allAddressed ? 'Continue to Dashboard \u2192' : 'Skip remaining and continue \u2192'),
      ),
    ),
  );
}
```

- [ ] **Step 2: Commit**

```
git add internal/web/frontend/src/components/enrol-page.jsx
git commit -m "Add EnrolPage component with continue/skip-all button"
```

---

### Task 9: SPA Routing and Header Indicator

**Files:**
- Modify: `internal/web/frontend/src/app.jsx`
- Modify: `internal/web/frontend/src/components/status-bar.jsx`

- [ ] **Step 1: Update `app.jsx` to route to enrolment page**

Replace the contents of `app.jsx`:

```jsx
import { h, Fragment } from 'preact';
import { useState, useEffect } from 'preact/hooks';
import { StatusBar } from './components/status-bar.jsx';
import { Sidebar } from './components/sidebar.jsx';
import { SecretPanel } from './components/secret-panel.jsx';
import { OAuthBanner } from './components/oauth-banner.jsx';
import { LoginPage } from './components/login-page.jsx';
import { EnrolPage } from './components/enrol-page.jsx';
import { getStatus, getRules, listSecrets } from './api.js';

export function App() {
  const [status, setStatus] = useState(null);
  const [rules, setRules] = useState([]);
  const [keys, setKeys] = useState([]);
  const [selectedKey, setSelectedKey] = useState(null);
  const [error, setError] = useState(null);
  const [enrolDismissed, setEnrolDismissed] = useState(false);

  useEffect(() => {
    loadStatus();
  }, []);

  // Poll for dashboard updates when authenticated.
  useEffect(() => {
    if (!status?.authenticated) return;
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, [status?.authenticated]);

  async function loadStatus() {
    try {
      const statusData = await getStatus();
      setStatus(statusData);
      if (statusData.authenticated) {
        loadData();
      }
    } catch (err) {
      setError(err.message);
    }
  }

  async function loadData() {
    try {
      const [statusData, rulesData, secretsData] = await Promise.all([
        getStatus(),
        getRules(),
        listSecrets(),
      ]);
      setStatus(statusData);
      setRules(rulesData.rules || []);
      setKeys(secretsData.keys || []);
      setError(null);
    } catch (err) {
      setError(err.message);
    }
  }

  // Show login page if not authenticated.
  if (status && !status.authenticated) {
    return h(LoginPage, {
      authMethod: status.auth_method,
      onAuth: loadData,
      customText: status.login_text,
    });
  }

  // Loading state.
  if (!status) {
    return h('div', { class: 'login-container' },
      h('div', { class: 'login-card' },
        h('h1', { class: 'login-title' }, '.vault'),
        error
          ? h('p', { class: 'login-error' }, error)
          : h('p', null, 'Loading...'),
      ),
    );
  }

  // Check for pending enrolments.
  const enrolments = status.enrolments || [];
  const pendingEnrolments = enrolments.filter(
    e => e.status === 'pending' || e.status === 'running' || e.status === 'failed'
  );

  // Show enrolment page if there are pending enrolments and user hasn't dismissed.
  if (pendingEnrolments.length > 0 && !enrolDismissed) {
    return h(EnrolPage, {
      enrolments,
      onComplete: () => {
        setEnrolDismissed(true);
        loadData();
      },
      onUpdate: loadStatus,
    });
  }

  const oauthRules = rules.filter(r => r.has_oauth);

  return h(Fragment, null,
    h(StatusBar, {
      status,
      onSync: loadData,
      pendingEnrolments: enrolDismissed ? 0 : pendingEnrolments.length,
      onEnrolClick: () => setEnrolDismissed(false),
    }),
    error && h('div', { class: 'error-banner' }, error),
    oauthRules.length > 0 && h(OAuthBanner, { rules: oauthRules }),
    h('div', { class: 'main-layout' },
      h(Sidebar, { keys, selected: selectedKey, onSelect: setSelectedKey }),
      h(SecretPanel, { secretPath: selectedKey, status, customText: status.secret_view_text }),
    ),
  );
}
```

- [ ] **Step 2: Update `status-bar.jsx` to show pending enrolments indicator**

Replace the contents of `status-bar.jsx`:

```jsx
import { h } from 'preact';
import { useState } from 'preact/hooks';
import { triggerSync, getVaultToken } from '../api.js';

export function StatusBar({ status, onSync, pendingEnrolments, onEnrolClick }) {
  const [syncing, setSyncing] = useState(false);
  const [tokenCopied, setTokenCopied] = useState(false);

  async function handleSync() {
    setSyncing(true);
    try {
      await triggerSync();
      if (onSync) await onSync();
    } catch (err) {
      console.error('sync failed:', err);
    } finally {
      setSyncing(false);
    }
  }

  async function handleCopyToken() {
    try {
      const data = await getVaultToken();
      await navigator.clipboard.writeText(data.token);
      setTokenCopied(true);
      setTimeout(() => setTokenCopied(false), 2000);
    } catch (err) {
      console.error('copy token failed:', err);
    }
  }

  const authStatus = status?.authenticated ? 'Connected' : 'Disconnected';
  const authClass = status?.authenticated ? 'status-ok' : 'status-error';

  const vaultURL = status?.vault_address;
  const safeVaultURL = vaultURL && /^https?:\/\//i.test(vaultURL) ? vaultURL : null;

  return h('header', { class: 'status-bar' },
    h('div', { class: 'status-left' },
      h('span', { class: 'app-title' },
        '.vault',
        status?.version && h('span', { class: 'app-version' }, ' v' + status.version),
      ),
      h('span', { class: `status-indicator ${authClass}` }, authStatus),
      safeVaultURL && h('a', {
        class: 'vault-link',
        href: safeVaultURL,
        target: '_blank',
        rel: 'noopener noreferrer',
      }, 'Vault \u2197'),
      pendingEnrolments > 0 && h('button', {
        class: 'enrol-indicator',
        onClick: onEnrolClick,
      }, pendingEnrolments + ' pending'),
    ),
    h('div', { class: 'status-right' },
      status?.time && h('span', { class: 'last-sync' },
        'Updated: ', new Date(status.time).toLocaleTimeString(),
      ),
      status?.authenticated && h('button', {
        class: 'copy-token-btn' + (tokenCopied ? ' copied' : ''),
        onClick: handleCopyToken,
        title: tokenCopied ? 'Token copied!' : 'Copy Vault token to clipboard',
      }, tokenCopied ? '\u2705' : '\u{1F4CB}'),
      h('button', {
        class: 'sync-btn',
        onClick: handleSync,
        disabled: syncing,
      }, syncing ? 'Syncing...' : 'Sync Now'),
    ),
  );
}
```

- [ ] **Step 3: Commit**

```
git add internal/web/frontend/src/app.jsx internal/web/frontend/src/components/status-bar.jsx
git commit -m "Add enrolment page routing and header indicator to SPA"
```

---

### Task 10: Enrolment Page Styles

**Files:**
- Modify: `internal/web/static/style.css`

- [ ] **Step 1: Add enrolment styles**

Append to the end of `style.css`:

```css
/* Enrolment page */
.enrol-page {
  display: flex;
  justify-content: center;
  padding: 40px 20px;
  min-height: 100vh;
  background: #f5f5f5;
}
.enrol-container { width: 100%; max-width: 600px; }
.enrol-heading { font-size: 22px; font-weight: 700; color: #1a1a2e; margin-bottom: 4px; }
.enrol-subheading { font-size: 14px; color: #888; margin-bottom: 24px; }

.enrol-list { display: flex; flex-direction: column; gap: 12px; }

.enrol-card {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 16px;
}
.enrol-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.enrol-card-header strong { font-size: 15px; color: #333; }
.enrol-engine-desc { font-size: 13px; color: #888; margin-left: 8px; }

.enrol-card-actions { display: flex; gap: 8px; }

.enrol-btn-primary {
  background: #3a86ff;
  color: white;
  border: none;
  padding: 6px 16px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 13px;
  font-family: inherit;
}
.enrol-btn-primary:hover { background: #2667cc; }

.enrol-btn-secondary {
  background: white;
  color: #666;
  border: 1px solid #ddd;
  padding: 6px 12px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 13px;
  text-decoration: none;
  font-family: inherit;
}
.enrol-btn-secondary:hover { background: #f8f9fa; }

/* Running state */
.enrol-running { border-color: #3a86ff; }
.enrol-badge {
  font-size: 11px;
  color: #888;
  margin-left: 8px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.enrol-badge-running { color: #3a86ff; }

/* GitHub device flow */
.enrol-device-flow {
  margin-top: 16px;
  padding: 16px;
  background: #f8f9fa;
  border-radius: 6px;
  text-align: center;
}
.enrol-device-label { font-size: 13px; color: #888; margin-bottom: 8px; }
.enrol-device-code {
  font-size: 28px;
  font-weight: 700;
  letter-spacing: 4px;
  color: #1a1a2e;
  font-family: 'SF Mono', Monaco, monospace;
  margin-bottom: 12px;
}
.enrol-device-actions { display: flex; gap: 8px; justify-content: center; }
.enrol-device-waiting { font-size: 12px; color: #888; margin-top: 12px; }

/* Passphrase prompt */
.enrol-prompt-form { margin-top: 16px; padding: 16px; background: #f8f9fa; border-radius: 6px; }
.enrol-prompt-label { font-size: 13px; color: #888; display: block; margin-bottom: 6px; }
.enrol-prompt-input {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
  font-family: inherit;
  margin-bottom: 8px;
  box-sizing: border-box;
}
.enrol-prompt-input:focus { outline: none; border-color: #3a86ff; box-shadow: 0 0 0 2px rgba(58,134,255,0.2); }
.enrol-prompt-actions { display: flex; gap: 8px; }

/* Generic output */
.enrol-output {
  margin-top: 12px;
  padding: 12px;
  background: #f8f9fa;
  border-radius: 6px;
  font-size: 13px;
  font-family: 'SF Mono', Monaco, monospace;
  color: #555;
}

/* Complete state */
.enrol-complete { border-color: #d1fae5; }
.enrol-check { color: #059669; margin-right: 6px; }
.enrol-status-text { font-size: 13px; }
.enrol-status-complete { color: #059669; }

/* Skipped state */
.enrol-skipped { opacity: 0.6; }

/* Failed state */
.enrol-failed { border-color: #fecaca; }
.enrol-error-text { color: #c0392b; font-size: 13px; margin-top: 8px; }

/* Footer */
.enrol-footer { margin-top: 24px; text-align: center; }
.enrol-continue-btn {
  background: #059669;
  color: white;
  border: none;
  padding: 10px 32px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 600;
  font-family: inherit;
}
.enrol-continue-btn:hover { background: #047857; }

/* Header indicator */
.enrol-indicator {
  background: #fef3c7;
  color: #92400e;
  border: none;
  padding: 2px 10px;
  border-radius: 12px;
  cursor: pointer;
  font-size: 12px;
  font-family: inherit;
}
.enrol-indicator:hover { background: #fde68a; }
```

- [ ] **Step 2: Commit**

```
git add internal/web/static/style.css
git commit -m "Add enrolment page styles"
```

---

### Task 11: Build Frontend and Verify

**Files:**
- Rebuild: `internal/web/frontend/`
- Verify: `internal/web/static/app.js`

- [ ] **Step 1: Build the frontend**

Run: `cd internal/web/frontend && npm run build`
Expected: esbuild completes without errors, `internal/web/static/app.js` is updated

- [ ] **Step 2: Run all Go tests**

Run: `go test ./internal/web/ -v`
Expected: all PASS

- [ ] **Step 3: Run full build**

Run: `go build ./cmd/dotvault/`
Expected: compiles successfully

- [ ] **Step 4: Commit built assets**

```
git add internal/web/static/app.js
git commit -m "Rebuild frontend with enrolment page"
```

---

### Task 12: Manual Integration Test

**Files:** None (validation only)

- [ ] **Step 1: Start the dev environment**

```bash
docker compose down && docker compose up -d
```

Wait for vault-init to complete:
```bash
docker compose logs vault-init --tail 3
```
Expected: "Vault ready"

- [ ] **Step 2: Start the daemon**

```bash
go run ./cmd/dotvault run --config config.dev.yaml
```

- [ ] **Step 3: Open the web UI and verify OIDC login redirects to enrolment page**

Navigate to `http://127.0.0.1:9000/`. Click "Login with OIDC". Complete Dex approval. Verify you land on the enrolment page (not "Authentication successful!") showing both `gh` and `ssh` enrolments as pending.

- [ ] **Step 4: Test skip and start flows**

Skip the SSH enrolment. Verify the card dims and shows "SKIPPED". Verify the GitHub card shows "Start" and "Skip" buttons. Click "Continue to Dashboard". Verify you reach the dashboard with the pending enrolments indicator in the header.

- [ ] **Step 5: Kill the daemon**

```bash
kill $(lsof -ti :9000) 2>/dev/null
```

- [ ] **Step 6: Commit any fixes discovered during testing**

If any adjustments are needed, fix and commit.
