package web

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
	key        string
	engineName string // config engine string, e.g. "github"
	engine     enrol.Engine
	settings   map[string]any
	status     string   // pending, running, complete, skipped, failed
	output     []string // captured IO.Out lines
	errMsg     string
	doneCh     chan struct{} // closed when engine finishes
	mu         sync.Mutex
}

// Sentinel errors for enrolment operations.
var (
	ErrEnrolNotFound       = fmt.Errorf("enrolment not found")
	ErrEnrolAlreadyRunning = fmt.Errorf("enrolment already running")
	ErrEnrolBusy           = fmt.Errorf("another enrolment is running")
	ErrEnrolInvalidEngine  = fmt.Errorf("enrolment has no valid engine")
	ErrEnrolNotStartable   = fmt.Errorf("enrolment is not in a startable state")
)

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
			slog.Warn("unknown enrolment engine", "key", key, "engine", e.Engine)
			s := &enrolState{
				key:        key,
				engineName: e.Engine,
				settings:   e.Settings,
				status:     "failed",
				errMsg:     fmt.Sprintf("unknown engine %q", e.Engine),
				doneCh:     make(chan struct{}),
			}
			close(s.doneCh)
			states[key] = s
			continue
		}
		states[key] = &enrolState{
			key:        key,
			engineName: e.Engine,
			engine:     engine,
			settings:   e.Settings,
			status:     "pending",
			doneCh:     make(chan struct{}),
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
			Key:    s.key,
			Engine: s.engineName,
			Status: s.status,
			Output: append([]string{}, s.output...),
			Error:  s.errMsg,
		}
		if s.engine != nil {
			info.EngineName = s.engine.Name()
			info.Fields = s.engine.Fields()
		} else {
			info.EngineName = s.engineName
			info.Fields = []string{}
		}
		s.mu.Unlock()
		result = append(result, info)
	}
	return result
}

// Skip marks an enrolment as skipped. Returns error if key not found or running.
func (r *EnrolmentRunner) Skip(key string) error {
	r.mu.RLock()
	s, ok := r.states[key]
	r.mu.RUnlock()
	if !ok {
		return ErrEnrolNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.status {
	case "pending":
		s.status = "skipped"
		return nil
	case "failed":
		s.status = "skipped"
		s.output = nil
		s.errMsg = ""
		return nil
	case "running":
		return ErrEnrolAlreadyRunning
	default:
		return ErrEnrolNotStartable
	}
}

// GetState returns the state of a single enrolment.
func (r *EnrolmentRunner) GetState(key string) (EnrolStateInfo, error) {
	r.mu.RLock()
	s, ok := r.states[key]
	r.mu.RUnlock()
	if !ok {
		return EnrolStateInfo{}, ErrEnrolNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	info := EnrolStateInfo{
		Key:    s.key,
		Engine: s.engineName,
		Status: s.status,
		Output: append([]string{}, s.output...),
		Error:  s.errMsg,
	}
	if s.engine != nil {
		info.EngineName = s.engine.Name()
		info.Fields = s.engine.Fields()
	} else {
		info.EngineName = s.engineName
		info.Fields = []string{}
	}
	return info, nil
}

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
			// Incomplete line — put it back.
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
// Returns error if the key is unknown, the enrolment is already running,
// or another enrolment is currently running (only one may run at a time
// because the secret prompt mechanism is global).
func (r *EnrolmentRunner) Start(ctx context.Context, key string, vc *vault.Client, kvMount, userPrefix, username string, promptSecret PromptSecretFunc) error {
	r.mu.Lock()
	s, ok := r.states[key]
	if !ok {
		r.mu.Unlock()
		return ErrEnrolNotFound
	}

	// Enforce single-running: the prompt mechanism is global, so only
	// one enrolment engine can run at a time.
	for otherKey, other := range r.states {
		if otherKey == key {
			continue
		}
		other.mu.Lock()
		running := other.status == "running"
		other.mu.Unlock()
		if running {
			r.mu.Unlock()
			return ErrEnrolBusy
		}
	}

	s.mu.Lock()
	if s.status == "running" {
		s.mu.Unlock()
		r.mu.Unlock()
		return ErrEnrolAlreadyRunning
	}
	if s.status != "pending" && s.status != "failed" {
		s.mu.Unlock()
		r.mu.Unlock()
		return ErrEnrolNotStartable
	}
	if s.engine == nil {
		s.mu.Unlock()
		r.mu.Unlock()
		return ErrEnrolInvalidEngine
	}
	s.status = "running"
	s.output = nil
	s.errMsg = ""
	s.doneCh = make(chan struct{})
	s.mu.Unlock()
	r.mu.Unlock()

	capture := &lineCapture{state: s}

	io := enrol.IO{
		Out:      capture,
		In:       strings.NewReader("\n"), // auto-proceed for engines that wait for Enter
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
			close(s.doneCh)
			return
		}

		// Validate all fields present.
		data := make(map[string]any, len(creds))
		for k, v := range creds {
			data[k] = v
		}
		if !enrol.HasAllFields(data, s.engine.Fields()) {
			s.mu.Lock()
			s.status = "failed"
			s.errMsg = "engine returned incomplete credentials"
			s.mu.Unlock()
			close(s.doneCh)
			return
		}

		// Write to Vault.
		vaultPath := userPrefix + key
		if err := vc.WriteKVv2(ctx, kvMount, vaultPath, data); err != nil {
			s.mu.Lock()
			s.status = "failed"
			s.errMsg = fmt.Sprintf("vault write failed: %v", err)
			s.mu.Unlock()
			close(s.doneCh)
			return
		}

		s.mu.Lock()
		s.status = "complete"
		s.mu.Unlock()
		close(s.doneCh)
	}()

	return nil
}

// WaitForKey blocks until the given enrolment is no longer "running".
// Returns immediately if the enrolment is not found or not running.
func (r *EnrolmentRunner) WaitForKey(key string) {
	r.mu.RLock()
	s, ok := r.states[key]
	r.mu.RUnlock()
	if !ok {
		return
	}
	s.mu.Lock()
	status := s.status
	ch := s.doneCh
	s.mu.Unlock()
	if status != "running" {
		return
	}
	<-ch
}
