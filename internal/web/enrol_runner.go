package web

import (
	"fmt"
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
			Key:        s.key,
			Engine:     s.engineName,
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
