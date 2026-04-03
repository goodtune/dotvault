package enrol

import (
	"context"
	"sync"
)

// EnrolmentState represents the current state of an enrolment flow.
type EnrolmentState string

const (
	StateIdle         EnrolmentState = "idle"
	StateRunning      EnrolmentState = "running"
	StateAwaitingUser EnrolmentState = "awaiting_user" // device code displayed, waiting for user
	StateComplete     EnrolmentState = "complete"
	StateFailed       EnrolmentState = "failed"
)

// EnrolmentStatus holds the current status of an enrolment flow.
type EnrolmentStatus struct {
	State      EnrolmentState  `json:"state"`
	DeviceCode *DeviceCodeInfo `json:"device_code,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// Tracker tracks the state of async enrolment flows for the web UI.
type Tracker struct {
	mu       sync.Mutex
	statuses map[string]*EnrolmentStatus
}

// NewTracker creates a new enrolment tracker.
func NewTracker() *Tracker {
	return &Tracker{
		statuses: make(map[string]*EnrolmentStatus),
	}
}

// GetStatus returns the current status for an enrolment key, or nil if not tracked.
func (t *Tracker) GetStatus(key string) *EnrolmentStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.statuses[key]
	if !ok {
		return nil
	}
	// Return a copy to avoid races.
	cp := *s
	if s.DeviceCode != nil {
		dc := *s.DeviceCode
		cp.DeviceCode = &dc
	}
	return &cp
}

// Start begins tracking an enrolment flow using the Manager.RunOne method.
// Returns false if the enrolment is already running.
func (t *Tracker) Start(ctx context.Context, mgr *Manager, key string) bool {
	t.mu.Lock()
	if s, ok := t.statuses[key]; ok && s.State == StateRunning || ok && s.State == StateAwaitingUser {
		t.mu.Unlock()
		return false
	}
	t.statuses[key] = &EnrolmentStatus{State: StateRunning}
	t.mu.Unlock()

	onDeviceCode := func(info DeviceCodeInfo) {
		t.mu.Lock()
		defer t.mu.Unlock()
		if s, ok := t.statuses[key]; ok {
			s.State = StateAwaitingUser
			s.DeviceCode = &info
		}
	}

	ch := mgr.RunOne(ctx, key, onDeviceCode)

	go func() {
		err := <-ch
		t.mu.Lock()
		defer t.mu.Unlock()
		if err != nil {
			t.statuses[key] = &EnrolmentStatus{
				State: StateFailed,
				Error: err.Error(),
			}
		} else {
			t.statuses[key] = &EnrolmentStatus{State: StateComplete}
		}
	}()

	return true
}

// Clear removes the status for a key, allowing it to be started again.
func (t *Tracker) Clear(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.statuses, key)
}

// SetForTest sets an enrolment status directly. Intended for testing only.
func (t *Tracker) SetForTest(key string, status *EnrolmentStatus) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.statuses[key] = status
}
