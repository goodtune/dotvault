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
	Key          string   `json:"key"`
	Engine       string   `json:"engine"`
	EngineName   string   `json:"name"`
	Status       string   `json:"status"`
	Fields       []string `json:"fields"`
	Output       []string `json:"output,omitempty"`
	Error        string   `json:"error,omitempty"`
	HelpTextHTML string   `json:"help_text_html,omitempty"`
	// Unattended mirrors enrol.EngineUnattended for this enrolment's engine:
	// it needs no user interaction. Carried on the snapshot rather than
	// re-derived by name at each call site so there is one answer per state.
	Unattended bool `json:"unattended,omitempty"`
}

type enrolState struct {
	key          string
	engineName   string // config engine string, e.g. "github"
	engine       enrol.Engine
	settings     map[string]any
	helpTextHTML string   // pre-rendered from config HelpText, mirroring Web.LoginText/SecretViewText
	status       string   // pending, running, complete, skipped, failed
	output       []string // captured IO.Out lines
	errMsg       string
	doneCh       chan struct{} // closed when engine finishes
	mu           sync.Mutex
}

// infoLocked snapshots this enrolment for the API and the UI. The caller must
// hold s.mu. It is shared by States and GetState so the two cannot drift —
// they previously carried identical copies of this construction.
func (s *enrolState) infoLocked() EnrolStateInfo {
	info := EnrolStateInfo{
		Key:          s.key,
		Engine:       s.engineName,
		Status:       s.status,
		Output:       append([]string{}, s.output...),
		Error:        s.errMsg,
		HelpTextHTML: s.helpTextHTML,
	}
	if s.engine != nil {
		info.EngineName = s.engine.Name()
		info.Fields = enrol.EngineFields(s.engine, s.settings)
		info.Unattended = enrol.EngineUnattended(s.engine)
	} else {
		info.EngineName = s.engineName
		info.Fields = []string{}
	}
	return info
}

// Sentinel errors for enrolment operations.
var (
	ErrEnrolNotFound       = fmt.Errorf("enrolment not found")
	ErrEnrolAlreadyRunning = fmt.Errorf("enrolment already running")
	ErrEnrolBusy           = fmt.Errorf("another enrolment is running")
	ErrEnrolInvalidEngine  = fmt.Errorf("enrolment has no valid engine")
	ErrEnrolNotStartable   = fmt.Errorf("enrolment is not in a startable state")
	ErrEnrolNotResettable  = fmt.Errorf("enrolment is not in a resettable state")
)

// EnrolmentRunner manages per-enrolment lifecycle for web mode.
type EnrolmentRunner struct {
	states map[string]*enrolState
	order  []string // sorted keys for stable ordering
	done   chan struct{}
	// dismissed latches once Complete has been called, so the first-run
	// wizard stays dismissed for the rest of this runner's life — including
	// the case where the user skipped every enrolment, which leaves nothing
	// "complete" for NeedsWizard to notice. A config reload builds a new
	// runner and so deliberately re-evaluates from scratch.
	dismissed bool
	mu        sync.RWMutex
}

// NewEnrolmentRunner creates a runner from the enrolments config.
// All enrolments start as "pending". Call MarkComplete() for enrolments
// that are already satisfied in Vault before exposing them in the UI.
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
				key:          key,
				engineName:   e.Engine,
				settings:     e.Settings,
				helpTextHTML: renderMarkdown(e.HelpText),
				status:       "failed",
				errMsg:       fmt.Sprintf("unknown engine %q", e.Engine),
				doneCh:       make(chan struct{}),
			}
			close(s.doneCh)
			states[key] = s
			continue
		}
		states[key] = &enrolState{
			key:          key,
			engineName:   e.Engine,
			engine:       engine,
			settings:     e.Settings,
			helpTextHTML: renderMarkdown(e.HelpText),
			status:       "pending",
			doneCh:       make(chan struct{}),
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
		info := s.infoLocked()
		s.mu.Unlock()
		result = append(result, info)
	}
	return result
}

// Reset returns a complete or skipped enrolment to pending so it can be re-run.
// Returns an error if the key is not found, the enrolment is running, or it
// is in a state that cannot be reset (e.g. pending or failed).
func (r *EnrolmentRunner) Reset(key string) error {
	r.mu.RLock()
	s, ok := r.states[key]
	r.mu.RUnlock()
	if !ok {
		return ErrEnrolNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.status {
	case "complete", "skipped":
		s.status = "pending"
		s.output = nil
		s.errMsg = ""
		s.doneCh = make(chan struct{})
		return nil
	case "running":
		return ErrEnrolAlreadyRunning
	default:
		return ErrEnrolNotResettable
	}
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
	return s.infoLocked(), nil
}

// AnyRunning reports whether any enrolment is currently executing. The
// daemon's config-refresh loop checks it before swapping the runner for a
// changed enrolments map, so a mid-run engine is never orphaned.
func (r *EnrolmentRunner) AnyRunning() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.states {
		s.mu.Lock()
		running := s.status == "running"
		s.mu.Unlock()
		if running {
			return true
		}
	}
	return false
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

// NeedsWizard reports whether the first-run enrolment wizard is warranted:
// at least one enrolment is actually runnable, none has been completed, and
// the user has not already dismissed the wizard.
//
// "None completed" is the deliberate trigger. A user with credentials in
// Vault has done first-run setup, so an outstanding enrolment they skipped
// (or a newly added one) must not keep hijacking their entry to the site —
// it waits for them on /ui/enrolments/ instead.
func (r *EnrolmentRunner) NeedsWizard() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.dismissed {
		return false
	}
	runnable := false
	for _, key := range r.order {
		s, ok := r.states[key]
		if !ok {
			continue
		}
		s.mu.Lock()
		status := s.status
		engine := s.engine
		s.mu.Unlock()
		// An unattended enrolment (the copy engine) is not evidence either
		// way and is skipped entirely. It gives the user nothing to do, so
		// it must not make the wizard fire; and because it completes on its
		// own — often before a human has seen anything — letting it satisfy
		// the "something is already enrolled" test below would suppress the
		// wizard for the interactive enrolments that genuinely need one.
		if engine != nil && enrol.EngineUnattended(engine) {
			continue
		}
		if status == "complete" {
			return false
		}
		// A skipped enrolment has been addressed: the user was shown it and
		// declined. It must not keep the wizard standing, or the exit link
		// would bounce a user who skipped everything straight back here with
		// no way out — the case the old Continue button's explicit dismissal
		// used to cover.
		if status == "skipped" {
			continue
		}
		if engine != nil {
			runnable = true
		}
	}
	return runnable
}

// Complete signals that the user is done with enrolments and dismisses the
// wizard. Idempotent: the web entry point calls it whenever a user reaches
// the main site, which is what keeps a daemon from waiting on a wizard
// nobody is going to finish.
func (r *EnrolmentRunner) Complete() {
	r.mu.Lock()
	r.dismissed = true
	r.mu.Unlock()
	select {
	case r.done <- struct{}{}:
	default:
	}
}

// Wait blocks until Complete() is called. Returns immediately unless the
// first-run wizard is warranted — the daemon only defers its startup for a
// wizard the user will actually be shown, never for an enrolment they can
// address later from the main site.
func (r *EnrolmentRunner) Wait() {
	if !r.NeedsWizard() {
		return
	}
	// Say so. Everything past this point in daemon startup — the sync engine
	// included — waits for a human to open the web UI, and on an unattended
	// host nobody ever will: managed files simply stop being refreshed. That
	// is the correct behaviour (there are credentials the daemon cannot
	// obtain on its own) but it is indistinguishable from a hung daemon in
	// the log, so it must not be silent. /readyz reports not-ready for the
	// same reason.
	slog.Info("waiting for first-run enrolment: open the web UI to continue, or the daemon will not begin syncing")
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

	vaultPath := userPrefix + key
	io := enrol.IO{
		Out:        capture,
		In:         strings.NewReader("\n"), // auto-proceed for engines that wait for Enter
		Log:        slog.Default(),
		Username:   username,
		Vault:      vc,
		KVMount:    kvMount,
		TargetPath: vaultPath,
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
		if !enrol.HasAllFields(data, enrol.EngineFields(s.engine, s.settings)) {
			s.mu.Lock()
			s.status = "failed"
			s.errMsg = "engine returned incomplete credentials"
			s.mu.Unlock()
			close(s.doneCh)
			return
		}

		// Write to Vault.
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
