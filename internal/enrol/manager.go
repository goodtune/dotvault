package enrol

import (
	"context"
	"fmt"
	iolib "io"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
)

// ManagerConfig holds configuration for the Manager.
type ManagerConfig struct {
	Enrolments map[string]config.Enrolment
	KVMount    string // e.g. "kv"
	UserPrefix string // e.g. "users/jdoe"
	WebMode    bool   // when true, skip interactive CLI wizard
}

// Manager orchestrates enrolment checks and the acquisition wizard.
type Manager struct {
	cfg   ManagerConfig
	vault *vault.Client
	io    IO
	mu    sync.Mutex
}

// NewManager creates a new Manager.
func NewManager(cfg ManagerConfig, vc *vault.Client, io IO) *Manager {
	// Normalize UserPrefix to have exactly one trailing slash so callers
	// don't need to remember to include it.
	cfg.UserPrefix = strings.TrimRight(cfg.UserPrefix, "/") + "/"
	// Default IO fields to safe no-ops to prevent nil pointer panics.
	if io.Log == nil {
		io.Log = slog.Default()
	}
	if io.Out == nil {
		io.Out = iolib.Discard
	}
	return &Manager{
		cfg:   cfg,
		vault: vc,
		io:    io,
	}
}

// UpdateConfig replaces the enrolment map (called when config changes are detected).
func (m *Manager) UpdateConfig(enrolments map[string]config.Enrolment) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.Enrolments = enrolments
}

// CheckAll checks all configured enrolments and runs the wizard for any that are
// missing or incomplete. Returns enrolled=true if any new enrolments were written
// to Vault. In web mode, the wizard is skipped — pending enrolments are logged
// and must be completed via the web UI.
func (m *Manager) CheckAll(ctx context.Context) (enrolled bool, err error) {
	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()

	if len(cfg.Enrolments) == 0 {
		return false, nil
	}

	pending, err := m.findPending(ctx, cfg)
	if err != nil {
		return false, err
	}
	if len(pending) == 0 {
		return false, nil
	}

	// In web mode, never run the interactive CLI wizard. Log pending
	// enrolments so they can be completed via the web UI.
	if cfg.WebMode {
		for _, p := range pending {
			m.io.Log.Info("enrolment pending — complete via web UI", "key", p.key, "engine", p.engine.Name())
		}
		return false, nil
	}

	results := runWizard(ctx, pending, m.io)

	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	enrolled = m.writeResults(ctx, cfg, results)
	return enrolled, nil
}

// writeResults validates and writes enrolment credentials to Vault.
// Returns true if any credentials were written.
func (m *Manager) writeResults(ctx context.Context, cfg ManagerConfig, results map[string]map[string]string) bool {
	var enrolled bool
	for key, creds := range results {
		enrolment := cfg.Enrolments[key]
		engine, ok := GetEngine(enrolment.Engine)
		if !ok {
			m.io.Log.Error("engine not found for result key", "key", key)
			continue
		}

		// Validate all required fields are present and non-empty before
		// writing to Vault. Incomplete credentials are silently discarded;
		// the enrolment will be retried on the next cycle.
		data := make(map[string]any, len(creds))
		for k, v := range creds {
			data[k] = v
		}
		if !hasAllFields(data, engine.Fields()) {
			m.io.Log.Error("engine returned incomplete credentials, skipping vault write", "key", key, "engine", enrolment.Engine)
			fmt.Fprintf(m.io.Out, "✗ %s — engine returned incomplete credentials (will retry next cycle)\n", key)
			continue
		}

		vaultPath := cfg.UserPrefix + key
		if writeErr := m.vault.WriteKVv2(ctx, cfg.KVMount, vaultPath, data); writeErr != nil {
			m.io.Log.Error("failed to write enrolment to vault", "key", key, "error", writeErr)
			fmt.Fprintf(m.io.Out, "✗ %s — vault write failed (credentials lost, will retry next cycle)\n", key)
			continue
		}
		enrolled = true
		m.io.Log.Info("enrolment written to vault", "key", key, "path", vaultPath)
	}
	return enrolled
}

// PendingEnrolmentInfo describes a pending enrolment for API consumers.
type PendingEnrolmentInfo struct {
	Key        string `json:"key"`
	EngineName string `json:"engine_name"`
}

// FindPending returns the list of enrolments that are missing or incomplete in Vault.
func (m *Manager) FindPending(ctx context.Context) ([]PendingEnrolmentInfo, error) {
	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()

	if len(cfg.Enrolments) == 0 {
		return nil, nil
	}

	pending, err := m.findPending(ctx, cfg)
	if err != nil {
		return nil, err
	}

	result := make([]PendingEnrolmentInfo, len(pending))
	for i, p := range pending {
		result[i] = PendingEnrolmentInfo{
			Key:        p.key,
			EngineName: p.engine.Name(),
		}
	}
	return result, nil
}

// RunOne starts a single enrolment by key. It runs the engine asynchronously and
// calls onDeviceCode when a device code flow begins. The returned channel receives
// nil on success or an error on failure.
func (m *Manager) RunOne(ctx context.Context, key string, onDeviceCode DeviceCodeCallback) <-chan error {
	ch := make(chan error, 1)

	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()

	enrolment, ok := cfg.Enrolments[key]
	if !ok {
		ch <- fmt.Errorf("enrolment %q not configured", key)
		return ch
	}
	engine, ok := GetEngine(enrolment.Engine)
	if !ok {
		ch <- fmt.Errorf("unknown engine %q for enrolment %q", enrolment.Engine, key)
		return ch
	}

	go func() {
		eio := IO{
			Out:          m.io.Out,
			Browser:      m.io.Browser,
			Log:          m.io.Log,
			OnDeviceCode: onDeviceCode,
		}

		creds, err := engine.Run(ctx, enrolment.Settings, eio)
		if err != nil {
			ch <- err
			return
		}

		results := map[string]map[string]string{key: creds}
		if !m.writeResults(ctx, cfg, results) {
			ch <- fmt.Errorf("failed to write credentials for %q", key)
			return
		}
		ch <- nil
	}()

	return ch
}

// findPending returns enrolments that are missing or incomplete in Vault.
func (m *Manager) findPending(ctx context.Context, cfg ManagerConfig) ([]pendingEnrolment, error) {
	var pending []pendingEnrolment

	keys := make([]string, 0, len(cfg.Enrolments))
	for key := range cfg.Enrolments {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		enrolment := cfg.Enrolments[key]
		engine, ok := GetEngine(enrolment.Engine)
		if !ok {
			m.io.Log.Error("unknown enrolment engine, skipping", "key", key, "engine", enrolment.Engine)
			continue
		}

		vaultPath := cfg.UserPrefix + key
		secret, err := m.vault.ReadKVv2(ctx, cfg.KVMount, vaultPath)
		if err != nil {
			return nil, fmt.Errorf("check vault for enrolment %q: %w", key, err)
		}

		if secret != nil && hasAllFields(secret.Data, engine.Fields()) {
			m.io.Log.Debug("enrolment already complete", "key", key)
			continue
		}

		pending = append(pending, pendingEnrolment{
			key:       key,
			enrolment: enrolment,
			engine:    engine,
		})
	}

	return pending, nil
}

func hasAllFields(data map[string]any, fields []string) bool {
	for _, f := range fields {
		v, ok := data[f]
		if !ok || v == nil {
			return false
		}
		s, ok := v.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return false
		}
	}
	return true
}
