package sync

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RuleState tracks the sync state for a single rule.
type RuleState struct {
	VaultVersion int       `json:"vault_version"`
	LastSynced   time.Time `json:"last_synced"`
	FileChecksum string    `json:"file_checksum"`
}

type stateFile struct {
	Rules map[string]RuleState `json:"rules"`
}

// StateStore manages sync state persistence.
type StateStore struct {
	path  string
	mu    sync.Mutex
	state stateFile
}

// NewStateStore creates a new state store at the given path.
func NewStateStore(path string) *StateStore {
	return &StateStore{
		path: path,
		state: stateFile{
			Rules: make(map[string]RuleState),
		},
	}
}

// Load reads the state file from disk. If the file doesn't exist, starts empty.
func (s *StateStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.state.Rules = make(map[string]RuleState)
			return nil
		}
		return fmt.Errorf("read state file: %w", err)
	}

	if err := json.Unmarshal(data, &s.state); err != nil {
		return fmt.Errorf("parse state file: %w", err)
	}
	if s.state.Rules == nil {
		s.state.Rules = make(map[string]RuleState)
	}
	return nil
}

// Save writes the state file to disk atomically.
func (s *StateStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename state file: %w", err)
	}
	return nil
}

// Get returns the state for a rule. Returns zero-value RuleState if not found.
func (s *StateStore) Get(name string) RuleState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Rules[name]
}

// Set updates the state for a rule.
func (s *StateStore) Set(name string, rs RuleState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Rules[name] = rs
}

// Rules returns a copy of all rule states.
func (s *StateStore) Rules() map[string]RuleState {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make(map[string]RuleState, len(s.state.Rules))
	for k, v := range s.state.Rules {
		cp[k] = v
	}
	return cp
}

// FileChecksum computes sha256 of a file's contents.
// Returns empty string (not error) for missing files.
func FileChecksum(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read file for checksum: %w", err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum), nil
}
