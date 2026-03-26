package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/handlers"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/tmpl"
	"github.com/goodtune/dotvault/internal/vault"
)

// Engine manages the sync loop.
type Engine struct {
	cfg       *config.Config
	vault     *vault.Client
	username  string
	state     *StateStore
	triggerCh chan struct{}
	mu        sync.Mutex
	DryRun    bool
}

// NewEngine creates a new sync engine.
func NewEngine(cfg *config.Config, vc *vault.Client, username, statePath string) *Engine {
	store := NewStateStore(statePath)
	store.Load()

	return &Engine{
		cfg:       cfg,
		vault:     vc,
		username:  username,
		state:     store,
		triggerCh: make(chan struct{}, 1),
	}
}

// TriggerSync requests an immediate sync cycle.
func (e *Engine) TriggerSync() {
	select {
	case e.triggerCh <- struct{}{}:
	default:
	}
}

// RunOnce executes a single sync cycle across all rules.
func (e *Engine) RunOnce(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	var lastErr error
	for _, rule := range e.cfg.Rules {
		if err := e.syncRule(ctx, rule); err != nil {
			slog.Error("sync rule failed", "rule", rule.Name, "error", err)
			lastErr = err
		}
	}
	return lastErr
}

// RunLoop runs the hybrid event/poll sync loop until ctx is cancelled.
func (e *Engine) RunLoop(ctx context.Context) error {
	// Initial sync
	e.RunOnce(ctx)

	// Try to subscribe to events
	eventCh, errCh := e.trySubscribeEvents(ctx)

	// reconnectCh signals the main loop to attempt reconnection.
	// This avoids a data race where a goroutine would write to
	// eventCh/errCh while the select loop reads them concurrently.
	reconnectCh := make(chan struct{}, 1)

	// Exponential backoff for reconnection attempts (1s base, 5m cap).
	reconnectDelay := 1 * time.Second
	const maxReconnectDelay = 5 * time.Minute

	ticker := time.NewTicker(e.cfg.Sync.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-ticker.C:
			slog.Debug("poll sync cycle")
			e.RunOnce(ctx)

		case <-e.triggerCh:
			slog.Info("manual sync triggered")
			e.RunOnce(ctx)

		case evt, ok := <-eventCh:
			if !ok {
				// Channel closed — switch to poll-only
				slog.Warn("event subscription closed, falling back to poll-only")
				eventCh = nil
				continue
			}
			slog.Info("vault event received", "path", evt.Path, "type", evt.EventType)
			e.syncRuleByPath(ctx, evt.Path)

		case err, ok := <-errCh:
			if ok && err != nil {
				slog.Warn("event subscription error, falling back to poll-only", "error", err)
				eventCh = nil
				errCh = nil
				// Schedule reconnection with backoff on a goroutine,
				// but signal back to the main loop via reconnectCh.
				go func(delay time.Duration) {
					slog.Info("scheduling event reconnection", "delay", delay)
					select {
					case <-time.After(delay):
						select {
						case reconnectCh <- struct{}{}:
						default:
						}
					case <-ctx.Done():
					}
				}(reconnectDelay)
				// Increase backoff for next failure
				reconnectDelay *= 2
				if reconnectDelay > maxReconnectDelay {
					reconnectDelay = maxReconnectDelay
				}
			}

		case <-reconnectCh:
			// Reconnection attempt runs on the main goroutine, avoiding
			// any data race on eventCh/errCh.
			newEvents, newErrCh := e.trySubscribeEvents(ctx)
			if newEvents != nil {
				eventCh = newEvents
				errCh = newErrCh
				reconnectDelay = 1 * time.Second // reset backoff on success
				slog.Info("event subscription reconnected")
			} else {
				// Subscription failed again; schedule another attempt.
				go func(delay time.Duration) {
					slog.Info("reconnection failed, retrying", "delay", delay)
					select {
					case <-time.After(delay):
						select {
						case reconnectCh <- struct{}{}:
						default:
						}
					case <-ctx.Done():
					}
				}(reconnectDelay)
				reconnectDelay *= 2
				if reconnectDelay > maxReconnectDelay {
					reconnectDelay = maxReconnectDelay
				}
			}
		}
	}
}

// State returns the underlying state store for external access.
func (e *Engine) State() *StateStore {
	return e.state
}

func (e *Engine) trySubscribeEvents(ctx context.Context) (<-chan vault.Event, <-chan error) {
	prefix := e.cfg.Vault.UserPrefix + e.username + "/"
	eventCh, errCh, err := e.vault.SubscribeEvents(ctx, "kv-v2/data-write")
	if err != nil {
		slog.Info("event subscription not available, using poll-only mode", "error", err)
		return nil, nil
	}

	// Filter events by user prefix
	filtered := make(chan vault.Event, 16)
	go func() {
		defer close(filtered)
		for evt := range eventCh {
			if hasPrefix(evt.Path, prefix) {
				filtered <- evt
			}
		}
	}()

	slog.Info("subscribed to vault events", "prefix", prefix)
	return filtered, errCh
}

func (e *Engine) syncRuleByPath(ctx context.Context, path string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	prefix := e.cfg.Vault.UserPrefix + e.username + "/"
	vaultKey := trimPrefix(path, prefix)

	for _, rule := range e.cfg.Rules {
		if rule.VaultKey == vaultKey {
			if err := e.syncRule(ctx, rule); err != nil {
				slog.Error("sync rule failed", "rule", rule.Name, "error", err)
			}
			return
		}
	}
}

func (e *Engine) syncRule(ctx context.Context, rule config.Rule) error {
	log := slog.With("rule", rule.Name)

	// Read secret from Vault
	secretPath := e.cfg.Vault.UserPrefix + e.username + "/" + rule.VaultKey
	secret, err := e.vault.ReadKVv2(ctx, e.cfg.Vault.KVMount, secretPath)
	if err != nil {
		return fmt.Errorf("read vault secret: %w", err)
	}
	if secret == nil {
		log.Warn("secret not found in vault", "path", secretPath)
		return nil
	}

	// Resolve target path
	targetPath, err := paths.ExpandHome(rule.Target.Path)
	if err != nil {
		return fmt.Errorf("expand target path: %w", err)
	}

	// Check version and target file — skip only if vault secret is unchanged
	// AND the target file still matches what we last wrote.
	currentState := e.state.Get(rule.Name)
	if secret.Version == currentState.VaultVersion && currentState.VaultVersion > 0 {
		currentChecksum, _ := FileChecksum(targetPath)
		if currentChecksum == currentState.FileChecksum {
			log.Debug("secret unchanged, skipping")
			return nil
		}
		log.Info("target file changed or missing, re-syncing", "path", targetPath)
	}

	// Get handler
	handler, err := handlers.HandlerFor(rule.Target.Format)
	if err != nil {
		return fmt.Errorf("get handler: %w", err)
	}

	// Render template if present
	var incomingData any
	if rule.Target.Template != "" {
		rendered, err := tmpl.Render(rule.Name, rule.Target.Template, secret.Data)
		if err != nil {
			return fmt.Errorf("render template: %w", err)
		}

		// Parse rendered output through handler
		parser, ok := handler.(handlers.Parser)
		if !ok {
			return fmt.Errorf("handler for format %q does not support templates (remove the template field from rule %q)", rule.Target.Format, rule.Name)
		}
		incomingData, err = parser.Parse(rendered)
		if err != nil {
			return fmt.Errorf("parse rendered template: %w", err)
		}
	} else {
		// No template — use vault data directly
		// For netrc format, convert raw vault data to NetrcVaultData
		if rule.Target.Format == "netrc" {
			incomingData = convertToNetrcVaultData(secret.Data)
		} else {
			incomingData = secret.Data
		}
	}

	// Read existing file
	existingData, err := handler.Read(targetPath)
	if err != nil {
		return fmt.Errorf("read existing file: %w", err)
	}

	// Check for external modification
	currentChecksum, _ := FileChecksum(targetPath)
	if currentChecksum != "" && currentState.FileChecksum != "" && currentChecksum != currentState.FileChecksum {
		log.Warn("file modified externally since last sync", "path", targetPath)
	}

	// Merge
	merged, err := handler.Merge(existingData, incomingData)
	if err != nil {
		return fmt.Errorf("merge data: %w", err)
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}

	// Determine file permissions
	perm := os.FileMode(0644)
	if rule.Target.Format == "netrc" {
		perm = 0600
	}

	// Write (or log what would be written in dry-run mode)
	if e.DryRun {
		log.Info("dry-run: would write file", "path", targetPath, "version", secret.Version, "permissions", fmt.Sprintf("%04o", perm))
		return nil
	}

	if err := handler.Write(targetPath, merged, perm); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	// Update state
	newChecksum, _ := FileChecksum(targetPath)
	e.state.Set(rule.Name, RuleState{
		VaultVersion: secret.Version,
		LastSynced:   time.Now(),
		FileChecksum: newChecksum,
	})
	if err := e.state.Save(); err != nil {
		log.Warn("failed to save state", "error", err)
	}

	log.Info("synced secret to file", "path", targetPath, "version", secret.Version)
	return nil
}

// convertToNetrcVaultData converts raw Vault JSON data to NetrcVaultData.
// It expects the vault data to have machine names as keys with login/password
// as nested values (either as a JSON string or as a map).
func convertToNetrcVaultData(data map[string]any) handlers.NetrcVaultData {
	result := make(handlers.NetrcVaultData)
	for machine, val := range data {
		switch v := val.(type) {
		case map[string]any:
			login, _ := v["login"].(string)
			password, _ := v["password"].(string)
			result[machine] = handlers.NetrcCredential{
				Login:    login,
				Password: password,
			}
		case string:
			// Try to parse as JSON
			var cred handlers.NetrcCredential
			if err := parseNetrcJSON(v, &cred); err == nil {
				result[machine] = cred
			}
		case json.Number:
			// json.Number values are not valid netrc credential structures;
			// convert to string and attempt JSON parse for consistency.
			var cred handlers.NetrcCredential
			if err := parseNetrcJSON(v.String(), &cred); err == nil {
				result[machine] = cred
			}
		}
	}
	return result
}

func parseNetrcJSON(s string, cred *handlers.NetrcCredential) error {
	type jsonCred struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	var jc jsonCred
	if err := json.Unmarshal([]byte(s), &jc); err != nil {
		return err
	}
	cred.Login = jc.Login
	cred.Password = jc.Password
	return nil
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func trimPrefix(s, prefix string) string {
	if hasPrefix(s, prefix) {
		return s[len(prefix):]
	}
	return s
}
