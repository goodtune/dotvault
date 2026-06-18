package sync

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/handlers"
	"github.com/goodtune/dotvault/internal/observability"
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
	// cfgCh nudges the run loop after UpdateConfig changes the sync
	// interval, so the ticker is reset without waiting out the old period.
	cfgCh  chan struct{}
	mu     sync.Mutex
	DryRun bool
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
		cfgCh:     make(chan struct{}, 1),
	}
}

// TriggerSync requests an immediate sync cycle.
func (e *Engine) TriggerSync() {
	select {
	case e.triggerCh <- struct{}{}:
	default:
	}
}

// UpdateConfig swaps the engine's dynamic configuration at runtime: the rule
// set and the poll interval. Called by the daemon's config-refresh loop when
// the remote overlay (or an edited local config) changes them. No-op when
// nothing changed. On a rule change, state entries for removed rules are
// pruned (so state.json converges with the rule set) and an immediate sync is
// triggered; on an interval change the run loop's ticker is reset.
func (e *Engine) UpdateConfig(rules []config.Rule, interval time.Duration) {
	e.mu.Lock()
	rulesChanged := !reflect.DeepEqual(e.cfg.Rules, rules)
	intervalChanged := interval > 0 && interval != e.cfg.Sync.Interval
	if rulesChanged {
		e.cfg.Rules = append([]config.Rule(nil), rules...)
	}
	if intervalChanged {
		e.cfg.Sync.Interval = interval
	}
	e.mu.Unlock()

	if !rulesChanged && !intervalChanged {
		return
	}
	slog.Info("sync engine configuration updated",
		"rules", len(rules), "interval", interval,
		"rules_changed", rulesChanged, "interval_changed", intervalChanged)

	if rulesChanged {
		keep := make(map[string]bool, len(rules))
		for _, r := range rules {
			keep[r.Name] = true
		}
		if removed := e.state.Prune(keep); removed > 0 {
			if err := e.state.Save(); err != nil {
				slog.Warn("failed to save state after pruning removed rules", "error", err)
			}
		}
		e.TriggerSync()
	}
	if intervalChanged {
		select {
		case e.cfgCh <- struct{}{}:
		default:
		}
	}
}

// currentInterval reads the poll interval under the engine mutex.
func (e *Engine) currentInterval() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg.Sync.Interval
}

// RunOnce executes a single sync cycle across all rules.
func (e *Engine) RunOnce(ctx context.Context) error {
	start := time.Now()
	lastErr := e.runOnceLocked(ctx)
	outcome := "ok"
	if lastErr != nil {
		outcome = "error"
	}
	// Record outside the mutex: metric ops are independent of the
	// engine's critical section, and dragging them inside would
	// inflate the lock-hold window if the OTel exporter (or a
	// future instrument) ever blocks.
	observability.RecordSyncTick(ctx, outcome)
	observability.RecordSyncDuration(ctx, time.Since(start), outcome)
	return lastErr
}

func (e *Engine) runOnceLocked(ctx context.Context) error {
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

// RunLoopOption tunes RunLoop's behaviour without exposing the
// engine's internal sequencing to callers.
type RunLoopOption func(*runLoopConfig)

type runLoopConfig struct {
	afterInitialSync func()
}

// AfterInitialSync registers a callback invoked exactly once,
// synchronously, after RunLoop's initial RunOnce returns and before
// the ticker / event loop starts. The daemon uses this to gate
// sd_notify(READY=1) and the web server's readiness flag on the
// initial sync completing — without leaking the initial-sync-then-
// loop sequencing to every caller via a separately-exported
// RunLoopAfterInitial entry point.
func AfterInitialSync(fn func()) RunLoopOption {
	return func(c *runLoopConfig) { c.afterInitialSync = fn }
}

// RunLoop runs the hybrid event/poll sync loop until ctx is cancelled.
// It performs an initial RunOnce up front, fires any
// AfterInitialSync hook, then enters the ticker / event loop. The
// initial RunOnce error is logged but does not abort the loop —
// per-rule isolation is the engine's invariant.
func (e *Engine) RunLoop(ctx context.Context, opts ...RunLoopOption) error {
	cfg := &runLoopConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	if err := e.RunOnce(ctx); err != nil {
		slog.Warn("initial sync had errors (continuing into the loop)", "error", err)
	}
	// Don't fire the readiness hook if ctx has been cancelled
	// during the initial RunOnce. Signalling sd_notify(READY=1) /
	// flipping the web /readyz flag mid-shutdown would
	// incorrectly unblock systemd dependencies or k8s
	// readinessProbe consumers right before the daemon exits.
	if cfg.afterInitialSync != nil && ctx.Err() == nil {
		cfg.afterInitialSync()
	}
	return e.runLoopAfterInitial(ctx)
}

// runLoopAfterInitial runs the hybrid event/poll sync loop without
// an implicit initial sync. Unexported because the initial-sync
// sequencing is an engine invariant — callers compose via
// RunLoopOption hooks instead.
func (e *Engine) runLoopAfterInitial(ctx context.Context) error {
	// Check Vault edition — events API requires Enterprise.
	var eventsAvailable bool
	if health, err := e.vault.ServerHealth(ctx); err != nil {
		slog.Warn("unable to check vault edition, assuming community", "error", err)
	} else {
		edition := "Community"
		if health.Enterprise {
			edition = "Enterprise"
			eventsAvailable = true
		}
		slog.Info("connected to vault", "version", health.Version, "edition", edition, "cluster", health.ClusterName)
	}

	// Try to subscribe to events (Enterprise only)
	var eventCh <-chan vault.Event
	var errCh <-chan error
	if eventsAvailable {
		eventCh, errCh = e.trySubscribeEvents(ctx)
	} else {
		slog.Info("event subscription requires Vault Enterprise, using poll-only mode")
	}

	// reconnectCh signals the main loop to attempt reconnection.
	// This avoids a data race where a goroutine would write to
	// eventCh/errCh while the select loop reads them concurrently.
	reconnectCh := make(chan struct{}, 1)

	// Exponential backoff for reconnection attempts (1s base, 5m cap).
	reconnectDelay := 1 * time.Second
	const maxReconnectDelay = 5 * time.Minute

	ticker := time.NewTicker(e.currentInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-ticker.C:
			slog.Debug("poll sync cycle")
			e.RunOnce(ctx)

		case <-e.cfgCh:
			// UpdateConfig changed the poll interval — restart the ticker
			// so the new cadence applies now, not after the old period.
			ticker.Reset(e.currentInterval())
			slog.Debug("sync poll interval updated", "interval", e.currentInterval())

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

	// Read the secret only when the rule names a vault key. A keyless rule
	// (e.g. an ssh_config file built purely from {{ username }} and literals)
	// manages a file with no Vault-backed content: it renders with an empty
	// data context and never contacts Vault. The username function still works
	// in either case, because it is a template function, not a context field.
	secretData := map[string]any{}
	secretVersion := 0
	if rule.VaultKey != "" {
		secretPath := e.cfg.Vault.UserPrefix + e.username + "/" + rule.VaultKey
		secret, err := e.vault.ReadKVv2(ctx, e.cfg.Vault.KVMount, secretPath)
		if err != nil {
			return fmt.Errorf("read vault secret: %w", err)
		}
		if secret == nil {
			log.Warn("secret not found in vault", "path", secretPath)
			return nil
		}
		secretData = secret.Data
		secretVersion = secret.Version
	}

	// Resolve target path
	targetPath, err := paths.ExpandHome(rule.Target.Path)
	if err != nil {
		return fmt.Errorf("expand target path: %w", err)
	}

	// Check version, rule definition, and target file — skip only if the vault
	// secret is unchanged, the rule's render-affecting definition is unchanged
	// (so an edited template re-applies even on an untouched secret), AND the
	// target file still matches what we last wrote. A keyless rule has no secret
	// version, so the rule fingerprint plus the file checksum carry the whole
	// skip decision for it (a never-synced rule has an empty stored RuleHash,
	// which cannot match the non-empty computed hash, forcing the first sync).
	currentState := e.state.Get(rule.Name)
	ruleHash := ruleRenderHash(rule)
	versionUnchanged := rule.VaultKey == "" || (secretVersion == currentState.VaultVersion && currentState.VaultVersion > 0)
	if versionUnchanged && currentState.RuleHash == ruleHash {
		currentChecksum, _ := FileChecksum(targetPath)
		if currentChecksum == currentState.FileChecksum {
			// Even when content is unchanged, enforce 0600 permissions.
			if !e.DryRun {
				if info, err := os.Stat(targetPath); err == nil {
					expectedPerm := os.FileMode(0600)
					if info.Mode().Perm() != expectedPerm {
						if err := os.Chmod(targetPath, expectedPerm); err != nil {
							log.Warn("failed to enforce file permissions", "path", targetPath, "expected", fmt.Sprintf("%04o", expectedPerm), "error", err)
						}
					}
				}
			}
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
		rendered, err := tmpl.RenderWithUsername(rule.Name, rule.Target.Template, secretData, e.username)
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
		// No template — use vault data directly. (A keyless rule is required to
		// have a template, so secretData here is always a real secret's data.)
		// For netrc format, convert raw vault data to NetrcVaultData
		if rule.Target.Format == "netrc" {
			incomingData = convertToNetrcVaultData(secretData)
		} else if rule.Target.Format == "text" {
			textData, err := convertToTextData(secretData)
			if err != nil {
				return fmt.Errorf("convert vault data to text: %w", err)
			}
			incomingData = textData
		} else {
			incomingData = secretData
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

	// Determine file permissions — all managed files use 0600
	perm := os.FileMode(0600)

	// Write (or log what would be written in dry-run mode)
	if e.DryRun {
		log.Info("dry-run: would write file", "path", targetPath, "version", secretVersion, "permissions", fmt.Sprintf("%04o", perm))
		return nil
	}

	if err := handler.Write(targetPath, merged, perm); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	// Ensure the written file has 0600 permissions (it may have pre-existed with looser perms).
	if info, err := os.Stat(targetPath); err == nil {
		if info.Mode().Perm() != perm {
			if err := os.Chmod(targetPath, perm); err != nil {
				log.Warn("failed to enforce file permissions", "path", targetPath, "expected", fmt.Sprintf("%04o", perm), "error", err)
			}
		}
	}

	// Update state
	newChecksum, _ := FileChecksum(targetPath)
	e.state.Set(rule.Name, RuleState{
		VaultVersion: secretVersion,
		LastSynced:   time.Now(),
		FileChecksum: newChecksum,
		RuleHash:     ruleHash,
	})
	if err := e.state.Save(); err != nil {
		log.Warn("failed to save state", "error", err)
	}

	log.Info("synced file", "path", targetPath, "version", secretVersion)
	return nil
}

// ruleRenderHash fingerprints the fields of a rule that determine its rendered,
// merged output: the vault key it reads and the target's path, format,
// template, and merge strategy. It is stored in RuleState so the skip gate can
// tell a render-affecting edit (most commonly a changed template) apart from an
// untouched rule even when the secret version and on-disk file are unchanged —
// the scenario where a template change would otherwise never re-apply. Each
// field is length-prefixed so distinct field boundaries cannot alias (e.g. a
// path ending where the next field begins).
func ruleRenderHash(rule config.Rule) string {
	h := sha256.New()
	for _, s := range []string{
		rule.VaultKey,
		rule.Target.Path,
		rule.Target.Format,
		rule.Target.Template,
		rule.Target.Merge,
	} {
		fmt.Fprintf(h, "%d:%s", len(s), s)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
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

// convertToTextData extracts the text content from Vault data.
// It looks for a "data" key first, then "value", then "content".
// If one of these keys is present it must be a string, otherwise an error is returned.
// If none of these keys are present (or none hold a string), the function falls back to:
//   - returning the value when there is exactly one string field in the secret, or
//   - returning an error if there are zero or multiple string fields (to avoid ambiguity).
func convertToTextData(data map[string]any) (string, error) {
	for _, key := range []string{"data", "value", "content"} {
		v, ok := data[key]
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("text format: vault key %q is %T, expected string", key, v)
		}
		return s, nil
	}

	// No well-known key found — check if there is exactly one string field.
	var found string
	var count int
	for _, v := range data {
		if s, ok := v.(string); ok {
			found = s
			count++
		}
	}
	if count == 1 {
		return found, nil
	}
	if count == 0 {
		return "", fmt.Errorf("text format: vault secret contains no string fields; use a \"data\", \"value\", or \"content\" key")
	}
	return "", fmt.Errorf("text format: vault secret contains %d string fields; use a \"data\", \"value\", or \"content\" key to disambiguate", count)
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
