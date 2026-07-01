package enrol

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"

	"github.com/goodtune/dotvault/internal/vault"
)

// Engine obtains credentials from an external service.
type Engine interface {
	// Name returns a human-readable provider name for display (e.g. "GitHub").
	Name() string

	// Run executes the credential acquisition flow.
	// settings is the engine-specific config bag from YAML.
	// Returns field→value pairs to write into Vault KVv2.
	Run(ctx context.Context, settings map[string]any, io IO) (map[string]string, error)

	// Fields returns the Vault KV field names this engine writes.
	// Used to check whether enrolment is already complete.
	Fields() []string
}

// SettingsFielder is implemented by engines whose written-field set depends
// on per-enrolment settings (e.g. the copy engine, where the JSON template
// determines which keys are written). Callers should prefer EngineFields,
// which transparently falls back to the static Fields() list for engines
// that don't implement this interface.
type SettingsFielder interface {
	Engine

	// FieldsFromSettings returns the field names this engine will write
	// for an enrolment configured with the given settings. Implementations
	// must return a stable result for stable settings; when the settings
	// are malformed, returning Fields() (or an empty slice) is acceptable.
	FieldsFromSettings(settings map[string]any) []string
}

// EngineFields returns the Vault KV field names an engine writes for a
// given settings bag. Engines that implement SettingsFielder use the
// settings-aware variant; others fall back to the static Fields() list.
func EngineFields(e Engine, settings map[string]any) []string {
	if sf, ok := e.(SettingsFielder); ok {
		return sf.FieldsFromSettings(settings)
	}
	return e.Fields()
}

// Refresher is implemented by engines whose credentials expire and can be
// rotated without user interaction. Today only JFrog implements it.
type Refresher interface {
	Engine

	// Refresh takes the current Vault secret body and returns a replacement.
	// The returned map overwrites the whole Vault secret (it must contain
	// every field the engine still cares about, including a new expires_at).
	//
	// Returns ErrRevoked to signal the upstream credential is permanently
	// gone (401/403) — caller wipes the Vault secret and flags for re-enrol.
	// Any other error is transient; caller keeps the existing secret and
	// retries with backoff.
	Refresh(ctx context.Context, settings map[string]any, existing map[string]string) (map[string]string, error)
}

// ErrRevoked indicates the upstream credential is no longer valid and
// cannot be recovered by refresh.
var ErrRevoked = errors.New("credential revoked upstream")

// WatchSource identifies a Vault KVv2 path that an enrolment derives its
// secret from. Used by Watcher engines to declare what the WatchManager
// should poll and (on Enterprise Vault) subscribe to via the Events API.
type WatchSource struct {
	Mount string
	Path  string
}

// Watcher is implemented by engines whose output is derived from one or
// more upstream Vault secrets and must be re-evaluated whenever those
// sources change. Today only the Copy engine implements it.
//
// Watcher is distinct from Refresher: Refresher is for credentials that
// expire and need rotation against the issuing service; Watcher is for
// data that is mirrored from another Vault path and needs to track
// upstream edits. The two are orthogonal — an engine could implement
// neither, either, or (in principle) both.
type Watcher interface {
	Engine

	// WatchSources returns the Vault paths this enrolment depends on,
	// resolved against the given username. Returning an empty slice
	// disables event subscription for this enrolment but does not
	// disable polling — that's controlled by whether the engine is
	// registered as a Watcher at all.
	WatchSources(settings map[string]any, username string) []WatchSource
}

// BrowserOpener opens a URL in the user's default browser.
type BrowserOpener func(url string) error

// IO provides user interaction capabilities to engines.
type IO struct {
	Out          io.Writer
	In           io.Reader // optional; defaults to os.Stdin if nil
	Browser      BrowserOpener
	Log          *slog.Logger
	Username     string                              // authenticated Vault username
	PromptSecret func(label string) (string, error) // masked user input

	// Vault is the authenticated Vault client. Most engines do not need
	// it (they acquire credentials from external services), but engines
	// that copy or derive secrets from existing Vault data (e.g. the
	// "copy" engine) read from it directly. May be nil in tests.
	Vault *vault.Client
	// KVMount is the configured KVv2 mount (e.g. "kv"). Used by engines
	// that need to read other paths under the same mount. May be empty
	// when Vault is nil.
	KVMount string
	// TargetPath is the absolute Vault path that the engine's returned
	// data will be written to (e.g. "users/jdoe/someapp"). Engines that
	// want to merge into an existing target rather than replace it can
	// read this path before returning their result.
	TargetPath string
}

var (
	enginesMu sync.RWMutex
	engines   = map[string]Engine{
		"copy":       &CopyEngine{},
		"databricks": &DatabricksEngine{},
		"ghp":        &GHPEngine{},
		"github":     &GitHubEngine{},
		"jfrog":      &JFrogEngine{},
		"ssh":        &SSHEngine{},
	}
)

// GetEngine returns the engine for the given name, or false if not found.
func GetEngine(name string) (Engine, bool) {
	enginesMu.RLock()
	defer enginesMu.RUnlock()
	e, ok := engines[name]
	return e, ok
}

// RegisterEngine adds an engine to the registry. Intended for testing.
func RegisterEngine(name string, e Engine) {
	enginesMu.Lock()
	defer enginesMu.Unlock()
	engines[name] = e
}

// UnregisterEngine removes an engine from the registry. Intended for testing.
func UnregisterEngine(name string) {
	enginesMu.Lock()
	defer enginesMu.Unlock()
	delete(engines, name)
}
