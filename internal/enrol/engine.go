package enrol

import (
	"context"
	"io"
	"log/slog"
	"sync"
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
}

var (
	enginesMu sync.RWMutex
	engines   = map[string]Engine{
		"github": &GitHubEngine{},
		"ssh":    &SSHEngine{},
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
