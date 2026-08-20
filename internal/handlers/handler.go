package handlers

import (
	"fmt"
	"os"
)

// FileHandler defines the interface for reading, merging, and writing config files.
type FileHandler interface {
	// Read parses the target file and returns structured data.
	// If the file doesn't exist, returns empty/zero state (not an error).
	Read(path string) (any, error)

	// Merge takes existing data and incoming data and returns the merged result.
	// Existing keys not present in incoming are preserved.
	Merge(existing any, incoming any) (any, error)

	// Write serialises the merged data back to the file atomically.
	Write(path string, data any, perm os.FileMode) error
}

// Parser parses raw content (e.g., from a rendered template) into the handler's
// native data structure, suitable for passing as the "incoming" argument to Merge.
type Parser interface {
	Parse(content string) (any, error)
}

// Options carries per-rule merge behaviour into the handler that implements it.
// The zero value is the historical default, so HandlerFor stays equivalent to
// HandlerWithOptions(format, Options{}).
type Options struct {
	// DeleteNulls makes a null in the incoming (template-rendered) document a
	// tombstone: the matching key is deleted from the target file rather than
	// written as a null. Only json and yaml support it — see HandlerWithOptions.
	DeleteNulls bool
}

// HandlerFor returns the appropriate FileHandler for the given format, with
// default merge behaviour.
func HandlerFor(format string) (FileHandler, error) {
	return HandlerWithOptions(format, Options{})
}

// HandlerWithOptions returns the appropriate FileHandler for the given format,
// configured with per-rule merge behaviour.
//
// Asking for DeleteNulls on a format with no null literal is an error rather
// than a silent no-op. config.validateRule rejects that combination at load
// time, so this is the second of two gates: it keeps a caller that builds a
// handler by some other route from quietly getting additive-only merges when
// it asked for deletions.
func HandlerWithOptions(format string, opts Options) (FileHandler, error) {
	if opts.DeleteNulls && format != "json" && format != "yaml" {
		return nil, fmt.Errorf("format %q does not support delete_nulls (only json and yaml have a null literal a template can render)", format)
	}
	switch format {
	case "yaml":
		return &YAMLHandler{DeleteNulls: opts.DeleteNulls}, nil
	case "json":
		return &JSONHandler{DeleteNulls: opts.DeleteNulls}, nil
	case "ini":
		return &INIHandler{}, nil
	case "toml":
		return &TOMLHandler{}, nil
	case "text":
		return &TextHandler{}, nil
	case "netrc":
		return &NetrcHandler{}, nil
	case "ssh_config":
		return &SSHConfigHandler{}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %q", format)
	}
}
