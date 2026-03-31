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

// HandlerFor returns the appropriate FileHandler for the given format.
func HandlerFor(format string) (FileHandler, error) {
	switch format {
	case "yaml":
		return &YAMLHandler{}, nil
	case "json":
		return &JSONHandler{}, nil
	case "ini":
		return &INIHandler{}, nil
	case "toml":
		return &TOMLHandler{}, nil
	case "text":
		return &TextHandler{}, nil
	case "netrc":
		return &NetrcHandler{}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %q", format)
	}
}
