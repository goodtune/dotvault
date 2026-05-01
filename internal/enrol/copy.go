package enrol

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/goodtune/dotvault/internal/tmpl"
)

// Compile-time checks that CopyEngine implements the optional interfaces
// the manager and watch loop probe for.
var (
	_ Engine          = (*CopyEngine)(nil)
	_ SettingsFielder = (*CopyEngine)(nil)
	_ Watcher         = (*CopyEngine)(nil)
)

// CopyEngine copies (and optionally transforms) an existing Vault KVv2
// secret into the user's enrolment path. The source path supports a
// {{.user}} template substitution so admins can keep per-user source
// secrets under a shared prefix; the rendered template determines the
// keys written to the target. Existing keys at the target path that are
// not produced by the template are preserved.
type CopyEngine struct{}

func (e *CopyEngine) Name() string { return "Copy" }

// Fields returns no static fields: a copy enrolment's written keys are
// determined entirely by the user-supplied template. Use
// FieldsFromSettings to discover them when the settings are known.
func (e *CopyEngine) Fields() []string { return nil }

// FieldsFromSettings parses the configured JSON template and returns its
// top-level keys. The template is rendered against an empty context so
// the field names — which must be JSON object keys, not template
// expressions — are extracted independently of any source data. Returns
// nil when the template is missing or unparseable; the manager will
// then treat the enrolment as never-satisfied and re-run it.
func (e *CopyEngine) FieldsFromSettings(settings map[string]any) []string {
	template, _ := settings["template"].(string)
	if template == "" {
		return nil
	}
	rendered, err := tmpl.Render("copy-fields", template, map[string]any{})
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(rendered), &m); err != nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// resolveSource extracts and validates the from-mount/from-path settings
// and substitutes {{.user}} into the path. Shared by Run (which needs to
// fetch the source) and WatchSources (which needs to know which paths to
// subscribe to / poll).
func (e *CopyEngine) resolveSource(settings map[string]any, username string) (mount, path string, err error) {
	from, ok := settings["from"].(map[string]any)
	if !ok {
		return "", "", fmt.Errorf("copy: settings.from must be a map with mount and path")
	}
	srcMount, _ := from["mount"].(string)
	if srcMount == "" {
		return "", "", fmt.Errorf("copy: settings.from.mount is required")
	}
	srcPathTmpl, _ := from["path"].(string)
	if srcPathTmpl == "" {
		return "", "", fmt.Errorf("copy: settings.from.path is required")
	}
	srcPath, err := tmpl.Render("copy-source-path", srcPathTmpl, map[string]any{
		"user": username,
	})
	if err != nil {
		return "", "", fmt.Errorf("copy: render source path: %w", err)
	}
	return srcMount, srcPath, nil
}

// WatchSources returns the source path the engine depends on, resolved
// against the given username. Returning an empty slice when settings are
// invalid is intentional: it disables event subscription rather than
// failing daemon startup; Run will still surface the error during the
// next poll tick.
func (e *CopyEngine) WatchSources(settings map[string]any, username string) []WatchSource {
	mount, path, err := e.resolveSource(settings, username)
	if err != nil {
		return nil
	}
	return []WatchSource{{Mount: mount, Path: path}}
}

func (e *CopyEngine) Run(ctx context.Context, settings map[string]any, io IO) (map[string]string, error) {
	if io.Vault == nil {
		return nil, fmt.Errorf("copy engine requires a Vault client")
	}

	format, _ := settings["format"].(string)
	if format == "" {
		format = "json"
	}
	if format != "json" {
		return nil, fmt.Errorf("copy: only json format is supported (got %q)", format)
	}

	template, _ := settings["template"].(string)
	if strings.TrimSpace(template) == "" {
		return nil, fmt.Errorf("copy: settings.template is required")
	}

	srcMount, srcPath, err := e.resolveSource(settings, io.Username)
	if err != nil {
		return nil, err
	}

	srcSecret, err := io.Vault.ReadKVv2(ctx, srcMount, srcPath)
	if err != nil {
		return nil, fmt.Errorf("copy: read source %s/%s: %w", srcMount, srcPath, err)
	}
	if srcSecret == nil {
		return nil, fmt.Errorf("copy: source secret %s/%s not found", srcMount, srcPath)
	}

	// Render the template with the source data exposed under .data so
	// users write {{ .data.key }} — keeping the contract obvious and
	// preventing accidental name collisions with future top-level keys.
	rendered, err := tmpl.Render("copy-template", template, map[string]any{
		"data": srcSecret.Data,
		"user": io.Username,
	})
	if err != nil {
		return nil, fmt.Errorf("copy: render template: %w", err)
	}

	var incoming map[string]any
	if err := json.Unmarshal([]byte(rendered), &incoming); err != nil {
		return nil, fmt.Errorf("copy: parse rendered JSON: %w\nrendered: %s", err, rendered)
	}

	// Merge into existing target so unrelated keys at the path are
	// preserved (e.g. another field written by a separate process).
	merged := make(map[string]string)
	if io.TargetPath != "" {
		existing, err := io.Vault.ReadKVv2(ctx, io.KVMount, io.TargetPath)
		if err != nil {
			return nil, fmt.Errorf("copy: read target %s/%s: %w", io.KVMount, io.TargetPath, err)
		}
		if existing != nil {
			for k, v := range existing.Data {
				s, ok := v.(string)
				if !ok {
					// KVv2 stores arbitrary JSON; coerce non-strings
					// rather than dropping them so we don't accidentally
					// strip data the user wrote with another tool.
					b, mErr := json.Marshal(v)
					if mErr != nil {
						return nil, fmt.Errorf("copy: encode existing key %q: %w", k, mErr)
					}
					s = string(b)
				}
				merged[k] = s
			}
		}
	}

	for k, v := range incoming {
		s, ok := v.(string)
		if !ok {
			b, mErr := json.Marshal(v)
			if mErr != nil {
				return nil, fmt.Errorf("copy: encode template key %q: %w", k, mErr)
			}
			s = string(b)
		}
		merged[k] = s
	}

	return merged, nil
}
