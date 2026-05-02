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

// FieldsFromSettings extracts the top-level keys of the configured JSON
// template without executing it. Top-level keys are the fields the
// engine writes to Vault, and they must be inferable from the template
// source alone — running the Go template engine would substitute
// `<no value>` for any data reference under an empty context, breaking
// any template that emits unquoted JSON values like
// `{"port": {{ .data.port }}}`. Returns nil when the template is
// missing or unparseable; the manager treats nil-fields as
// "incomplete" so the enrolment is re-run rather than silently skipped.
func (e *CopyEngine) FieldsFromSettings(settings map[string]any) []string {
	template, _ := settings["template"].(string)
	if template == "" {
		return nil
	}
	stripped := stripTemplateActions(template)
	var m map[string]any
	if err := json.Unmarshal([]byte(stripped), &m); err != nil {
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
		// Deliberately omit the rendered payload — it contains the
		// source secret's data and could leak credential material into
		// logs or the web UI. The byte offset in the json error is
		// usually enough to localise the problem in the template.
		return nil, fmt.Errorf("copy: parse rendered JSON: %w", err)
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

// stripTemplateActions replaces every `{{ ... }}` action in s with the
// JSON literal `null`. The result is suitable for json.Unmarshal when
// the surrounding text is JSON: an action inside a string ("{{x}}")
// becomes the string "null"; a bare action ({{x}}) becomes the literal
// null — both valid JSON. This is how FieldsFromSettings extracts
// top-level keys without executing the template against real data,
// where unquoted dynamic values (e.g. {"port": {{ .data.port }}})
// would otherwise produce invalid JSON when rendered against an empty
// context.
//
// Limitation: the closing `}}` is found by a simple scan, so an action
// that itself contains the literal `}}` inside a quoted string argument
// (e.g. `{{ printf "}}" }}`) terminates early and the trailing
// fragment falls through verbatim. Such templates are pathological for
// the copy engine's "JSON-with-string-substitutions" shape and would
// fail json.Unmarshal anyway; in that case FieldsFromSettings returns
// nil and the manager treats the enrolment as incomplete so the
// misconfiguration is surfaced rather than silently skipped.
func stripTemplateActions(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if i+1 < len(s) && s[i] == '{' && s[i+1] == '{' {
			end := strings.Index(s[i+2:], "}}")
			if end >= 0 {
				b.WriteString("null")
				i += 2 + end + 2
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
