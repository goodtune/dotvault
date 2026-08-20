package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/goodtune/dotvault/internal/perms"
	"gopkg.in/yaml.v3"
)

// UserConfig is the per-user preference overlay, read from the user's own
// configuration directory (see paths.UserConfigPath) and merged over the
// system configuration.
//
// It is deliberately not a second Config. The system configuration is policy —
// admin-owned on a managed machine, and superseded entirely by Group Policy on
// Windows — and a file the user can write must never be able to redirect the
// Vault, open a listener, or alter telemetry. Only sections listed in
// userOverridableSections may appear here, and each one defines its own merge
// rule rather than simply overwriting the policy value.
//
// Today that is the filesystem section alone. The type exists in this shape
// (a document with named sections, not a bare FUSE block) so a second
// user-overridable section can be added later without users learning a new
// file.
type UserConfig struct {
	FUSE *UserFUSEConfig `yaml:"fuse,omitempty"`
}

// UserFUSEConfig is the user's preference for the filesystem section.
//
// The booleans are pointers, unlike the FUSEConfig they merge into, because
// the merge has to distinguish "the user did not express a preference" from
// "the user asked for false". A plain bool cannot: an absent key and an
// explicit `enabled: false` both decode to false, so a user who never
// mentioned the section would silently be asking to turn it off.
type UserFUSEConfig struct {
	// Enabled may turn the filesystem ON when the system configuration
	// leaves it off. It cannot turn it off when the system enables it — an
	// administrator who mounts the filesystem for a fleet has decided it is
	// part of the machine's setup, and a user-writable file is not the place
	// to opt out of that.
	Enabled *bool `yaml:"enabled,omitempty"`

	// Mountpoint relocates the mount. It is a pure preference — the
	// directory is in the user's own home, and where their secrets appear is
	// their business — so the user's value simply wins when set.
	Mountpoint string `yaml:"mountpoint,omitempty"`

	// ReadWrite may turn writes OFF when the system configuration enables
	// them. It cannot turn them on.
	//
	// This is the opposite direction to Enabled, and deliberately so. The two
	// settings are not the same kind of thing: enabling a read-only mount
	// grants nothing the user's Vault token could not already do, while
	// read-write puts every process running as that user — and every mistyped
	// shell redirect — one `>` away from replacing a credential. So the
	// administrator's "no" stays binding, and the user stays free to be more
	// careful than policy requires.
	ReadWrite *bool `yaml:"read_write,omitempty"`

	// CacheTTL adjusts the cache window. A preference like Mountpoint: it
	// trades staleness against Vault round trips and carries no policy
	// weight, so the user's value wins when set.
	CacheTTL string `yaml:"cache_ttl,omitempty"`
}

// userOverridableSections are the top-level keys a user config may carry.
var userOverridableSections = map[string]bool{
	"fuse": true,
}

// ParseUserConfig parses a user configuration document, enforcing that it
// carries only user-overridable sections.
//
// A section the user may not set is a hard error naming it, not a silent
// drop. Silently ignoring a `vault:` block would let someone believe they had
// re-pointed their daemon at a different Vault — the failure mode is a user
// who thinks a setting took effect when policy overrode it, which is exactly
// what an explicit error prevents. Unknown sections are ignored with a
// warning, matching ParsePartial: a newer dotvault may understand keys this
// build does not, and a stale binary should not refuse to start over one.
//
// Section matching is case-insensitive for the rejection check so `Vault:`
// cannot slip past as merely unknown, mirroring ParsePartial's reasoning.
func ParseUserConfig(data []byte) (*UserConfig, error) {
	// yaml.Unmarshal reads the first document and silently discards the rest,
	// so `fuse: …` followed by `---` and a `vault:` block would sail past the
	// section check below having never been looked at. That is exactly the
	// "the user believes it took effect" failure the check exists to prevent,
	// so a multi-document stream is refused outright rather than truncated.
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var probe map[string]any
	if err := dec.Decode(&probe); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse user config: %w", err)
	}
	var extra map[string]any
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("user config: contains more than one YAML document; put every setting in a single document")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse user config: %w", err)
	}

	var unknown []string
	for key := range probe {
		lower := strings.ToLower(key)
		if userOverridableSections[lower] {
			if key != lower {
				// A mis-cased known section would be dropped by the typed
				// decode below and take effect as nothing at all.
				return nil, fmt.Errorf("user config: section %q must be spelled %q", key, lower)
			}
			continue
		}
		if isConfigSection(lower) {
			return nil, fmt.Errorf("user config: section %q is set by the system configuration and cannot be overridden here (this file may set: %s)",
				key, strings.Join(sortedUserSections(), ", "))
		}
		unknown = append(unknown, key)
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		slog.Warn("user config: ignoring unrecognised sections", "sections", unknown)
	}

	var uc UserConfig
	if err := yaml.Unmarshal(data, &uc); err != nil {
		return nil, fmt.Errorf("parse user config: %w", err)
	}
	return &uc, nil
}

// configSectionNames is the set of top-level keys Config actually declares,
// derived from its yaml tags.
//
// Reflected rather than listed by hand on purpose. A hand-written list drifts
// the moment someone adds a section and forgets this file, and it drifts
// *toward permissive*: the new section stops being refused and becomes merely
// "unknown", so a user setting it gets a warning they will not read and a
// belief that it took effect. Deriving it means the question can only be
// answered correctly.
var configSectionNames = sync.OnceValue(func() map[string]bool {
	out := make(map[string]bool)
	t := reflect.TypeOf(Config{})
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("yaml")
		name, _, _ := strings.Cut(tag, ",")
		// `yaml:"-"` marks a field that is never serialised (Managed), so it
		// is not a section a user could name.
		if name == "" || name == "-" {
			continue
		}
		out[name] = true
	}
	return out
})

// isConfigSection reports whether key names a real top-level Config section.
// A key that is neither user-overridable nor a known section is a typo or a
// section from a future release, and warns rather than failing.
func isConfigSection(key string) bool {
	return configSectionNames()[key]
}

func sortedUserSections() []string {
	out := make([]string, 0, len(userOverridableSections))
	for k := range userOverridableSections {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// LoadUserConfig reads the user configuration at path. A missing file is
// (nil, nil): the overlay is entirely optional, and the overwhelmingly common
// case is that it does not exist.
func LoadUserConfig(path string) (*UserConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read user config: %w", err)
	}

	// Refused, not warned. This file turns a secrets mount on and chooses
	// where the secrets appear, and dotvault already *refuses* a --config
	// override whose system config is tamperable (config.go's bypass gate)
	// for weaker stakes than that. A warning on a path someone else can
	// rewrite is a control in name only.
	//
	// The directory is checked as well as the file: a writable parent lets
	// the file be replaced wholesale, which is the half a mode check on the
	// node alone misses — the same reasoning internal/uds applies to the
	// 0600-in-0700 socket invariant.
	for _, target := range []struct{ kind, path string }{
		{"file", path},
		{"directory", filepath.Dir(path)},
	} {
		insecure, checkErr := perms.IsGroupWorldWritable(target.path)
		if checkErr != nil {
			// Unreadable permissions are not a licence to proceed: the check
			// exists precisely because the answer matters.
			return nil, fmt.Errorf("user config: cannot check permissions on %s %q: %w", target.kind, target.path, checkErr)
		}
		if insecure {
			return nil, fmt.Errorf("user config %s %q is writable by group or others; tighten it (chmod go-w) before dotvault will read it", target.kind, target.path)
		}
	}

	uc, err := ParseUserConfig(data)
	if err != nil {
		// The path is the single most useful thing in this message: on macOS
		// and Windows the file lives somewhere a user would never guess, and
		// without it they are told something is wrong with a file they cannot
		// find.
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return uc, nil
}

// overruledWarned records the preferences already reported as overruled.
//
// The daemon re-runs the whole loader on every config-refresh tick (15m by
// default), so without this the same warning repeats for the life of the
// process. Once per field is the useful signal: the user is told their
// preference did not take, and the log does not fill with it.
var overruledWarned sync.Map

func warnOverruledOnce(field, msg string) {
	if _, seen := overruledWarned.LoadOrStore(field, struct{}{}); seen {
		return
	}
	slog.Warn(msg, "section", field)
}

// ApplyUser merges a user configuration over c in place and re-validates the
// sections it touched.
//
// Each field's merge rule is a ratchet rather than an assignment, so the
// result cannot grant the user more than policy allows in the directions that
// matter. Re-validation is scoped to the affected section: the base has
// already been validated, and the user file can only reach the filesystem
// block.
//
// A nil overlay is a no-op, so callers need not branch on whether the file
// existed.
func (c *Config) ApplyUser(u *UserConfig) error {
	if u == nil || u.FUSE == nil {
		return nil
	}
	f := u.FUSE

	if f.Enabled != nil {
		if !*f.Enabled && c.FUSE.Enabled {
			warnOverruledOnce("fuse.enabled",
				"user config cannot disable the filesystem; the system configuration enables it")
		}
		// OR: the user may turn it on, never off.
		c.FUSE.Enabled = c.FUSE.Enabled || *f.Enabled
	}

	if f.ReadWrite != nil {
		if *f.ReadWrite && !c.FUSE.ReadWrite {
			warnOverruledOnce("fuse.read_write",
				"user config cannot enable filesystem writes; the system configuration disables them")
		}
		// AND: the user may turn it off, never on.
		c.FUSE.ReadWrite = c.FUSE.ReadWrite && *f.ReadWrite
	}

	if f.Mountpoint != "" {
		c.FUSE.Mountpoint = f.Mountpoint
	}
	if f.CacheTTL != "" {
		c.FUSE.RawCacheTTL = f.CacheTTL
	}

	if err := c.validateFUSE(); err != nil {
		return fmt.Errorf("user config: %w", err)
	}
	return nil
}
