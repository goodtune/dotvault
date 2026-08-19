package config

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sort"
	"strings"

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
	var probe map[string]any
	if err := yaml.Unmarshal(data, &probe); err != nil {
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

// isConfigSection reports whether key names a real top-level Config section.
// A key that is neither user-overridable nor a known section is a typo or a
// future section, and warns rather than failing.
func isConfigSection(key string) bool {
	switch key {
	case "vault", "sync", "web", "observability", "agent", "api", "ssh",
		"remote_config", "rules", "enrolments", "bypass_system_config", "fuse":
		return true
	}
	return false
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

	// The file can turn the filesystem on and relocate where secrets appear,
	// so another account being able to write it matters even though it is in
	// the user's own directory.
	if insecure, checkErr := perms.IsGroupWorldWritable(path); checkErr == nil && insecure {
		slog.Warn("user config file is group or world writable", "path", path)
	}

	return ParseUserConfig(data)
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
			slog.Warn("user config cannot disable the filesystem; the system configuration enables it",
				"section", "fuse.enabled")
		}
		// OR: the user may turn it on, never off.
		c.FUSE.Enabled = c.FUSE.Enabled || *f.Enabled
	}

	if f.ReadWrite != nil {
		if *f.ReadWrite && !c.FUSE.ReadWrite {
			slog.Warn("user config cannot enable filesystem writes; the system configuration disables them",
				"section", "fuse.read_write")
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
