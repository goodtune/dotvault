package config

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/paths"
)

// DefaultFUSEMountpoint is where the filesystem mounts when fuse.mountpoint is
// unset. It is `~`-relative rather than absolute so an exported config stays
// portable between machines and users.
const DefaultFUSEMountpoint = "~/.dotvault"

// DefaultFUSECacheTTL is how long a listing or a rendered secret is reused
// before Vault is asked again, when fuse.cache_ttl is unset.
//
// Thirty seconds is chosen against what a filesystem actually does rather than
// against how often secrets change: a single `ls -l` stats every entry, so
// without a cache one directory listing becomes one Vault read per secret. The
// window is short enough that a secret rotated by the daemon (or by another
// machine) shows up well inside the time it takes a human to notice, and a
// write through the mount invalidates its own entries immediately.
const DefaultFUSECacheTTL = 30 * time.Second

// MaxFUSECacheTTL bounds how long the mount may serve a secret without asking
// Vault again.
//
// The cache is what makes the filesystem usable, but it is also a window in
// which a revoked or rotated secret stays readable — in this package's cache
// and in the kernel's, since the entry/attr timeouts track the same value. Ten
// minutes is far longer than the cache needs to do its job (its purpose is to
// collapse the burst of stats a single `ls -l` produces) and short enough that
// a revocation is never left standing for an appreciable time.
const MaxFUSECacheTTL = 10 * time.Minute

// FUSEConfig configures the filesystem view of the user's KV secrets: each
// secret appears as a file whose contents are its data section rendered as
// JSON, so `jq . ~/.dotvault/gh` works and stat reports the secret's version
// timestamp as the file's mtime.
//
// Disabled by default. Unix only: Windows has no FUSE implementation that can
// be reached from a CGO_ENABLED=0 binary, so enabling it there logs a warning
// and mounts nothing — the same treatment api.enabled gets.
//
// The inner fields deliberately omit `omitempty` for the same round-trip
// reason as AgentConfig and APIConfig: an exported config must re-emit cleared
// optional values so a re-import can blank a previously-set mountpoint. The
// top-level FUSE field keeps `omitempty` so operators who do not use the
// filesystem see no empty block in downloads.
type FUSEConfig struct {
	Enabled bool `yaml:"enabled"`

	// Mountpoint is the directory to mount on. Empty resolves to
	// DefaultFUSEMountpoint at daemon-start time — defaulting there rather
	// than at load time so an exported config round-trips the operator's
	// literal value instead of baking in one machine's home directory. A
	// leading ~ is expanded, as it is for api.unix.path.
	Mountpoint string `yaml:"mountpoint"`

	// ReadWrite permits writing through the mount: replacing a secret by
	// writing JSON over its file, creating one, and deleting one by
	// unlinking it.
	//
	// Default false, deliberately, even though the daemon's token can
	// usually write. The token's write capability exists for the daemon's
	// own sync and enrolment work; exposing it through a filesystem makes
	// every process running as this user — and every mistyped shell
	// redirect — able to overwrite a credential. Opting in is a separate
	// decision from mounting.
	ReadWrite bool `yaml:"read_write"`

	// CacheTTL is the parsed form of RawCacheTTL, filled in by validation.
	CacheTTL time.Duration `yaml:"-"`

	// RawCacheTTL is the configured cache window as a duration string.
	// Empty means DefaultFUSECacheTTL; an explicit "0" disables caching so
	// every operation reaches Vault.
	RawCacheTTL string `yaml:"cache_ttl"`

	// UserOverlayPath names the per-user file that contributed to this
	// section, empty when none did. Set by the overlay loader, never
	// serialised — the same treatment Config.Managed gets, and for the same
	// reason: it records where the configuration came from rather than being
	// part of it, so an exported config must not carry it back in.
	//
	// It exists so `dotvault status` can say that a mount came from the
	// user's own preference. Without it, an administrator looking at a
	// machine whose policy says the filesystem is off has only a startup
	// WARN, long since scrolled past, to explain why one is mounted.
	UserOverlayPath string `yaml:"-"`
}

// fuseMountpointCandidate returns the configured mountpoint — the operator's
// literal value, or the default when unset — without expanding a leading ~. It
// returns "" whenever no filesystem will be mounted: the section is disabled,
// or the platform has no FUSE at all.
//
// Windows is gated here rather than only at the mount site so every consumer
// agrees, exactly as apiSocketCandidate does for the local API socket. A
// mountpoint resolved on Windows would name a directory nothing ever mounts,
// and `dotvault status` would report it as merely "not mounted (daemon not
// running?)" when in fact it can never be mounted.
func (c *Config) fuseMountpointCandidate() string {
	if !c.FUSE.Enabled || runtime.GOOS == "windows" {
		return ""
	}
	if p := c.FUSE.Mountpoint; p != "" {
		return p
	}
	return DefaultFUSEMountpoint
}

// FUSEMountpoint resolves the directory the daemon should mount the filesystem
// on, with a leading ~ expanded. It returns "" when no filesystem applies
// (disabled, or an unsupported platform), so callers can treat "no path" and
// "not enabled" identically.
func (c *Config) FUSEMountpoint() (string, error) {
	p := c.fuseMountpointCandidate()
	if p == "" {
		return "", nil
	}
	expanded, err := paths.ExpandHome(p)
	if err != nil {
		return "", fmt.Errorf("fuse.mountpoint %q: %w", p, err)
	}
	return expanded, nil
}

// isAbsMountpoint reports whether p is a usable mountpoint spelling: ~-relative,
// or absolute.
//
// A leading slash counts as absolute on every platform, not just where
// filepath.IsAbs says so. This section only ever takes effect on Unix, but the
// config carrying it is shared across a mixed fleet — and filepath.IsAbs is
// host-relative, so a perfectly good "/home/gary/.dotvault" is "relative" to a
// Windows binary. Judging it by the host would make a Windows daemon *exit* on
// a config written for the Linux machines beside it, which is precisely what
// the warn-and-mount-nothing gate elsewhere in this file exists to prevent.
func isAbsMountpoint(p string) bool {
	return strings.HasPrefix(p, "~") || strings.HasPrefix(p, "/") || filepath.IsAbs(p)
}

// validateFUSE checks the filesystem section and fills in CacheTTL.
//
// Like validateAPI, it runs whether or not the section is enabled: a relative
// mountpoint or an unparseable duration is a mistake worth naming at load time
// rather than at the moment someone flips `enabled: true`.
func (c *Config) validateFUSE() error {
	if p := c.FUSE.Mountpoint; p != "" && !isAbsMountpoint(p) {
		// A relative mountpoint would be resolved against the daemon's
		// working directory, so the daemon and anyone reading the config
		// would disagree about where the secrets appeared.
		return fmt.Errorf("fuse.mountpoint %q: must be an absolute path (or ~-relative)", p)
	}

	switch c.FUSE.RawCacheTTL {
	case "":
		c.FUSE.CacheTTL = DefaultFUSECacheTTL
	default:
		d, err := ParseDuration(c.FUSE.RawCacheTTL)
		if err != nil {
			return fmt.Errorf("fuse.cache_ttl %q: %w", c.FUSE.RawCacheTTL, err)
		}
		if d < 0 {
			return fmt.Errorf("fuse.cache_ttl %q: must not be negative", c.FUSE.RawCacheTTL)
		}
		if d > MaxFUSECacheTTL {
			return fmt.Errorf("fuse.cache_ttl %q: must not exceed %s (a longer window leaves a revoked secret readable)", c.FUSE.RawCacheTTL, MaxFUSECacheTTL)
		}
		c.FUSE.CacheTTL = d
	}
	return nil
}
