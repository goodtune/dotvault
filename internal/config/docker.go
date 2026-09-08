package config

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/paths"
)

// DefaultDockerCacheTTL is how long a materialised volume is served before
// Vault is asked again, when docker.cache_ttl is unset and the volume itself
// sets no ttl.
//
// It only governs the Community edition, or an Enterprise daemon whose event
// subscription has dropped: with a live subscription the volume is refreshed
// the moment Vault reports a write and is otherwise never re-read. One minute
// is longer than the filesystem's 30s because a volume is refreshed as a
// whole — every secret it selects is re-read on each pass, where the mount
// re-reads only what something touched — and because nothing in a container
// is stat-ing every entry the way `ls -l` does.
const DefaultDockerCacheTTL = time.Minute

// MaxDockerCacheTTL bounds the volume refresh window. Same reasoning as
// MaxFUSECacheTTL: the window is also how long a rotated or revoked secret
// keeps being served to a container, so it is capped rather than left to an
// operator to set to a day.
const MaxDockerCacheTTL = MaxFUSECacheTTL

// DockerConfig configures the Docker volume plugin: a per-user Unix socket
// speaking the Docker volume plugin protocol, so a container (rootless or not,
// Docker or Podman) can mount a directory of this user's secrets at a path
// like /run/secrets/dotvault.
//
// Disabled by default. Linux only: the plugin protocol needs the container
// engine on the same kernel — Docker Desktop and Podman machine run theirs in
// a VM where a host-side socket is unreachable — so enabling it elsewhere logs
// a warning and serves nothing, the same treatment api.enabled and
// fuse.enabled get on Windows.
//
// The inner fields deliberately omit `omitempty` for the round-trip reason
// every other optional section states: an exported config must re-emit
// cleared values so a re-import can blank a previously-set path. The
// top-level Docker field keeps `omitempty` so operators who do not use the
// plugin see no empty block in downloads.
type DockerConfig struct {
	Enabled bool `yaml:"enabled"`

	// Socket is the Unix socket path the plugin listens on. Empty resolves to
	// paths.DefaultDockerSocket at daemon-start time — defaulting there rather
	// than at load time so an exported config round-trips the operator's
	// literal value instead of baking in one machine's runtime directory. A
	// leading ~ is expanded, as it is for api.unix.path.
	Socket string `yaml:"socket"`

	// VolumeDir is the directory each volume is materialised under. Empty
	// resolves to paths.DefaultDockerVolumeDir at daemon-start time. Created
	// 0700; each volume is a subdirectory of it.
	VolumeDir string `yaml:"volume_dir"`

	// CacheTTL is the parsed form of RawCacheTTL, filled in by validation.
	CacheTTL time.Duration `yaml:"-"`

	// RawCacheTTL is the default refresh window as a duration string. Empty
	// means DefaultDockerCacheTTL. Unlike fuse.cache_ttl, zero is not a
	// valid value: a volume has no "ask Vault on every read" mode, since the
	// container reads plain files. A volume may override it with its own
	// ttl option, subject to the same ceiling.
	RawCacheTTL string `yaml:"cache_ttl"`
}

// dockerSupported reports whether this build can serve the plugin at all.
// Gated on the platform, not on the presence of an engine: the daemon has no
// business probing for one, and an absent engine simply never connects.
func dockerSupported() bool { return runtime.GOOS == "linux" }

// dockerSocketCandidate returns the configured plugin socket path — the
// operator's literal value, or the per-user runtime default when unset —
// without expanding a leading ~. It returns "" whenever no socket will exist:
// the section is disabled, or the platform has no engine that could reach it.
//
// The platform gate lives here rather than only at the bind site so every
// consumer agrees, exactly as apiSocketCandidate does for the API socket: a
// path resolved on an unsupported platform would name a socket nothing ever
// binds, and `dotvault status` would report it as merely "not listening"
// when in fact it can never be.
func (c *Config) dockerSocketCandidate() string {
	if !c.Docker.Enabled || !dockerSupported() {
		return ""
	}
	if p := c.Docker.Socket; p != "" {
		return p
	}
	return paths.DefaultDockerSocket()
}

// DockerSocketPath resolves the plugin socket path the daemon should bind,
// with a leading ~ expanded. It returns "" when no plugin applies (disabled,
// or an unsupported platform), so callers can treat "no path" and "not
// enabled" identically.
func (c *Config) DockerSocketPath() (string, error) {
	p := c.dockerSocketCandidate()
	if p == "" {
		return "", nil
	}
	expanded, err := paths.ExpandHome(p)
	if err != nil {
		return "", fmt.Errorf("docker.socket %q: %w", p, err)
	}
	return expanded, nil
}

// DockerVolumeDir resolves the directory volumes are materialised under, with
// a leading ~ expanded. Returns "" under the same conditions as
// DockerSocketPath.
func (c *Config) DockerVolumeDir() (string, error) {
	if !c.Docker.Enabled || !dockerSupported() {
		return "", nil
	}
	p := c.Docker.VolumeDir
	if p == "" {
		p = paths.DefaultDockerVolumeDir()
	}
	expanded, err := paths.ExpandHome(p)
	if err != nil {
		return "", fmt.Errorf("docker.volume_dir %q: %w", p, err)
	}
	return expanded, nil
}

// validateDocker checks the plugin section and fills in CacheTTL.
//
// Like validateAPI and validateFUSE, it runs whether or not the section is
// enabled: a relative path or an unparseable duration is a mistake worth
// naming at load time rather than at the moment someone flips `enabled: true`.
func (c *Config) validateDocker() error {
	for _, f := range []struct{ name, value string }{
		{"docker.socket", c.Docker.Socket},
		{"docker.volume_dir", c.Docker.VolumeDir},
	} {
		if f.value == "" || strings.HasPrefix(f.value, "~") {
			continue
		}
		// A leading slash counts as absolute on every platform, for the
		// same mixed-fleet reason isAbsMountpoint gives: this section only
		// takes effect on Linux, but the config carrying it is shared, and a
		// Windows daemon must not exit on a path written for the Linux
		// machines beside it.
		if !strings.HasPrefix(f.value, "/") && !filepath.IsAbs(f.value) {
			return fmt.Errorf("%s %q: must be an absolute path (or ~-relative)", f.name, f.value)
		}
	}

	switch c.Docker.RawCacheTTL {
	case "":
		c.Docker.CacheTTL = DefaultDockerCacheTTL
	default:
		d, err := ParseDuration(c.Docker.RawCacheTTL)
		if err != nil {
			return fmt.Errorf("docker.cache_ttl %q: %w", c.Docker.RawCacheTTL, err)
		}
		if err := ValidateDockerTTL(d); err != nil {
			return fmt.Errorf("docker.cache_ttl %q: %w", c.Docker.RawCacheTTL, err)
		}
		c.Docker.CacheTTL = d
	}
	return nil
}

// ValidateDockerTTL checks a volume refresh window against the bounds the
// config section and a per-volume ttl option share. Exported so the volume
// driver applies exactly the same rule to a `-o ttl=` option that the config
// loader applies to docker.cache_ttl — one definition, two gates.
func ValidateDockerTTL(d time.Duration) error {
	if d <= 0 {
		return fmt.Errorf("must be positive (a container reads plain files, so there is no ask-on-every-read mode to select with 0)")
	}
	if d > MaxDockerCacheTTL {
		return fmt.Errorf("must not exceed %s (a longer window leaves a rotated secret in the container)", MaxDockerCacheTTL)
	}
	return nil
}
