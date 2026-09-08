// Package dockervol serves the user's KVv2 secrets to containers as a Docker
// volume plugin.
//
// It speaks the Docker volume plugin protocol (JSON over HTTP on a Unix
// socket — the "legacy" plugin API that rootless Docker and Podman both
// consume) so a container can do
//
//	docker run --mount type=volume,volume-driver=dotvault,volume-opt=secrets=gh,dst=/run/secrets/dotvault ...
//
// and find /run/secrets/dotvault/gh.json inside, rendered from
// kv/users/<you>/gh exactly as the FUSE mount (internal/vaultfs) would render
// it. Authentication and the KV prefix come from the daemon's own configuration
// — a volume is a view of the secrets the daemon's token can already read, and
// the plugin adds no way to reach anyone else's.
//
// # Files, not a filesystem
//
// A volume is a directory of plain files the daemon writes and keeps current,
// not a FUSE mount. That is the same shape as Docker's own secrets (a tmpfs at
// /run/secrets) and it is chosen for the container case specifically: a FUSE
// mount is accessible only to the mounting uid, which under rootless
// containers is container root alone, and it depends on mount propagation
// into the engine's namespace that Podman does not guarantee. Plain files in a
// directory that already existed when the engine started need neither, and a
// container user other than root can be granted read access with a single
// `mode=` option.
//
// # Caching follows the Vault edition
//
// The daemon decides how a volume stays fresh from what Vault can offer. On
// Vault Enterprise it subscribes to the KVv2 event stream and re-renders a
// volume the moment one of its secrets changes; while that subscription is
// connected a volume is otherwise never re-read. On Community (or while an
// Enterprise subscription is down) every volume is re-rendered on a fixed
// window — docker.cache_ttl, or the volume's own ttl option — so a rotation
// reaches the container within that window. Reconnecting the subscription
// refreshes everything, since anything may have changed in the gap.
//
// # Selection and layout
//
// Which secrets a volume carries is chosen at `docker volume create` with
// `-o secrets=a,b/,c/d` — bare names are single secrets, a trailing slash is a
// whole folder, and no option at all is the user's entire subtree, matching
// the mount. `-o layout=fields` writes one file per field
// (/run/secrets/dotvault/gh/oauth_token) for programs that want a raw value
// rather than a JSON document; `-o mode=0444` widens the files to non-root
// container users.
package dockervol

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vaultfs"
)

// DriverName is the name the engine addresses the plugin by — the
// `volume-driver=` value, and the stem of the .spec file that registers it.
const DriverName = "dotvault"

// ErrNotFound is returned for a volume name the driver does not know.
var ErrNotFound = errors.New("no such volume")

// ErrNoToken is returned by Mount while the daemon holds no Vault token: the
// volume cannot be populated, and an empty directory would be a worse answer
// than a refusal the container runtime reports.
var ErrNoToken = errors.New("dotvault has not authenticated with vault yet, so the volume cannot be populated")

// ErrUnsupported is returned by Run on platforms where the plugin is not
// served.
var ErrUnsupported = errors.New("dockervol: the volume plugin is served on linux only")

// Layout is how a secret is laid out on disk.
type Layout string

const (
	// LayoutJSON renders each secret as <name>.json holding its data
	// section — the FUSE mount's layout, and the default.
	LayoutJSON Layout = "json"
	// LayoutFields renders each secret as a directory <name>/ holding one
	// file per field, the raw value as the file's contents — the shape
	// programs expecting a Docker secret at a *_FILE path want.
	LayoutFields Layout = "fields"
)

// Option names accepted at `docker volume create -o`.
const (
	OptSecrets = "secrets"
	OptLayout  = "layout"
	OptMode    = "mode"
	OptTTL     = "ttl"
)

// DefaultMode is the file mode a volume's files carry when the mode option
// is unset: owner read only. Under a rootless engine the owner is container
// root; a container process running as any other user cannot read the secret
// until the volume is created with a wider mode.
const DefaultMode os.FileMode = 0o400

// modeReadBits are the only bits the mode option may set. Write bits would
// invite a container to edit a file the next refresh overwrites, and an
// executable secret is not a thing.
const modeReadBits os.FileMode = 0o444

// volumeNamePattern is Docker's own restricted-name rule for volumes. It
// excludes a path separator by construction, which is what lets the name be
// used as a directory name under the volume dir without further checks.
var volumeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

const maxVolumeNameLen = 255

// Spec is a volume's validated definition — what its options resolved to.
// It is what the driver persists across restarts, alongside the raw options
// for `docker volume inspect` to echo back.
type Spec struct {
	// Secrets is the selection, each entry a canonical relative KV path;
	// a trailing slash marks a folder. Empty means the whole subtree.
	Secrets []string `json:"secrets,omitempty"`
	Layout  Layout   `json:"layout"`
	// Mode is the file mode; directories derive theirs from it.
	Mode os.FileMode `json:"mode"`
	// TTL is the refresh window used when events are not driving refreshes.
	TTL time.Duration `json:"ttl"`
}

// ValidateName checks a volume name against Docker's own rule.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("volume name is empty")
	}
	if len(name) > maxVolumeNameLen {
		return fmt.Errorf("volume name %q is longer than %d characters", name, maxVolumeNameLen)
	}
	if !volumeNamePattern.MatchString(name) {
		return fmt.Errorf("volume name %q is invalid: only [a-zA-Z0-9][a-zA-Z0-9_.-]* is accepted", name)
	}
	return nil
}

// ParseOptions turns the `-o` map from a create request into a Spec, with
// defaultTTL standing in for an absent ttl option.
//
// An unknown option is an error rather than ignored: a mistyped `secret=`
// that silently selected the whole subtree would hand a container every
// secret the user has, which is the opposite of what they typed.
func ParseOptions(opts map[string]string, defaultTTL time.Duration) (Spec, error) {
	spec := Spec{Layout: LayoutJSON, Mode: DefaultMode, TTL: defaultTTL}
	for k, v := range opts {
		switch k {
		case OptSecrets:
			sel, err := parseSelection(v)
			if err != nil {
				return Spec{}, fmt.Errorf("option %s: %w", k, err)
			}
			spec.Secrets = sel
		case OptLayout:
			switch Layout(v) {
			case LayoutJSON, LayoutFields:
				spec.Layout = Layout(v)
			default:
				return Spec{}, fmt.Errorf("option %s: %q is not one of %s, %s", k, v, LayoutJSON, LayoutFields)
			}
		case OptMode:
			m, err := strconv.ParseUint(strings.TrimPrefix(v, "0o"), 8, 32)
			if err != nil {
				return Spec{}, fmt.Errorf("option %s: %q is not an octal mode", k, v)
			}
			mode := os.FileMode(m)
			if mode == 0 || mode&^modeReadBits != 0 {
				return Spec{}, fmt.Errorf("option %s: %q may only set read bits (0400, 0440, 0444)", k, v)
			}
			if mode&0o400 == 0 {
				// The daemon must be able to read back what it wrote to
				// decide whether a refresh changed anything.
				return Spec{}, fmt.Errorf("option %s: %q must include owner read", k, v)
			}
			spec.Mode = mode
		case OptTTL:
			d, err := config.ParseDuration(v)
			if err != nil {
				return Spec{}, fmt.Errorf("option %s: %q: %w", k, v, err)
			}
			if err := config.ValidateDockerTTL(d); err != nil {
				return Spec{}, fmt.Errorf("option %s: %q: %w", k, v, err)
			}
			spec.TTL = d
		default:
			return Spec{}, fmt.Errorf("unknown option %q (accepted: %s, %s, %s, %s)", k, OptSecrets, OptLayout, OptMode, OptTTL)
		}
	}
	if spec.TTL <= 0 {
		return Spec{}, fmt.Errorf("no refresh window: neither a ttl option nor a configured docker.cache_ttl")
	}
	return spec, nil
}

// parseSelection splits a comma-separated `secrets=` value into canonical
// relative paths, keeping a trailing slash as the folder marker. Entries are
// deduplicated and sorted so two volumes created with the same secrets in a
// different order compare equal.
func parseSelection(v string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range strings.Split(v, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		folder := strings.HasSuffix(raw, "/")
		clean, err := vaultfs.CleanPath(raw)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", raw, err)
		}
		if clean == "" {
			// "/" alone: the whole subtree, which is what no selection
			// already means. Reject rather than guess.
			return nil, fmt.Errorf("%q: a bare slash selects nothing; omit the option to select every secret", raw)
		}
		if folder {
			clean += "/"
		}
		if !seen[clean] {
			seen[clean] = true
			out = append(out, clean)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Covers reports whether the selection includes the secret at relPath (a
// canonical relative KV path with no trailing slash). It is the one
// definition used both to decide what to render and to decide whether a
// Vault event concerns this volume.
func (s Spec) Covers(relPath string) bool {
	if len(s.Secrets) == 0 {
		return true
	}
	for _, sel := range s.Secrets {
		if folder, ok := strings.CutSuffix(sel, "/"); ok {
			if relPath == folder || strings.HasPrefix(relPath, folder+"/") {
				return true
			}
			continue
		}
		if relPath == sel {
			return true
		}
	}
	return false
}

// Equal reports whether two specs describe the same volume.
func (s Spec) Equal(o Spec) bool {
	if s.Layout != o.Layout || s.Mode != o.Mode || s.TTL != o.TTL || len(s.Secrets) != len(o.Secrets) {
		return false
	}
	for i := range s.Secrets {
		if s.Secrets[i] != o.Secrets[i] {
			return false
		}
	}
	return true
}

// DirMode derives a directory mode from the file mode: the owner keeps full
// access (the daemon has to create files inside), and any principal granted
// read on the files is granted traverse on the directories, or the read
// would be unreachable.
func (s Spec) DirMode() os.FileMode {
	shared := s.Mode & 0o044
	return 0o700 | shared | (shared >> 2)
}
