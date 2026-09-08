package dockervol

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
	"github.com/goodtune/dotvault/internal/vaultfs"
)

// EventSource is the subset of *vault.Client the refresh policy needs: the
// edition probe that decides between events and polling, and the
// subscription itself. Narrowed to an interface so the policy is testable
// against a fake Vault.
type EventSource interface {
	ServerHealth(ctx context.Context) (*vault.HealthResponse, error)
	SubscribeEvents(ctx context.Context, eventType string) (<-chan vault.Event, <-chan error, error)
}

// Options configures a Driver.
type Options struct {
	// SocketPath is where Run listens for the container engine.
	SocketPath string
	// VolumeDir is the directory each volume is materialised under, as a
	// subdirectory named after the volume.
	VolumeDir string
	// StatePath is the file volume definitions persist to across daemon
	// restarts. Definitions only — no secret data.
	StatePath string
	// DefaultTTL is the refresh window a volume gets when created without
	// a ttl option.
	DefaultTTL time.Duration
	// UserPrefix is the KV path prefix of the user's subtree, e.g.
	// "users/gary/", used to relate a Vault event's path to a volume.
	UserPrefix string
	// HasToken reports whether the Vault client currently holds a token. A
	// Mount that would have to populate a volume is refused while it does
	// not, and the event watcher waits for one before subscribing. Nil
	// means "always".
	HasToken func() bool
}

// Timeouts bounding the Vault work behind one request or one refresh. A
// mount is answered inside the engine's own request timeout; a background
// refresh may take longer since nothing waits on it but the ticker.
const (
	mountTimeout   = 30 * time.Second
	refreshTimeout = 2 * time.Minute
)

// Driver is the volume driver: the registry of volumes, their on-disk state,
// and the refresh policy that keeps them current.
type Driver struct {
	opts   Options
	store  vaultfs.Store
	events EventSource
	now    func() time.Time

	// ctx is the lifetime context Run was given; volume loops derive from
	// it. Background until Run starts, which is also when volumes can first
	// be mounted.
	ctxMu sync.Mutex
	ctx   context.Context

	mu      sync.Mutex
	volumes map[string]*volume

	// edition and eventsLive describe the refresh policy in force; see
	// runWatcher. Guarded by mu.
	edition    edition
	eventsLive bool
	eventsErr  string
}

type edition string

const (
	editionUnknown    edition = ""
	editionCommunity  edition = "community"
	editionEnterprise edition = "enterprise"
)

// Refresh modes reported in a volume's status.
const (
	RefreshEvents  = "events"
	RefreshPoll    = "poll"
	RefreshProbing = "probing"
)

type volume struct {
	Name string
	Opts map[string]string
	Spec Spec
	// Mounts is the set of engine-supplied mount IDs currently holding the
	// volume. It is persisted, so a daemon restart under a running
	// container resumes refreshing the directory the container still has
	// bind-mounted instead of wiping it.
	Mounts map[string]bool

	// Runtime state. cancel is non-nil while the refresh loop runs, which
	// is the definition of "active". opMu serialises all disk work on the
	// volume: a mount-time materialise, a loop refresh and the wipe on last
	// unmount must never interleave.
	opMu   sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
	nudge  chan struct{}

	lastRefresh time.Time
	lastErr     string
	secrets     int
}

// New builds a driver over store, loading any persisted definitions. It
// touches no socket and starts no goroutine; Run does both.
func New(opts Options, store vaultfs.Store, events EventSource) (*Driver, error) {
	if store == nil {
		return nil, fmt.Errorf("dockervol: nil store")
	}
	if opts.SocketPath == "" || opts.VolumeDir == "" || opts.StatePath == "" {
		return nil, fmt.Errorf("dockervol: socket, volume dir and state path are all required")
	}
	if opts.DefaultTTL <= 0 {
		return nil, fmt.Errorf("dockervol: default ttl must be positive")
	}
	d := &Driver{
		opts:    opts,
		store:   store,
		events:  events,
		now:     time.Now,
		ctx:     context.Background(),
		volumes: map[string]*volume{},
	}
	if err := d.load(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Driver) hasToken() bool {
	return d.opts.HasToken == nil || d.opts.HasToken()
}

func (d *Driver) lifetime() context.Context {
	d.ctxMu.Lock()
	defer d.ctxMu.Unlock()
	return d.ctx
}

func (d *Driver) setLifetime(ctx context.Context) {
	d.ctxMu.Lock()
	defer d.ctxMu.Unlock()
	d.ctx = ctx
}

// volumePath is the host directory a volume is materialised in. The name is
// validated against volumeNamePattern on creation, which excludes every
// path separator, so a plain join cannot escape VolumeDir.
func (d *Driver) volumePath(name string) string {
	return filepath.Join(d.opts.VolumeDir, name)
}

// Create registers a volume. Creating a name that already exists with the
// same options is a no-op, so an engine that re-sends a create after a
// restart is answered as it expects; the same name with different options
// is refused rather than silently redefined under whatever container
// mounted it first.
func (d *Driver) Create(name string, opts map[string]string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	spec, err := ParseOptions(opts, d.opts.DefaultTTL)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if existing, ok := d.volumes[name]; ok {
		if existing.Spec.Equal(spec) {
			return nil
		}
		return fmt.Errorf("volume %q already exists with different options; remove it first", name)
	}
	d.volumes[name] = &volume{
		Name:   name,
		Opts:   cloneOpts(opts),
		Spec:   spec,
		Mounts: map[string]bool{},
	}
	slog.Info("docker volume created", "volume", name, "secrets", spec.Secrets, "layout", spec.Layout)
	return d.saveLocked()
}

// Remove forgets a volume and deletes its directory. The engine only asks
// once its own reference count is zero, so outstanding mount IDs here mean
// the engine and the driver disagree (an unmount the daemon never received,
// typically because it was down at the time); the engine's view wins, and
// the disagreement is logged rather than left to wedge the volume forever.
func (d *Driver) Remove(name string) error {
	d.mu.Lock()
	v, ok := d.volumes[name]
	if !ok {
		d.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if n := len(v.Mounts); n > 0 {
		slog.Warn("removing a docker volume the driver still counts as mounted; trusting the engine", "volume", name, "mounts", n)
	}
	done := d.stopLoopLocked(v)
	delete(d.volumes, name)
	err := d.saveLocked()
	d.mu.Unlock()

	d.wipe(v, done)
	slog.Info("docker volume removed", "volume", name)
	return err
}

// Mount populates the volume if it is not already, records the caller, and
// returns the host directory the engine bind-mounts into the container.
func (d *Driver) Mount(ctx context.Context, name, id string) (string, error) {
	d.mu.Lock()
	v, ok := d.volumes[name]
	if !ok {
		d.mu.Unlock()
		return "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	active := v.cancel != nil
	d.mu.Unlock()

	dir := d.volumePath(name)
	if !active {
		// Only the first mount needs Vault: a second container joining a
		// volume that is already materialised gets the files that exist,
		// whatever the daemon's token is doing at that moment.
		if !d.hasToken() {
			return "", ErrNoToken
		}
		ctx, cancel := context.WithTimeout(ctx, mountTimeout)
		defer cancel()
		v.opMu.Lock()
		n, err := materialise(ctx, d.store, dir, v.Spec)
		v.opMu.Unlock()
		d.recordRefresh(v, n, err)
		if err != nil {
			return "", fmt.Errorf("populate volume %q: %w", name, err)
		}
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, still := d.volumes[name]; !still {
		return "", fmt.Errorf("%w: %s (removed while mounting)", ErrNotFound, name)
	}
	v.Mounts[id] = true
	if v.cancel == nil {
		d.startLoopLocked(v, false)
	}
	slog.Info("docker volume mounted", "volume", name, "mounts", len(v.Mounts), "secrets", v.secrets)
	return dir, d.saveLocked()
}

// Unmount drops one caller. When the last one goes, the refresh loop stops
// and the directory is deleted: a secret should not sit on disk for a
// container that no longer exists. Unknown volumes and unknown IDs are not
// errors — the engine may unmount what it believes is mounted after either
// side restarted, and refusing would leave its bookkeeping stuck.
func (d *Driver) Unmount(name, id string) error {
	d.mu.Lock()
	v, ok := d.volumes[name]
	if !ok {
		d.mu.Unlock()
		return nil
	}
	delete(v.Mounts, id)
	if len(v.Mounts) > 0 {
		err := d.saveLocked()
		d.mu.Unlock()
		return err
	}
	done := d.stopLoopLocked(v)
	err := d.saveLocked()
	d.mu.Unlock()

	d.wipe(v, done)
	slog.Info("docker volume unmounted", "volume", name)
	return err
}

// Path returns the host directory for a volume whether or not it is
// populated; the engine asks it for `docker volume inspect`.
func (d *Driver) Path(name string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.volumes[name]; !ok {
		return "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return d.volumePath(name), nil
}

// VolumeInfo is what Get and List report per volume, in the protocol's own
// field names.
type VolumeInfo struct {
	Name       string         `json:"Name"`
	Mountpoint string         `json:"Mountpoint,omitempty"`
	Status     map[string]any `json:"Status,omitempty"`
}

// Get describes one volume.
func (d *Driver) Get(name string) (VolumeInfo, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v, ok := d.volumes[name]
	if !ok {
		return VolumeInfo{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return d.infoLocked(v), nil
}

// List describes every volume, sorted by name.
func (d *Driver) List() []VolumeInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]VolumeInfo, 0, len(d.volumes))
	for _, v := range d.volumes {
		out = append(out, d.infoLocked(v))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Status keys carried in VolumeInfo.Status. They are the plugin protocol's
// only channel for driver-specific state, so `docker volume inspect` and
// `dotvault status` both read them.
const (
	StatusSecrets     = "secrets"
	StatusLayout      = "layout"
	StatusMode        = "mode"
	StatusTTL         = "ttl"
	StatusMounts      = "mounts"
	StatusRefresh     = "refresh"
	StatusLastRefresh = "last_refresh"
	StatusLastError   = "last_error"
	StatusSelection   = "selection"
)

func (d *Driver) infoLocked(v *volume) VolumeInfo {
	status := map[string]any{
		StatusSecrets: v.secrets,
		StatusLayout:  string(v.Spec.Layout),
		StatusMode:    fmt.Sprintf("%04o", v.Spec.Mode),
		StatusTTL:     v.Spec.TTL.String(),
		StatusMounts:  len(v.Mounts),
		StatusRefresh: d.refreshModeLocked(),
	}
	if len(v.Spec.Secrets) > 0 {
		status[StatusSelection] = append([]string(nil), v.Spec.Secrets...)
	} else {
		status[StatusSelection] = "all"
	}
	if !v.lastRefresh.IsZero() {
		status[StatusLastRefresh] = v.lastRefresh.Format(time.RFC3339)
	}
	if v.lastErr != "" {
		status[StatusLastError] = v.lastErr
	}
	return VolumeInfo{Name: v.Name, Mountpoint: d.volumePath(v.Name), Status: status}
}

// refreshModeLocked names the policy currently keeping volumes fresh.
func (d *Driver) refreshModeLocked() string {
	switch {
	case d.edition == editionUnknown:
		return RefreshProbing
	case d.edition == editionEnterprise && d.eventsLive:
		return RefreshEvents
	default:
		return RefreshPoll
	}
}

// Status is the driver-level view for the daemon's status surfaces.
type Status struct {
	Socket    string `json:"socket"`
	VolumeDir string `json:"volume_dir"`
	// Refresh is the policy in force: "events" (Enterprise, subscription
	// connected), "poll" (Community, or a subscription that is down), or
	// "probing" (the edition is not known yet).
	Refresh string `json:"refresh"`
	// EventsError is why the subscription is down, when it is.
	EventsError string       `json:"events_error,omitempty"`
	Volumes     []VolumeInfo `json:"volumes"`
}

// Status returns the driver's current state.
func (d *Driver) Status() Status {
	vols := d.List()
	d.mu.Lock()
	defer d.mu.Unlock()
	return Status{
		Socket:      d.opts.SocketPath,
		VolumeDir:   d.opts.VolumeDir,
		Refresh:     d.refreshModeLocked(),
		EventsError: d.eventsErr,
		Volumes:     vols,
	}
}

// recordRefresh notes the outcome of a materialise. A failure is logged when
// it first appears and when its text changes, not on every tick: a Vault
// that is down for an hour would otherwise produce sixty identical lines
// per volume.
func (d *Driver) recordRefresh(v *volume, secrets int, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		msg := err.Error()
		if msg != v.lastErr {
			slog.Warn("docker volume refresh failed", "volume", v.Name, "error", err)
		}
		v.lastErr = msg
		return
	}
	if v.lastErr != "" {
		slog.Info("docker volume refresh recovered", "volume", v.Name)
	}
	v.lastErr = ""
	v.lastRefresh = d.now()
	v.secrets = secrets
}

// wipe waits for a stopped loop to exit and then deletes the volume's
// directory. Called with mu released: the loop may be mid-refresh and about
// to call recordRefresh, which needs mu.
func (d *Driver) wipe(v *volume, done chan struct{}) {
	if done != nil {
		<-done
	}
	v.opMu.Lock()
	defer v.opMu.Unlock()
	if err := os.RemoveAll(d.volumePath(v.Name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("could not remove docker volume directory", "volume", v.Name, "error", err)
	}
}

func cloneOpts(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
