package vaultfs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Options configures a mounted filesystem.
type Options struct {
	// Mountpoint is the directory to mount on, already expanded to an
	// absolute path.
	Mountpoint string

	// ReadWrite permits writes through the mount. Default false: the mount
	// is read-only regardless of what the Vault token could do, because the
	// token's write capability exists for the daemon's own sync and
	// enrolment work, not to make every process running as this user one
	// stray `>` away from replacing a credential.
	ReadWrite bool

	// CacheTTL is how long a directory listing or a rendered secret is
	// reused before Vault is asked again. Zero disables caching.
	CacheTTL time.Duration
}

// State is the mount's lifecycle state, reported by Status.
type State string

const (
	// StateStopped means the filesystem is not mounted — either it has not
	// started yet or it has been unmounted.
	StateStopped State = "stopped"
	// StateMounted means the filesystem is mounted and serving.
	StateMounted State = "mounted"
	// StateFailed means mounting was attempted and failed; Status.Error says
	// why.
	StateFailed State = "failed"
)

// Status is the snapshot `dotvault status` and the web API render.
type Status struct {
	Mountpoint string `json:"mountpoint"`
	ReadWrite  bool   `json:"read_write"`
	State      State  `json:"state"`
	Error      string `json:"error,omitempty"`
}

// Service owns the lifetime of one mounted filesystem: it prepares the
// mountpoint, mounts, serves until the context is cancelled, and unmounts.
//
// It is constructible on every platform so the daemon and `dotvault status`
// can describe the configured filesystem without caring whether this build
// can mount one; only Run reaches the platform-specific layer, and on a
// platform without FUSE it returns ErrUnsupported without side effects.
type Service struct {
	opts Options
	tree *Tree

	mu      sync.Mutex
	state   State
	lastErr error
}

// NewService builds a service over store. It does not touch the filesystem.
func NewService(store Store, opts Options) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("vaultfs: nil store")
	}
	if opts.Mountpoint == "" {
		return nil, fmt.Errorf("vaultfs: empty mountpoint")
	}
	return &Service{
		opts:  opts,
		tree:  NewTree(store, opts.ReadWrite, opts.CacheTTL),
		state: StateStopped,
	}, nil
}

// Mountpoint returns the directory the service mounts on.
func (s *Service) Mountpoint() string { return s.opts.Mountpoint }

// Tree exposes the underlying tree, for callers that want to drop cached
// state (after a token change, say) without going through the mount.
func (s *Service) Tree() *Tree { return s.tree }

// Status returns the current mount state.
func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		Mountpoint: s.opts.Mountpoint,
		ReadWrite:  s.opts.ReadWrite,
		State:      s.state,
	}
	if s.lastErr != nil {
		st.Error = s.lastErr.Error()
	}
	return st
}

func (s *Service) setState(state State, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
	s.lastErr = err
}

// Run mounts the filesystem and serves it until ctx is cancelled, then
// unmounts and returns.
//
// Unlike the SSH agent's listener, a failed mount is not retried in a loop.
// The failure modes here are overwhelmingly static — no /dev/fuse, no
// fusermount binary, macFUSE not installed, the mountpoint occupied — and
// none of them clear on their own, so a retry loop would only produce a
// warning every few seconds for the daemon's whole lifetime. The error is
// reported once, recorded in Status, and the daemon carries on without the
// filesystem.
func (s *Service) Run(ctx context.Context) error {
	if err := prepareMountpoint(s.opts.Mountpoint); err != nil {
		s.setState(StateFailed, err)
		return err
	}

	srv, err := mount(s.opts.Mountpoint, s.tree, s.opts)
	if err != nil {
		s.setState(StateFailed, err)
		return err
	}
	s.setState(StateMounted, nil)
	slog.Info("filesystem mounted",
		"mountpoint", s.opts.Mountpoint,
		"mode", accessMode(s.opts.ReadWrite),
		"cache_ttl", s.opts.CacheTTL)

	// Unmounting is what makes the mountpoint usable again, so it has to
	// happen on shutdown even though a process still sitting inside the
	// mount can refuse it. Retry briefly, then leave the mount in place and
	// say so — a stale mountpoint the operator can clear by hand is a better
	// outcome than a daemon that will not exit.
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		s.unmount(srv)
	}()

	srv.Wait()
	<-done
	s.setState(StateStopped, nil)
	slog.Info("filesystem unmounted", "mountpoint", s.opts.Mountpoint)
	return nil
}

// unmountAttempts and unmountBackoff bound the shutdown retry loop. Roughly
// three seconds in total: long enough for a shell that was `cd`'d into the
// mount to be the only holder and go away, short enough not to stall a
// daemon restart.
const (
	unmountAttempts = 6
	unmountBackoff  = 500 * time.Millisecond
)

func (s *Service) unmount(srv mountedFS) {
	var err error
	for attempt := range unmountAttempts {
		if err = srv.Unmount(); err == nil {
			return
		}
		if attempt < unmountAttempts-1 {
			time.Sleep(unmountBackoff)
		}
	}
	slog.Warn("could not unmount filesystem; a process is still using it",
		"mountpoint", s.opts.Mountpoint,
		"error", err,
		"hint", "close anything under the mountpoint, then unmount it manually")
}

func accessMode(rw bool) string {
	if rw {
		return "read-write"
	}
	return "read-only"
}

// mountedFS is the platform layer's handle on a live mount.
type mountedFS interface {
	// Wait blocks until the filesystem is unmounted.
	Wait()
	// Unmount detaches the filesystem, returning an error if it is busy.
	Unmount() error
}

// prepareMountpoint makes sure the mountpoint exists and is a directory we own.
//
// It is created rather than required to exist because the default (~/.dotvault)
// is dotvault's own to manage, and requiring the user to mkdir it first is a
// setup step with no purpose. It is created 0700: a mounted filesystem's
// permissions come from the FUSE mount (owner-only by default), but between
// unmounts the bare directory is visible, and a world-readable empty directory
// where secrets are about to appear is the wrong default to leave behind.
func prepareMountpoint(dir string) error {
	info, err := os.Stat(dir)
	switch {
	case err == nil:
		if !info.IsDir() {
			return fmt.Errorf("mountpoint %q exists and is not a directory", dir)
		}
		return nil
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create mountpoint %q: %w", dir, err)
		}
		return nil
	default:
		// A stale mount left behind by a killed daemon reports ENOTCONN
		// here rather than a normal stat error. The platform layer knows how
		// to clear that; everything else is a genuine failure.
		if clearStaleMount(dir, err) {
			return nil
		}
		return fmt.Errorf("stat mountpoint %q: %w", dir, err)
	}
}
