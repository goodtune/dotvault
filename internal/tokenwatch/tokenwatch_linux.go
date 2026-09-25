//go:build linux

package tokenwatch

import (
	"context"
	"errors"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// watchMask is the set of inotify events that signal the token file has
// been created or replaced with new content:
//
//   - IN_CLOSE_WRITE — a writer that opened the file for writing closed
//     it (the in-place write / truncate case).
//   - IN_MOVED_TO — a file was renamed into the directory under the
//     watched name (the atomic temp-file+rename case `vault login` and
//     dotvault itself use).
//   - IN_CREATE — the file appeared where none existed (covers writers
//     that create-and-write without a rename, and re-creation after a
//     prior delete).
//
// Deletes (IN_DELETE, IN_MOVED_FROM) are intentionally absent: the
// daemon keeps using its current token until a replacement lands.
const watchMask = unix.IN_CLOSE_WRITE | unix.IN_MOVED_TO | unix.IN_CREATE

// pollTimeoutMs bounds each Poll so ctx cancellation is observed
// promptly instead of blocking forever in Read. 100ms matches the idle
// wakeup cadence cmd/dotvault/enrol_keywait_unix.go already uses — well
// below any reasonable CPU-cost budget, and the token reload it gates
// is not latency-sensitive to that degree.
const pollTimeoutMs = 100

// Watcher holds a live inotify subscription to the token file's parent
// directory. Splitting registration (New) from the read loop (Run) lets
// the daemon make InotifyAddWatch synchronous — completing before any
// "no token, idle" decision — so a token written in the gap between
// registration and the loop starting is queued by the kernel and
// delivered once Run begins, rather than being lost (inotify only
// delivers events that occur after InotifyAddWatch returns).
type Watcher struct {
	fd       int
	match    func(name string) bool
	onChange func(name string)
}

// New registers an inotify watch on the parent directory of path and
// returns a Watcher ready to Run. Registration is synchronous: on
// return the kernel is already queuing events for path's basename, so a
// caller that issues a reconciling read after New (to catch a token
// that predates the watch) plus Run (to catch everything after) cannot
// miss a write. onChange runs on the Run goroutine, so keep it cheap;
// the daemon passes LifecycleManager.Reload, a non-blocking channel
// nudge.
//
// The directory rather than the file is watched because atomic writers
// replace the inode; a file-level watch would survive only until the
// first rotation. Watching the directory and filtering events by name
// keeps the subscription alive across arbitrarily many replacements.
//
// New is built on the more general NewMatch, narrowed to a single
// literal name.
func New(path string, onChange func()) (*Watcher, error) {
	name := filepath.Base(path)
	return NewMatch(filepath.Dir(path), func(n string) bool { return n == name }, func(string) { onChange() })
}

// Run blocks reading the inotify fd registered by New, calling onChange
// whenever an event names the watched file. It returns when ctx is
// cancelled — yielding ctx.Err() — or on an unrecoverable read error.
// Run does not close the fd; call Close (typically via defer) to release
// it.
func (w *Watcher) Run(ctx context.Context) error {
	// Generous relative to the 272-byte worst-case single event
	// (SizeofInotifyEvent + NAME_MAX + 1); inotify never returns a
	// partial event, so a buffer this size holds several at once.
	var buf [4096]byte
	pfd := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		pfd[0].Revents = 0
		n, err := unix.Poll(pfd, pollTimeoutMs)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if n <= 0 || pfd[0].Revents&unix.POLLIN == 0 {
			continue
		}

		nread, err := unix.Read(w.fd, buf[:])
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}

		for _, name := range matchedNames(buf[:nread], w.match) {
			w.onChange(name)
		}
	}
}

// Close releases the inotify fd. It is safe to call after Run returns.
func (w *Watcher) Close() error {
	return unix.Close(w.fd)
}

// Watch is a thin wrapper that registers a Watcher, runs it, and closes
// it — preserving the original one-shot API for existing callers and
// tests. New callers that need registration to complete before a
// no-token decision should use New/Run/Close directly.
func Watch(ctx context.Context, path string, onChange func()) error {
	w, err := New(path, onChange)
	if err != nil {
		return err
	}
	defer w.Close()
	return w.Run(ctx)
}
