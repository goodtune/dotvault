//go:build linux

package tokenwatch

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"unsafe"

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

// Watch monitors the parent directory of path and calls onChange when a
// file with path's basename is created or updated. It blocks until ctx
// is cancelled — returning ctx.Err() — or returns a non-nil error if
// the inotify machinery could not be set up or read. onChange runs on
// the watch goroutine, so keep it cheap; the daemon passes
// LifecycleManager.Reload, a non-blocking channel nudge.
//
// The directory rather than the file is watched because atomic writers
// replace the inode; a file-level watch would survive only until the
// first rotation. Watching the directory and filtering events by name
// keeps the subscription alive across arbitrarily many replacements.
func Watch(ctx context.Context, path string, onChange func()) error {
	dir := filepath.Dir(path)
	name := filepath.Base(path)

	// Non-blocking fd so the read loop interleaves ctx-cancellation
	// checks (via Poll with a bounded timeout) instead of blocking
	// forever in Read.
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	if _, err := unix.InotifyAddWatch(fd, dir, watchMask); err != nil {
		return err
	}

	// Generous relative to the 272-byte worst-case single event
	// (SizeofInotifyEvent + NAME_MAX + 1); inotify never returns a
	// partial event, so a buffer this size holds several at once.
	var buf [4096]byte
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
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

		nread, err := unix.Read(fd, buf[:])
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}

		if nameMatched(buf[:nread], name) {
			onChange()
		}
	}
}

// nameMatched reports whether any inotify event in buf names the watched
// file. A directory watch delivers events for every entry, so the name
// filter is what scopes the callback to the token file. Coalescing a
// burst of matching events into a single onChange is fine — Reload is
// idempotent.
func nameMatched(buf []byte, name string) bool {
	offset := 0
	for offset+unix.SizeofInotifyEvent <= len(buf) {
		raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
		nameLen := int(raw.Len)
		start := offset + unix.SizeofInotifyEvent
		end := start + nameLen
		if nameLen > 0 && end <= len(buf) {
			// The name field is NUL-padded to the event alignment;
			// trim at the first NUL before comparing.
			evName := buf[start:end]
			if i := bytes.IndexByte(evName, 0); i >= 0 {
				evName = evName[:i]
			}
			if string(evName) == name {
				return true
			}
		}
		offset = end
	}
	return false
}
