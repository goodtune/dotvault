//go:build unix

package main

import (
	"context"
	"time"

	"golang.org/x/sys/unix"
)

// waitForMoreInput reports whether fd is ready for a Read (data
// available, EOF, or error). Used by readSingleKey after it has read
// a bare ESC byte to decide whether the keystroke is a genuine Esc
// press (no follow-up bytes) or the start of a multi-byte escape
// sequence (arrow / function key) whose tail bytes are in flight
// across a slow link, and by blockUntilInput as the wakeup primitive
// for the ctx-aware idle loop.
//
// On POSIX terms term.MakeRaw configures VMIN=1 VTIME=0, so a Read
// returns the moment a single byte is available — the tail of an
// arrow's "\x1b[A" sequence can in principle land in a second Read. A
// short Poll() against POLLIN closes the gap without resorting to
// per-platform termios juggling, and it works on both real TTY fds and
// the os.Pipe fds the tests use.
//
// POLLHUP and POLLERR also count as "ready" so a closed pipe (the
// shape blockUntilInput sees in tests with a closed writer) wakes us
// up — the subsequent Read returns 0/EOF and readSingleKey
// classifies that as quit, instead of the loop spinning forever
// because POLLIN never fires on a closed-empty pipe.
func waitForMoreInput(fd uintptr, timeout time.Duration) bool {
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(pfd, int(timeout/time.Millisecond))
	if err != nil || n <= 0 {
		return false
	}
	return pfd[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0
}

// blockUntilInput waits until fd has input ready to read or ctx is
// cancelled, returning ctx.Err() on cancellation and nil when input
// is available. Polls in short slices so an external SIGTERM/SIGINT
// arriving while the picker is idle in raw-mode input doesn't leave
// the process stuck until the user presses a key.
//
// The wakeup interval is small enough to feel responsive without
// being a measurable CPU cost (~100ms idle wakeup is well below any
// reasonable observation budget for an interactive command).
func blockUntilInput(ctx context.Context, fd uintptr) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if waitForMoreInput(fd, 100*time.Millisecond) {
			return nil
		}
	}
}
