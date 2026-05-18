//go:build unix

package main

import (
	"time"

	"golang.org/x/sys/unix"
)

// waitForMoreInput reports whether at least one more byte is available
// to read from fd within the given timeout. Used by readSingleKey after
// it has read a bare ESC byte to decide whether the keystroke is a
// genuine Esc press (no follow-up bytes) or the start of a multi-byte
// escape sequence (arrow / function key) whose tail bytes are in flight
// across a slow link.
//
// On POSIX terms term.MakeRaw configures VMIN=1 VTIME=0, so a Read
// returns the moment a single byte is available — the tail of an
// arrow's "\x1b[A" sequence can in principle land in a second Read. A
// short Poll() against POLLIN closes the gap without resorting to
// per-platform termios juggling, and it works on both real TTY fds and
// the os.Pipe fds the tests use.
func waitForMoreInput(fd uintptr, timeout time.Duration) bool {
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(pfd, int(timeout/time.Millisecond))
	if err != nil || n <= 0 {
		return false
	}
	return pfd[0].Revents&unix.POLLIN != 0
}
