//go:build unix

package main

import (
	"context"
	"errors"
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
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		n, err := unix.Poll(pfd, pollTimeoutMillis(remaining))
		if errors.Is(err, unix.EINTR) {
			// A signal interrupted the wait, which says nothing about
			// whether input arrived — retry for what is left of the budget.
			// This is not a rare case to wave away: the Go runtime delivers
			// SIGURG to preempt goroutines, so on a busy process poll is
			// interrupted routinely. Reporting that as "no input" made
			// drainEscapeTail give up part-way through an arrow key's escape
			// sequence, so the keystroke was silently dropped (a 2-byte
			// prefix classifies as keyNone) or, worse, taken as quit (a lone
			// ESC classifies as keyQuit) — the picker exiting on an arrow
			// press. It surfaced as a CI flake in the split-escape tests, but
			// the user-visible bug is on a real terminal.
			continue
		}
		if err != nil || n <= 0 {
			return false
		}
		return pfd[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0
	}
}

// pollTimeoutMillis converts a remaining budget to poll(2)'s whole-millisecond
// timeout. It floors, with a floor of 1: any positive value below a
// millisecond becomes 1 rather than 0.
//
// Zero is not a short wait but a non-blocking check: poll returns at once,
// and waitForMoreInput reads that as "no input" even though the budget had
// time left and the byte may land microseconds later — the same wrong answer
// the EINTR retry above removes, reached by arithmetic instead of by a signal.
// Flooring is right everywhere above a millisecond, because a truncated wait
// still blocks and the loop simply comes round again; only zero is hazardous.
//
// Its one call site rejects a non-positive budget first, so the clamp is
// unreachable today. It is written as < 1 rather than == 0 anyway, because a
// negative timeout tells poll to block forever: if a future caller ever let
// one through, == 0 would trade a wait that ends too early for one that never
// ends at all.
func pollTimeoutMillis(remaining time.Duration) int {
	ms := int(remaining / time.Millisecond)
	if ms < 1 {
		ms = 1
	}
	return ms
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
