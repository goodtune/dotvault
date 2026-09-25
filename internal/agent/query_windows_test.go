//go:build windows

package agent

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
)

// The Unix half of these regression tests lives in query_test.go, which is
// //go:build !windows because it needs socket files. The named-pipe transport
// is the half whose deadline and concurrent-close semantics are least obvious
// — winio's pipe conn implements SetDeadline over separate read/write
// deadlines, and the watcher goroutine closes the conn while a read is in
// flight — so the same two properties are pinned here against a real pipe.

// pipeName returns a per-test pipe name; a named pipe carries one name, so
// tests must not share.
func pipeName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`\\.\pipe\dotvault-test-%s-%d`, t.Name(), time.Now().UnixNano())
}

// silentPipe listens on a fresh pipe, accepts one connection and never speaks
// the agent protocol — the pipe equivalent of a connection sitting unread in a
// listen backlog.
func silentPipe(t *testing.T) string {
	t.Helper()
	name := pipeName(t)
	ln, err := winio.ListenPipe(name, nil)
	if err != nil {
		t.Fatalf("ListenPipe: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	held := make(chan interface{ Close() error }, 1)
	go func() {
		if conn, err := ln.Accept(); err == nil {
			held <- conn
		}
	}()
	t.Cleanup(func() {
		select {
		case conn := <-held:
			conn.Close()
		default:
		}
	})
	return name
}

// TestQueryListeningUnresponsivePipe is the named-pipe counterpart of
// TestQueryListeningUnresponsiveEndpoint: bounding only the dial left
// `dotvault status` blocked in List() forever against a daemon that had
// accepted but was not yet serving.
func TestQueryListeningUnresponsivePipe(t *testing.T) {
	name := silentPipe(t)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := QueryListening(ctx, name)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from a pipe that accepts but never replies")
		}
	case <-time.After(3 * queryTimeout):
		t.Fatal("QueryListening blocked on a connected but silent pipe; the agent-protocol exchange is unbounded")
	}
}

// TestQueryListeningHonoursCancellationPipe confirms Ctrl+C unblocks the query
// on Windows too — the path where the watcher goroutine closes a winio conn
// with a read in flight.
func TestQueryListeningHonoursCancellationPipe(t *testing.T) {
	name := silentPipe(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := QueryListening(ctx, name)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error after the caller cancelled")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("QueryListening ignored caller cancellation on a named pipe")
	}
}
