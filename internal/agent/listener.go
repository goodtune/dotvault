package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"golang.org/x/crypto/ssh/agent"
)

// Listener serves an agent backend over a platform transport (Unix domain
// socket or Windows named pipe). The shared Serve/Close logic lives here; the
// endpoint creation and teardown are platform-specific (listener_unix.go,
// listener_windows.go). Endpoint permissions are a hard invariant on both
// platforms: only the owning user may connect.
type Listener struct {
	addr    string
	backend agent.ExtendedAgent

	mu     sync.Mutex
	ln     net.Listener
	closed bool
}

// NewListener returns a listener bound to addr (socket path or pipe name) that
// serves backend.
func NewListener(addr string, backend agent.ExtendedAgent) *Listener {
	return &Listener{addr: addr, backend: backend}
}

// Addr returns the configured endpoint address.
func (l *Listener) Addr() string { return l.addr }

// Serve creates the endpoint and accepts connections until ctx is cancelled,
// dispatching each to agent.ServeAgent in its own goroutine. Cancellation
// closes the endpoint, unblocks Accept, and returns nil — errors arising from
// the closed endpoint during shutdown are a clean stop, not a failure.
func (l *Listener) Serve(ctx context.Context) error {
	ln, err := l.platformListen()
	if err != nil {
		return err
	}
	l.mu.Lock()
	if l.closed {
		// Closed before we finished binding (racing shutdown).
		l.mu.Unlock()
		_ = ln.Close()
		l.platformCleanup()
		return nil
	}
	l.ln = ln
	l.mu.Unlock()

	slog.Info("ssh agent listening", "endpoint", l.addr)

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = l.Close()
		case <-done:
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || l.isClosed() {
				return nil
			}
			return fmt.Errorf("ssh agent accept: %w", err)
		}
		go l.serveConn(conn)
	}
}

func (l *Listener) serveConn(conn net.Conn) {
	defer conn.Close()
	// agent.ServeAgent blocks until the client disconnects; the resulting
	// io.EOF is the normal end of a connection and must not be fatal to the
	// listener.
	if err := agent.ServeAgent(l.backend, conn); err != nil && !errors.Is(err, io.EOF) {
		slog.Debug("ssh agent connection ended", "error", err)
	}
}

func (l *Listener) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// Close shuts the endpoint down. Safe to call more than once.
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	ln := l.ln
	l.mu.Unlock()

	var err error
	if ln != nil {
		err = ln.Close()
	}
	l.platformCleanup()
	return err
}
