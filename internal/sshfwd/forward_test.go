package sshfwd

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestPumpCopiesBothDirections(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	go Pump(a2, b1)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := a1.Write([]byte("ping")); err != nil {
			t.Error(err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(b2, buf); err != nil {
			t.Error(err)
			return
		}
		if string(buf) != "ping" {
			t.Errorf("a→b got %q, want %q", buf, "ping")
		}
		if _, err := b2.Write([]byte("pong")); err != nil {
			t.Error(err)
			return
		}
		rbuf := make([]byte, 4)
		if _, err := io.ReadFull(a1, rbuf); err != nil {
			t.Error(err)
			return
		}
		if string(rbuf) != "pong" {
			t.Errorf("b→a got %q, want %q", rbuf, "pong")
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Pump did not relay within 5s")
	}
	a1.Close()
	b2.Close()
}

func TestPumpClosesBothWhenOneSideEnds(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); Pump(a2, b1) }()

	a1.Close()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Pump did not return after one side closed")
	}

	if _, err := b2.Read(make([]byte, 1)); err == nil {
		t.Error("far side still readable; Pump must close both connections")
	}
}

type fakeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newFakeListener() *fakeListener {
	return &fakeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (f *fakeListener) Accept() (net.Conn, error) {
	select {
	case c := <-f.conns:
		return c, nil
	case <-f.closed:
		return nil, net.ErrClosed
	}
}

func (f *fakeListener) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeListener) Addr() net.Addr { return fakeAddr{} }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "unix" }
func (fakeAddr) String() string  { return "/fake.sock" }

func TestServeListenerRelaysToTarget(t *testing.T) {
	ln := newFakeListener()
	t.Cleanup(func() { ln.Close() })

	targetSrv, targetCli := net.Pipe()
	target := func(ctx context.Context) (net.Conn, error) { return targetCli, nil }

	var active struct {
		sync.Mutex
		max int
		cur int
	}
	onConn := func(delta int) {
		active.Lock()
		defer active.Unlock()
		active.cur += delta
		if active.cur > active.max {
			active.max = active.cur
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go serveListener(ctx, ln, target, onConn)

	remote, forwarded := net.Pipe()
	ln.conns <- forwarded

	if _, err := remote.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if err := targetSrv.SetReadDeadline(time.Now().Add(5 * time.Second)); err == nil {
		// net.Pipe supports deadlines since Go 1.10.
	}
	if _, err := io.ReadFull(targetSrv, buf); err != nil {
		t.Fatalf("target did not receive forwarded bytes: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("target got %q, want %q", buf, "hello")
	}

	active.Lock()
	max := active.max
	active.Unlock()
	if max != 1 {
		t.Errorf("active connection gauge peaked at %d, want 1", max)
	}

	remote.Close()
	targetSrv.Close()

	// onConn(-1) must fire once Pump finishes, or the active-connection gauge
	// in `dotvault ssh list` / status climbs monotonically and never comes
	// back down.
	deadline := time.Now().Add(5 * time.Second)
	for {
		active.Lock()
		cur := active.cur
		active.Unlock()
		if cur == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("active connection gauge stuck at %d after the connection closed; onConn(-1) did not fire", cur)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServeListenerStopsOnContextCancel(t *testing.T) {
	ln := newFakeListener()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- serveListener(ctx, ln, func(context.Context) (net.Conn, error) {
			return nil, errors.New("unused")
		}, func(int) {})
	}()

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			t.Errorf("serveListener returned %v, want nil/Canceled/ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveListener did not return after cancel")
	}
}

func TestServeListenerSurvivesTargetDialFailure(t *testing.T) {
	ln := newFakeListener()
	t.Cleanup(func() { ln.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var calls int
	var mu sync.Mutex
	target := func(context.Context) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return nil, errors.New("target down")
	}
	go serveListener(ctx, ln, target, func(int) {})

	for i := 0; i < 2; i++ {
		_, forwarded := net.Pipe()
		ln.conns <- forwarded
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := calls
		mu.Unlock()
		if n == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("serveListener stopped accepting after a target dial failure")
}

// errorListener always fails Accept, simulating a died transport (sshd
// restart, connection drop) — a return path distinct from ctx cancellation.
type errorListener struct{ err error }

func (e errorListener) Accept() (net.Conn, error) { return nil, e.err }
func (e errorListener) Close() error              { return nil }
func (e errorListener) Addr() net.Addr            { return fakeAddr{} }

func TestServeListenerReleasesWatcherGoroutineOnAcceptFailure(t *testing.T) {
	runtime.GC()
	base := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // best-effort cleanup even if the assertion below fails

	ln := errorListener{err: errors.New("transport died")}
	if err := serveListener(ctx, ln, func(context.Context) (net.Conn, error) {
		return nil, errors.New("unused")
	}, func(int) {}); err == nil {
		t.Fatal("serveListener returned nil for a failing Accept; want the wrapped error")
	}

	// The ctx-watcher goroutine parks on <-ctx.Done() until releasing it; a
	// return caused by Accept failing on its own (not ctx cancellation) must
	// still release it via serveListener's own done channel, not depend on
	// this test's later cancel() to reap it.
	deadline := time.Now().Add(2 * time.Second)
	for {
		runtime.Gosched()
		if n := runtime.NumGoroutine(); n <= base {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine count did not settle back to the pre-call baseline (%d) within 2s after serveListener returned via a non-context Accept failure; the ctx-watcher goroutine leaked", base)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestServeListenerClosesInFlightConnectionOnCancel(t *testing.T) {
	ln := newFakeListener()
	t.Cleanup(func() { ln.Close() })

	targetSrv, targetCli := net.Pipe()
	t.Cleanup(func() { targetSrv.Close() })
	target := func(ctx context.Context) (net.Conn, error) { return targetCli, nil }

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- serveListener(ctx, ln, target, func(int) {}) }()

	// The "remote" end is deliberately never written to or closed: absent
	// cancellation-driven teardown, Pump would block forever waiting for EOF
	// on this connection, and serveListener would never return.
	_, forwarded := net.Pipe()
	ln.conns <- forwarded

	time.Sleep(50 * time.Millisecond) // let the accept goroutine register the connection
	cancel()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			t.Errorf("serveListener returned %v, want nil/Canceled/ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveListener did not return after cancel; an in-flight relayed connection was not torn down")
	}
}

func TestPumpClosesBothEndsFullyOnRealSockets(t *testing.T) {
	// net.Pipe cannot exercise this: its conns do not implement CloseWrite, so
	// copyDir's own EOF-triggered fallback close already fully closes both
	// ends regardless of Pump's trailing Close calls (see
	// TestPumpClosesBothWhenOneSideEnds). A real TCP pair does implement
	// CloseWrite, so ending one direction only half-closes it — this is the
	// only way to observe whether the trailing Close is actually load-bearing.
	newPair := func(t *testing.T) (client, server net.Conn) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		accepted := make(chan net.Conn, 1)
		acceptErr := make(chan error, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
			accepted <- c
		}()

		cl, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		select {
		case sv := <-accepted:
			return cl, sv
		case err := <-acceptErr:
			t.Fatal(err)
		case <-time.After(5 * time.Second):
			t.Fatal("accept timed out")
		}
		return nil, nil
	}

	c1, s1 := newPair(t)
	c2, s2 := newPair(t)

	// s1 and s2 stand in for the two ends Pump relays between — the accepted
	// forwarded connection and the local target dial, in production.
	done := make(chan struct{})
	go func() { Pump(s1, s2); close(done) }()

	// End both directions so both copyDir loops reach EOF and Pump returns.
	c1.Close()
	c2.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Pump did not return after both real peers closed")
	}

	if _, err := s1.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("s1.Read after Pump returned = %v, want net.ErrClosed — the trailing Close is load-bearing on CloseWrite-capable sockets and net.Pipe cannot express this", err)
	}
	if _, err := s2.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("s2.Read after Pump returned = %v, want net.ErrClosed", err)
	}
}
