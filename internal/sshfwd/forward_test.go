package sshfwd

import (
	"context"
	"errors"
	"io"
	"net"
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
