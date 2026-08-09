package sshfwd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// metricsSpy replaces every observability record-site var for the duration
// of a test, restoring the originals on cleanup, and records every call it
// receives so a test can assert both what fired and — just as
// important — what did not.
type metricsSpy struct {
	mu sync.Mutex

	connState        []bool // recordSSHConnState's connected argument, in call order
	reconnects       int
	connectFailures  []string // recordSSHConnectFailure's class argument, in call order
	keepaliveFailure int
	forwardConn      []int // recordSSHForwardConn's delta argument, in call order
	forwardFailure   int
}

func installMetricsSpy(t *testing.T) *metricsSpy {
	t.Helper()
	origState, origReconnect, origConnFail, origKeepFail, origFwdConn := recordSSHConnState, recordSSHReconnect, recordSSHConnectFailure, recordSSHKeepaliveFailure, recordSSHForwardConn
	origFwdFail := recordSSHForwardFailure
	t.Cleanup(func() {
		recordSSHConnState = origState
		recordSSHReconnect = origReconnect
		recordSSHConnectFailure = origConnFail
		recordSSHKeepaliveFailure = origKeepFail
		recordSSHForwardConn = origFwdConn
		recordSSHForwardFailure = origFwdFail
	})

	s := &metricsSpy{}
	recordSSHConnState = func(_ context.Context, _ string, connected bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.connState = append(s.connState, connected)
	}
	recordSSHReconnect = func(_ context.Context, _ string) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.reconnects++
	}
	recordSSHConnectFailure = func(_ context.Context, _, class string) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.connectFailures = append(s.connectFailures, class)
	}
	recordSSHKeepaliveFailure = func(_ context.Context, _ string) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.keepaliveFailure++
	}
	recordSSHForwardConn = func(_ context.Context, _ string, delta int) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.forwardConn = append(s.forwardConn, delta)
	}
	recordSSHForwardFailure = func(_ context.Context) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.forwardFailure++
	}
	return s
}

// metricsSnapshot is a copyable, lock-free view of metricsSpy's counters —
// separate from metricsSpy itself so snapshot() can return by value without
// copying the embedded mutex.
type metricsSnapshot struct {
	connState        []bool
	reconnects       int
	connectFailures  []string
	keepaliveFailure int
	forwardConn      []int
	forwardFailure   int
}

func (s *metricsSpy) snapshot() metricsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return metricsSnapshot{
		connState:        append([]bool(nil), s.connState...),
		reconnects:       s.reconnects,
		connectFailures:  append([]string(nil), s.connectFailures...),
		keepaliveFailure: s.keepaliveFailure,
		forwardConn:      append([]int(nil), s.forwardConn...),
		forwardFailure:   s.forwardFailure,
	}
}

// TestConnStateRecordedOnlyOnTransition drives the same
// connect→drop→reconnect cycle as TestRunConnectServeDropReconnectCycle and
// asserts the connection-state gauge fires exactly on the two real
// transitions (into StateConnected, then out of it) — not once per pass
// through run()'s retry loop. run() calls setState(StateConnecting, ...)
// on every iteration including the redial itself, so this is the case that
// would catch a naively-placed "record on every setState call" mistake.
func TestConnStateRecordedOnlyOnTransition(t *testing.T) {
	fakeTransport(t)
	spy := installMetricsSpy(t)

	var dialCount int32
	dialRemote = func(ctx context.Context, c DialConfig) (*ssh.Client, error) {
		atomic.AddInt32(&dialCount, 1)
		return &ssh.Client{}, nil
	}
	closeRemoteClient = func(c *ssh.Client) error { return nil }
	forwardRemote = dropOnce(errors.New("simulated forward drop"))
	keepaliveRemote = blockingKeepalive

	mr := newManagedRemote(Remote{Host: "foo.example.com", RemoteSocket: "/run/dotvault-test.sock"}, Deps{
		Signers: func() ([]ssh.Signer, error) { return nil, nil },
		User:    func() (string, error) { return "u", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{} },
		Target:  func(ctx context.Context) (net.Conn, error) { return nil, errors.New("not used by this test") },
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		mr.run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&dialCount) < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&dialCount); got < 2 {
		t.Fatalf("dial count = %d, want >= 2 (a reconnect)", got)
	}

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && mr.status("").State != string(StateConnected) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := mr.status("").State; got != string(StateConnected) {
		t.Fatalf("state after reconnect = %q, want %q", got, StateConnected)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run() did not exit after ctx cancellation")
	}

	got := spy.snapshot()
	// One full cycle is connect (true), drop (false), reconnect (true), then
	// the test's own cancel() tears the second connection down (false) —
	// exactly four calls despite run()'s loop having spun through
	// StateConnecting on every one of those attempts plus any transient
	// retries. A per-iteration bug would inflate this well past 4.
	want := []bool{true, false, true, false}
	if len(got.connState) != len(want) {
		t.Fatalf("RecordSSHConnState called %d times %v, want exactly %v", len(got.connState), got.connState, want)
	}
	for i, w := range want {
		if got.connState[i] != w {
			t.Errorf("RecordSSHConnState call %d = %v, want %v (full sequence %v)", i, got.connState[i], w, got.connState)
		}
	}
	if got.reconnects != 1 {
		t.Errorf("RecordSSHReconnect called %d times, want exactly 1 (one drop, one reconnect)", got.reconnects)
	}
}

// TestConnectFailureClassNotErrorMessage pins the cardinality guarantee at
// its source: fail() must record sshfwd's fixed ErrorClass string, not the
// error's own free-form message. Two distinct DNS errors (different
// messages, same class) must produce the identical recorded label — if
// fail() were changed to pass err.Error() instead, this test would start
// seeing two different values and fail, which is the mutation the
// call-site review depends on this test to catch.
func TestConnectFailureClassNotErrorMessage(t *testing.T) {
	spy := installMetricsSpy(t)

	mr := newManagedRemote(remote("foo.example.com"), Deps{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // fail()'s sleep must return immediately regardless of backoff

	dnsErr1 := &net.DNSError{Err: "no such host", Name: "one.invalid"}
	dnsErr2 := &net.DNSError{Err: "server misbehaving", Name: "two.invalid"}
	if Classify(dnsErr1) != ClassDNS || Classify(dnsErr2) != ClassDNS {
		t.Fatal("test setup: both errors must classify as ClassDNS")
	}

	mr.fail(ctx, dnsErr1)
	mr.fail(ctx, dnsErr2)

	got := spy.snapshot()
	if len(got.connectFailures) != 2 {
		t.Fatalf("RecordSSHConnectFailure called %d times, want 2", len(got.connectFailures))
	}
	for i, class := range got.connectFailures {
		if class != string(ClassDNS) {
			t.Errorf("call %d recorded class %q, want %q (%s) — the fixed class, not the error message", i, class, ClassDNS, []error{dnsErr1, dnsErr2}[i])
		}
	}
	if got.connectFailures[0] != got.connectFailures[1] {
		t.Errorf("two errors of the same class recorded different labels (%q vs %q) — this is exactly the unbounded-cardinality failure mode the class taxonomy exists to prevent", got.connectFailures[0], got.connectFailures[1])
	}
}

// TestKeepaliveFailureRecordedOnlyOnRealStrikeFailure asserts the keepalive
// counter fires when Keepalive genuinely exhausts its strikes, and does not
// fire when the connection instead ends via ordinary shutdown (ctx
// cancellation) — Keepalive returns a non-nil error (ctx.Err()) in the
// shutdown case too, so the distinction has to be made on connCtx state, not
// merely "err != nil".
func TestKeepaliveFailureRecordedOnlyOnRealStrikeFailure(t *testing.T) {
	fakeTransport(t)
	spy := installMetricsSpy(t)

	dialRemote = func(ctx context.Context, c DialConfig) (*ssh.Client, error) {
		return &ssh.Client{}, nil
	}
	closeRemoteClient = func(c *ssh.Client) error { return nil }
	// forwardRemote blocks forever (until connCtx is cancelled by the
	// keepalive side losing first, or by the outer ctx/stop).
	forwardRemote = func(ctx context.Context, cl *ssh.Client, socket string, target Dialer, onConn func(int)) error {
		<-ctx.Done()
		return ctx.Err()
	}
	strikeErr := fmt.Errorf("keepalive failed 3 times: %w", errKeepaliveTimeout)
	keepaliveRemote = func(ctx context.Context, cl requestSender, interval time.Duration, strikes int) error {
		return strikeErr
	}

	mr := newManagedRemote(Remote{Host: "foo.example.com", RemoteSocket: "/run/dotvault-test.sock"}, Deps{
		Signers: func() ([]ssh.Signer, error) { return nil, nil },
		User:    func() (string, error) { return "u", nil },
		Policy:  func(Remote) *HostKeyPolicy { return &HostKeyPolicy{} },
		Target:  func(ctx context.Context) (net.Conn, error) { return nil, errors.New("not used by this test") },
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		mr.run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && spy.snapshot().keepaliveFailure == 0 {
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run() did not exit after ctx cancellation")
	}

	got := spy.snapshot()
	if got.keepaliveFailure != 1 {
		t.Errorf("RecordSSHKeepaliveFailure called %d times, want exactly 1 for the genuine strike failure", got.keepaliveFailure)
	}
}

// TestForwardConnRecordedPerAcceptAndClose pins onConn's metric side: one
// call per accepted connection (positive delta) and one per closed
// connection (negative delta), mirroring the internal activeConns
// bookkeeping it sits beside.
func TestForwardConnRecordedPerAcceptAndClose(t *testing.T) {
	spy := installMetricsSpy(t)

	mr := newManagedRemote(remote("foo.example.com"), Deps{})
	mr.onConn(1)
	mr.onConn(1)
	mr.onConn(-1)

	got := spy.snapshot()
	want := []int{1, 1, -1}
	if len(got.forwardConn) != len(want) {
		t.Fatalf("RecordSSHForwardConn called %d times %v, want %v", len(got.forwardConn), got.forwardConn, want)
	}
	for i, w := range want {
		if got.forwardConn[i] != w {
			t.Errorf("call %d delta = %d, want %d", i, got.forwardConn[i], w)
		}
	}
}
