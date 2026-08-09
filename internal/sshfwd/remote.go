package sshfwd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/goodtune/dotvault/internal/observability"
)

// recordSSHConnState, recordSSHReconnect, recordSSHConnectFailure, and
// recordSSHKeepaliveFailure are observability.RecordSSH* indirected through
// package-level vars — the same seam dialRemote/forwardRemote/keepaliveRemote
// below use — so a test can substitute a spy and assert exactly what a call
// site recorded (in particular, that the connect-failure class is the fixed
// ErrorClass string and not an error's free-form message) without standing
// up a real OTel reader.
var (
	recordSSHConnState        = observability.RecordSSHConnState
	recordSSHReconnect        = observability.RecordSSHReconnect
	recordSSHConnectFailure   = observability.RecordSSHConnectFailure
	recordSSHKeepaliveFailure = observability.RecordSSHKeepaliveFailure
	recordSSHForwardConn      = observability.RecordSSHForwardConn
)

// ClientWaitTimeout bounds how long WaitForClient blocks for a connection to
// arrive. Long enough to ride out a brief reconnect (a Wi-Fi handover, a
// laptop resuming from sleep triggering the keepalive strike path), short
// enough that a caller waiting on a genuinely dead remote gets an answer.
const ClientWaitTimeout = 10 * time.Second

// keepaliveInterval and keepaliveStrikes drive Keepalive for every managed
// remote, mirroring OpenSSH's ServerAliveInterval/ServerAliveCountMax
// defaults closely enough to surface a wedged transport within a couple of
// minutes without being noisy against an ordinary network blip.
const (
	keepaliveInterval = 30 * time.Second
	keepaliveStrikes  = 3
)

// ManagedRemote owns one configured remote's connection lifecycle: dial,
// forward, keepalive, and reconnect-with-backoff, reporting its condition
// through status() and its live transport through WaitForClient.
//
// Manager.Reconcile decides whether cfg has "changed" via cfg.sameAs, a
// semantic comparison — not ==, because Remote.Enabled is a *bool and two
// otherwise-identical configs loaded on separate occasions never share a
// pointer.
type ManagedRemote struct {
	cfg  Remote
	deps Deps

	backoff *Backoff

	mu             sync.Mutex
	state          State
	lastError      string
	client         *ssh.Client
	connectedSince *time.Time
	reconnects     int
	activeConns    int

	// clientReady is closed exactly once, when a client is installed via
	// setClient, and replaced with a fresh unclosed channel by clearClient —
	// so WaitForClient can block on whichever instance was current when it
	// looked, without missing a client that arrives concurrently.
	clientReady chan struct{}

	// clientWaitTimeout is ClientWaitTimeout by default; a field rather than
	// using the constant directly so a test can shrink it and turn
	// WaitForClient's timeout path into a fast, still-genuine wait instead of
	// a 10-second sleep asserted on the wall clock.
	clientWaitTimeout time.Duration

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// newManagedRemote returns a ManagedRemote for r, not yet started.
func newManagedRemote(r Remote, deps Deps) *ManagedRemote {
	return &ManagedRemote{
		cfg:               r,
		deps:              deps,
		backoff:           NewBackoff(),
		clientReady:       make(chan struct{}),
		clientWaitTimeout: ClientWaitTimeout,
	}
}

// isRunning reports whether start has been called on this remote. cancel is
// set exactly once, by start, and never cleared, so a nil cancel identifies a
// disabled entry that has only ever existed as a status-row placeholder.
func (r *ManagedRemote) isRunning() bool { return r.cancel != nil }

// start runs body in a tracked goroutine under a context derived from ctx, so
// stop() can cancel and wait for it deterministically. body is a parameter
// (rather than always r.run) so Manager can substitute a stub for testing
// without an SSH server.
//
// start returns as soon as the goroutine is launched — it does not wait for
// body to have begun running. An earlier version blocked on a rendezvous
// channel closed as the goroutine's first statement, intending to guarantee
// the goroutine had started before start (and therefore Reconcile) returned;
// it didn't actually provide that guarantee (closing a channel doesn't
// create a happens-before edge to the *next* statement in the goroutine that
// closed it, so a concurrent scheduler could still run the caller past that
// point first) and no production caller needs it — only a test did, and the
// test has its own poll-based wait for that (see runRecorder.waitStarted in
// manager_test.go).
func (r *ManagedRemote) start(ctx context.Context, body func(context.Context)) {
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		body(runCtx)
	}()
}

// stop cancels the running goroutine, if any, and waits for it to exit. Safe
// to call on a ManagedRemote that was never started (a disabled entry keeps
// a status row but has no goroutine) since cancel stays nil and wg was never
// incremented.
func (r *ManagedRemote) stop() {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
}

// setState records the externally visible state and, when err is non-nil,
// the error that produced it. A transition to StateConnected clears any
// stale error from a previous failed attempt.
func (r *ManagedRemote) setState(s State, err error) {
	r.mu.Lock()
	r.state = s
	if err != nil {
		r.lastError = err.Error()
	} else if s == StateConnected {
		r.lastError = ""
	}
	r.mu.Unlock()
}

// setClient installs the live transport and wakes every WaitForClient caller
// blocked on the previous clientReady channel.
//
// Must not be called twice without an intervening clearClient: closing an
// already-closed channel panics. run's single dial-then-serve sequence per
// attempt (one setClient, always paired with exactly one later clearClient
// before the next dial) is what keeps that invariant true; a future change
// to run's control flow must preserve the pairing.
func (r *ManagedRemote) setClient(c *ssh.Client) {
	r.mu.Lock()
	r.client = c
	close(r.clientReady)
	r.mu.Unlock()
}

// clearClient removes the live transport and arms a fresh clientReady
// channel for the next connection attempt to close.
func (r *ManagedRemote) clearClient() {
	r.mu.Lock()
	r.client = nil
	r.clientReady = make(chan struct{})
	r.mu.Unlock()
}

// teardownConnection clears the live client pointer and then closes the
// underlying transport via closeFn, in that order. The order is the whole
// point of this being its own function rather than two inline statements: a
// WaitForClient call racing this teardown takes its fast path whenever
// r.client is still non-nil, so closing the transport first (and clearing
// the pointer only afterwards) would leave a window where a caller can be
// handed a *ssh.Client this function is already in the middle of closing.
// Clearing first closes that window — any WaitForClient racing this call
// either sees the pointer before it's cleared (a client that is about to be
// closed but is not yet) or takes the slow path and waits for the next one.
func (r *ManagedRemote) teardownConnection(closeFn func() error) {
	r.clearClient()
	_ = closeFn()
}

// onConn adjusts the active-connection count reported in status; wired as
// ServeForward's onConn callback. It also drives the forward-connection
// metrics: onConn has no context of its own (it is a plain func(int)
// callback threaded through the transport-agnostic serveListener, which
// carries no host identity to label with), so the record calls use
// context.Background() — these are fire-and-forget counters, not requests
// that need trace correlation.
func (r *ManagedRemote) onConn(delta int) {
	r.mu.Lock()
	r.activeConns += delta
	r.mu.Unlock()
	recordSSHForwardConn(context.Background(), r.cfg.Host, delta)
}

// status returns a snapshot of this remote's condition, with target filled
// in from the Manager's Deps.TargetName (a Manager-wide value, not something
// ManagedRemote otherwise needs to know).
func (r *ManagedRemote) status(target string) RemoteStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return RemoteStatus{
		Host:              r.cfg.Host,
		State:             string(r.state),
		RemoteSocket:      r.cfg.RemoteSocket,
		Target:            target,
		ConnectedSince:    r.connectedSince,
		Reconnects:        r.reconnects,
		ActiveConnections: r.activeConns,
		LastError:         r.lastError,
	}
}

// WaitForClient returns the current live SSH client, blocking up to
// ClientWaitTimeout for one to arrive if a reconnect is in progress.
// Forwarding code that needs the transport asks here rather than reading a
// client field directly, so a lookup made mid-reconnect blocks for the grace
// period instead of failing immediately.
//
// The returned client is not guaranteed to stay open after it is returned:
// there is no refcount linking a caller's use of it to serveConnected's
// teardown, so a client obtained here can be closed by the next reconnect a
// moment later. Callers must already tolerate "use of closed connection"
// from any operation against it, exactly as they would for a client obtained
// any other way — this function only removes the "no client at all yet"
// class of failure, not races with a live connection's own end of life.
func (r *ManagedRemote) WaitForClient(ctx context.Context) (*ssh.Client, error) {
	r.mu.Lock()
	if r.client != nil {
		c := r.client
		r.mu.Unlock()
		return c, nil
	}
	ready := r.clientReady
	timeout := r.clientWaitTimeout
	r.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ready:
		r.mu.Lock()
		c := r.client
		r.mu.Unlock()
		if c == nil {
			// clientReady was closed by setClient and then immediately
			// replaced by a subsequent clearClient before we re-acquired
			// the lock (a connection that dropped the instant it came up).
			// Report the timeout rather than nil: a caller mid-handover
			// should retry, not treat this as "never connects".
			return nil, fmt.Errorf("connection to %s dropped before it could be used", r.cfg.Host)
		}
		return c, nil
	case <-timer.C:
		return nil, fmt.Errorf("timed out after %s waiting for a connection to %s", timeout, r.cfg.Host)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// sleep waits for d or ctx cancellation, whichever comes first — the
// interruptible half of every backoff pause, so a stop() during a long
// reconnect delay returns immediately rather than waiting it out.
func (r *ManagedRemote) sleep(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// backoffDelay returns the next backoff delay, raised to floor when the
// failure class demands a minimum (authentication and host-key failures
// clear only via a human or Vault action, never by retrying quickly).
func (r *ManagedRemote) backoffDelay(class ErrorClass) time.Duration {
	d := r.backoff.Next()
	var floor time.Duration
	switch class {
	case ClassAuth, ClassHostKey:
		floor = AuthFailureFloor
	}
	if d < floor {
		return floor
	}
	return d
}

// stateForClass maps a failure's class to the reported State. It is the only
// mapping the state vocabulary in state.go supports: auth and host-key
// failures get their own dedicated states because a human or Vault action is
// what clears them, everything else collapses to the generic offline/
// reconnecting state its caller already picked.
func stateForClass(class ErrorClass, generic State) State {
	switch class {
	case ClassAuth:
		return StateAuthError
	case ClassHostKey:
		return StateHostKeyError
	default:
		return generic
	}
}

// fail records a connection-attempt failure, maps it to the reported state,
// and sleeps the appropriate backoff before the run loop retries.
func (r *ManagedRemote) fail(ctx context.Context, err error) {
	class := Classify(err)
	slog.Warn("sshfwd: connection attempt failed", "host", r.cfg.Host, "class", class, "error", err)
	recordSSHConnectFailure(ctx, r.cfg.Host, string(class))
	r.setState(stateForClass(class, StateOffline), err)
	r.sleep(ctx, r.backoffDelay(class))
}

// errIncompleteDeps is returned when a ManagedRemote is run with a Deps that
// is missing a required func. Production remotes are always constructed by
// Manager with a fully-populated Deps; this guards a wiring mistake (or a
// test's intentionally bare Deps{}, which several in this package's test
// suite construct without ever expecting run to be reached) so it surfaces
// as a failed connection attempt instead of a nil-func panic inside a
// background goroutine.
var errIncompleteDeps = errors.New("incomplete Deps: Signers, User, Policy, and Target must all be set")

// dialRemote, forwardRemote, keepaliveRemote, and closeRemoteClient are
// Dial, ServeForward, Keepalive, and (*ssh.Client).Close respectively,
// indirected through package-level vars — the same seam createTempFile
// (hostkey.go) uses — so run's and serveConnected's composition (the
// dial→serve→keepalive→teardown→backoff→redial cycle, and the per-attempt
// re-resolution of Signers/User/Policy) is testable end to end without a
// live SSH connection. Production code always uses the defaults below;
// tests restore them via t.Cleanup after overriding.
var (
	dialRemote        = Dial
	forwardRemote     = ServeForward
	keepaliveRemote   = Keepalive
	closeRemoteClient = func(c *ssh.Client) error { return c.Close() }
)

// run is the per-remote connection lifecycle: dial, forward, keepalive,
// reconnect with backoff — until ctx is cancelled by stop().
//
// Signers and the user are re-resolved on every attempt rather than cached
// once: a Vault-CA certificate rotated since the last attempt (or the last
// successful connection) must be picked up on the very next dial, not stay
// pinned to whatever was current when run started.
func (r *ManagedRemote) run(ctx context.Context) {
	for ctx.Err() == nil {
		r.setState(StateConnecting, nil)

		if r.deps.Signers == nil || r.deps.User == nil || r.deps.Policy == nil || r.deps.Target == nil {
			r.fail(ctx, errIncompleteDeps)
			continue
		}

		slog.Debug("sshfwd: connecting to remote", "host", r.cfg.Host)

		signers, err := r.deps.Signers()
		if err != nil {
			r.fail(ctx, err)
			continue
		}
		user, err := r.deps.User()
		if err != nil {
			r.fail(ctx, err)
			continue
		}

		client, err := dialRemote(ctx, DialConfig{
			Host:    r.cfg.Host,
			Port:    r.cfg.PortOrDefault(),
			User:    user,
			Signers: signers,
			HostKey: r.deps.Policy(r.cfg),
			Timeout: DefaultDialTimeout,
		})
		if err != nil {
			r.fail(ctx, err)
			continue
		}

		socket, err := ExpandRemotePath(ctx, sshRunner{cl: client}, r.cfg.RemoteSocket)
		if err != nil {
			_ = closeRemoteClient(client)
			r.fail(ctx, err)
			continue
		}

		r.serveConnected(ctx, client, socket)
	}
}

// armStableReset starts a goroutine that resets r.backoff once threshold has
// elapsed, unless the returned stop func is called first. Extracted from
// serveConnected so the stable-connection-resets-backoff behaviour is
// testable on its own, with a short threshold, rather than only reachable by
// waiting out the real StableConnectionThreshold (60s) inside a live
// connection.
//
// The goroutine always exits via one of its two select cases — the timer
// firing or stableCtx being cancelled — so calling stop (which cancels
// stableCtx) is both how a caller declines the reset and how it guarantees
// the goroutine does not outlive the connection that started it.
func (r *ManagedRemote) armStableReset(ctx context.Context, threshold time.Duration) (stop func()) {
	stableCtx, cancel := context.WithCancel(ctx)
	go func() {
		timer := time.NewTimer(threshold)
		defer timer.Stop()
		select {
		case <-timer.C:
			r.backoff.Reset()
		case <-stableCtx.Done():
		}
	}()
	return cancel
}

// serveConnected runs one established connection until ServeForward or
// Keepalive reports an error (or ctx is cancelled), then tears it down and
// sleeps the reconnect backoff. It returns once that backoff has elapsed (or
// ctx died), handing control back to run's loop to dial again.
func (r *ManagedRemote) serveConnected(ctx context.Context, client *ssh.Client, socket string) {
	r.setClient(client)
	now := time.Now()
	r.mu.Lock()
	r.connectedSince = &now
	r.mu.Unlock()
	r.setState(StateConnected, nil)
	recordSSHConnState(ctx, r.cfg.Host, true)
	slog.Info("sshfwd: connected to remote", "host", r.cfg.Host)

	// A connection that stays up for StableConnectionThreshold has proven
	// itself, so the backoff schedule resets — otherwise a host that flaps
	// after being healthy for hours would reconnect at whatever multiplier
	// its very first, long-ago failure left behind.
	stopStable := r.armStableReset(ctx, StableConnectionThreshold)

	// ServeForward and Keepalive share this connection's lifetime: whichever
	// fails first ends the other via connCtx. errCh is sized so both
	// goroutines can always deliver their result and exit even though only
	// the first is read; connWG additionally lets this function wait for
	// *both* to actually finish before tearing the client down, rather than
	// racing ahead the moment the first one reports — see the connWG.Wait()
	// call below for why that matters.
	connCtx, cancelConn := context.WithCancel(ctx)
	errCh := make(chan error, 2)
	var connWG sync.WaitGroup
	connWG.Add(2)
	go func() {
		defer connWG.Done()
		errCh <- forwardRemote(connCtx, client, socket, r.deps.Target, r.onConn)
	}()
	go func() {
		defer connWG.Done()
		kerr := keepaliveRemote(connCtx, client, keepaliveInterval, keepaliveStrikes)
		// connCtx.Err() != nil means this returned because ServeForward failed
		// first (or the outer ctx was cancelled) and cancelConn() tore down the
		// keepalive loop out from under it — an ordinary shutdown, not a
		// keepalive failure, so only a genuine strike-threshold error (returned
		// while connCtx is still live) counts here.
		if kerr != nil && connCtx.Err() == nil {
			recordSSHKeepaliveFailure(ctx, r.cfg.Host)
		}
		errCh <- kerr
	}()

	err := <-errCh
	cancelConn()
	stopStable()

	// Wait for the loser of the race, too: stop()/Manager.Close() promise to
	// wait for a remote's work to finish, and returning after only the first
	// errCh value would let ServeForward's in-flight relays (or a pending
	// Keepalive round-trip) keep running after this function has already
	// moved on to redial. It also means activeConns has already been
	// decremented back to zero by ServeForward's own accept-loop teardown by
	// the time the next connection starts, so it can't be seen to undercount
	// or go transiently negative from a straggling connection's onConn(-1).
	connWG.Wait()

	r.teardownConnection(func() error { return closeRemoteClient(client) })

	r.mu.Lock()
	r.connectedSince = nil
	r.mu.Unlock()
	recordSSHConnState(ctx, r.cfg.Host, false)

	if ctx.Err() != nil {
		// Shutdown, not a failure: run's loop condition will exit next, and
		// this teardown was requested, not a reconnect the operator needs to
		// see counted.
		return
	}

	r.mu.Lock()
	r.reconnects++
	r.mu.Unlock()
	recordSSHReconnect(ctx, r.cfg.Host)

	class := Classify(err)
	slog.Warn("sshfwd: remote connection lost; reconnecting", "host", r.cfg.Host, "class", class, "error", err)
	r.setState(stateForClass(class, StateReconnecting), err)
	r.sleep(ctx, r.backoffDelay(class))
}
