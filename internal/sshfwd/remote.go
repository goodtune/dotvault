package sshfwd

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
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
// cfg is compared with == by Manager.Reconcile to detect a changed entry, so
// every field must stay a comparable type (see Remote).
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

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// newManagedRemote returns a ManagedRemote for r, not yet started.
func newManagedRemote(r Remote, deps Deps) *ManagedRemote {
	return &ManagedRemote{
		cfg:         r,
		deps:        deps,
		backoff:     NewBackoff(),
		clientReady: make(chan struct{}),
	}
}

// start runs body in a tracked goroutine under a context derived from ctx,
// so stop() can cancel and wait for it deterministically. body is a
// parameter (rather than always r.run) so Manager can substitute a stub for
// testing without an SSH server.
//
// start does not return until the goroutine has actually begun executing —
// spawning it with a bare `go` and returning immediately would let Reconcile
// hand control back to the caller (or the next iteration of its own loop)
// before the new goroutine ever got a turn from the scheduler, which is
// observable as a flaky "not started yet" from a caller (or a test) that
// checks state right after Reconcile returns with no synchronization of its
// own.
func (r *ManagedRemote) start(ctx context.Context, body func(context.Context)) {
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	running := make(chan struct{})
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		close(running)
		body(runCtx)
	}()
	<-running
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

// onConn adjusts the active-connection count reported in status; wired as
// ServeForward's onConn callback.
func (r *ManagedRemote) onConn(delta int) {
	r.mu.Lock()
	r.activeConns += delta
	r.mu.Unlock()
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
// client field directly, so it never observes — let alone mutates — a
// client mid-teardown: run() owns the client's lifetime end to end.
func (r *ManagedRemote) WaitForClient(ctx context.Context) (*ssh.Client, error) {
	r.mu.Lock()
	if r.client != nil {
		c := r.client
		r.mu.Unlock()
		return c, nil
	}
	ready := r.clientReady
	r.mu.Unlock()

	timer := time.NewTimer(ClientWaitTimeout)
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
		return nil, fmt.Errorf("timed out after %s waiting for a connection to %s", ClientWaitTimeout, r.cfg.Host)
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

// fail records a connection-attempt failure, maps it to the reported state,
// and sleeps the appropriate backoff before the run loop retries.
func (r *ManagedRemote) fail(ctx context.Context, err error) {
	class := Classify(err)
	state := StateOffline
	switch class {
	case ClassAuth:
		state = StateAuthError
	case ClassHostKey:
		state = StateHostKeyError
	}
	r.setState(state, err)
	r.sleep(ctx, r.backoffDelay(class))
}

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

		client, err := Dial(ctx, DialConfig{
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
			client.Close()
			r.fail(ctx, err)
			continue
		}

		r.serveConnected(ctx, client, socket)
	}
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

	// A connection that stays up for StableConnectionThreshold has proven
	// itself, so the backoff schedule resets — otherwise a host that flaps
	// after being healthy for hours would reconnect at whatever multiplier
	// its very first, long-ago failure left behind.
	stableCtx, stopStable := context.WithCancel(ctx)
	go func() {
		timer := time.NewTimer(StableConnectionThreshold)
		defer timer.Stop()
		select {
		case <-timer.C:
			r.backoff.Reset()
		case <-stableCtx.Done():
		}
	}()

	// ServeForward and Keepalive share this connection's lifetime: whichever
	// fails first ends the other via connCtx, and errCh is sized so both
	// goroutines can always deliver their result and exit even though only
	// the first is read.
	connCtx, cancelConn := context.WithCancel(ctx)
	errCh := make(chan error, 2)
	go func() { errCh <- ServeForward(connCtx, client, socket, r.deps.Target, r.onConn) }()
	go func() { errCh <- Keepalive(connCtx, client, keepaliveInterval, keepaliveStrikes) }()

	err := <-errCh
	cancelConn()
	stopStable()
	client.Close()
	r.clearClient()

	r.mu.Lock()
	r.connectedSince = nil
	r.reconnects++
	r.mu.Unlock()

	if ctx.Err() != nil {
		// Shutdown, not a failure: run's loop condition will exit next.
		return
	}

	class := Classify(err)
	state := StateReconnecting
	switch class {
	case ClassAuth:
		state = StateAuthError
	case ClassHostKey:
		state = StateHostKeyError
	}
	r.setState(state, err)
	r.sleep(ctx, r.backoffDelay(class))
}
