package web

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// errLauncherBusy is returned by guardedLaunch when the single-flight gate is
// already held by an in-flight launch.
var errLauncherBusy = errors.New("launcher busy")

// guardedLaunch runs fn — a call into an external launcher (a browser opener,
// a desktop-notification daemon) that can block or panic — under three
// protections shared by every remote peer-action endpoint:
//
//   - a single-flight gate, so a launcher that hangs cannot accumulate one
//     stuck goroutine per request (the bounded wait abandons a hung launcher
//     but cannot kill it);
//   - a bounded wait, so a hung launcher never strands the HTTP handler;
//   - panic recovery, because an unrecovered panic in the spawned goroutine
//     would take down the whole daemon — net/http's recovery only covers the
//     handler goroutine.
//
// Results: (false, errLauncherBusy) when the gate is held; (false, err) when
// fn returned or panicked; (true, nil) on timeout, where fn is abandoned but
// still running (the gate is released by fn's own goroutine when it finally
// returns, so a later request can proceed).
func guardedLaunch(gate *sync.Mutex, timeout time.Duration, fn func() error) (timedOut bool, err error) {
	if !gate.TryLock() {
		return false, errLauncherBusy
	}
	errCh := make(chan error, 1)
	go func() {
		var e error
		// LIFO defers: recover the panic into an error first, then release
		// the gate, then send the result — so by the time the caller sees
		// the outcome a follow-up request can already acquire the gate.
		defer func() { errCh <- e }()
		defer gate.Unlock()
		defer func() {
			if rcv := recover(); rcv != nil {
				e = fmt.Errorf("launcher panicked: %v", rcv)
			}
		}()
		e = fn()
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case e := <-errCh:
		return false, e
	case <-timer.C:
		return true, nil
	}
}
