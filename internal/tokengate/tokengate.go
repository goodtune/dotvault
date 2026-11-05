// Package tokengate holds the two seams between the daemon's token lifecycle
// and the subsystems that present its Vault token on their own initiative:
// the SSH agent's backend and the client certificate source.
//
// A Gate is the read side: a consumer about to present the token asks whether
// it is safe to, and waits briefly while it is being replaced. A Reporter is
// the write side: a consumer that sees Vault reject the token before the
// lifecycle manager's own poll does says so, so recovery starts now.
// *auth.LifecycleManager satisfies Gate, Signaller and Reporter.
//
// It is a leaf on purpose. The lifecycle manager lives in internal/auth and
// the consumers must not import it (or each other) for an interface, a
// holder and a poll loop, so the shapes live here, once.
package tokengate

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// Gate reports whether the shared Vault client's token is unsafe to use right
// now: true while a re-auth is signalled and also across a replacement in
// flight, whether or not the replacement succeeds.
type Gate interface {
	NeedsReauth() bool
}

// Signaller is the narrower question a Gate may also answer: whether the
// lifecycle manager has given up replacing the token on its own and needs one
// from outside (a login, a borrow). It excludes a replacement in flight, so a
// Gate that reports NeedsReauth but not ReauthSignalled is mid-replacement.
type Signaller interface {
	ReauthSignalled() bool
}

// Reporter is told about a Vault error a consumer saw while presenting the
// token. The lifecycle manager's NotifyRejected classifies and rate-limits
// what it is told.
type Reporter interface {
	NotifyRejected(err error)
}

// PollInterval is how often a waiting consumer re-reads the gate.
const PollInterval = 100 * time.Millisecond

// ErrSignalled is returned by WaitForReplacement when the re-auth is one a
// human (or a peer) has to resolve, so there is nothing worth waiting for.
var ErrSignalled = errors.New("tokengate: the Vault token needs replacing from outside (re-auth signalled)")

// Wait blocks while g reports NeedsReauth, returning nil once it clears and
// ctx.Err() if ctx ends first. A nil g returns nil at once. It does not
// distinguish a signalled re-auth from a replacement in flight.
func Wait(ctx context.Context, g Gate) error {
	return wait(ctx, g, false)
}

// WaitForReplacement is Wait that waits only for a replacement in flight.
// When g also implements Signaller and reports a signalled re-auth, at the
// start or while waiting, it returns ErrSignalled at once instead of waiting
// for something that will not finish on its own. A g that does not implement
// Signaller is waited on exactly as Wait would.
func WaitForReplacement(ctx context.Context, g Gate) error {
	return wait(ctx, g, true)
}

func wait(ctx context.Context, g Gate, stopOnSignal bool) error {
	if g == nil {
		return nil
	}
	var s Signaller
	if stopOnSignal {
		s, _ = g.(Signaller)
	}
	signalled := func() bool { return s != nil && s.ReauthSignalled() }
	if !g.NeedsReauth() {
		return nil
	}
	if signalled() {
		return ErrSignalled
	}
	ticker := time.NewTicker(PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if !g.NeedsReauth() {
				return nil
			}
			if signalled() {
				return ErrSignalled
			}
		}
	}
}

// GateSlot holds a Gate set after construction, safely against concurrent
// readers: a consumer is built before the lifecycle manager and wired once it
// exists, by which time it may already be serving. The zero value holds no
// gate. Setting nil is a no-op; a gate cannot be un-wired.
type GateSlot struct{ v atomic.Value }

// gateBox keeps the atomic.Value's stored type stable whichever Gate
// implementation is set; atomic.Value panics on a change of concrete type.
type gateBox struct{ g Gate }

// Set stores g unless it is nil.
func (s *GateSlot) Set(g Gate) {
	if g != nil {
		s.v.Store(gateBox{g: g})
	}
}

// Get returns the stored gate, or nil.
func (s *GateSlot) Get() Gate {
	b, _ := s.v.Load().(gateBox)
	return b.g
}

// ReporterSlot is GateSlot for a Reporter.
type ReporterSlot struct{ v atomic.Value }

type reporterBox struct{ r Reporter }

// Set stores r unless it is nil.
func (s *ReporterSlot) Set(r Reporter) {
	if r != nil {
		s.v.Store(reporterBox{r: r})
	}
}

// Get returns the stored reporter, or nil.
func (s *ReporterSlot) Get() Reporter {
	b, _ := s.v.Load().(reporterBox)
	return b.r
}

// Report passes err to the stored reporter, and does nothing without one.
func (s *ReporterSlot) Report(err error) {
	if r := s.Get(); r != nil {
		r.NotifyRejected(err)
	}
}
