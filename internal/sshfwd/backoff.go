package sshfwd

import (
	"math/rand/v2"
	"time"
)

// StableConnectionThreshold is how long a connection must stay up before its
// backoff resets. Without it a host that accepts a connection and drops it
// immediately would reconnect at the base delay forever.
const StableConnectionThreshold = 60 * time.Second

// AuthFailureFloor is the minimum delay after an authentication or host-key
// failure. Those conditions are cleared by a human (re-pinning a key) or by
// Vault (reissuing a certificate), never by retrying quickly — so retrying at
// the base delay would be pure noise against a wedged remote. They still
// retry, because both genuinely do self-heal.
const AuthFailureFloor = 5 * time.Minute

// Backoff produces the jittered exponential reconnect delay.
type Backoff struct {
	Base   time.Duration
	Max    time.Duration
	Jitter float64

	// rnd returns a value in [0,1). Injected so tests are deterministic.
	rnd func() float64

	n int
}

// NewBackoff returns the reconnect schedule: 500ms doubling to a 30s ceiling,
// each delay jittered by ±20% so a fleet of daemons that lost a shared network
// does not reconnect in lockstep.
func NewBackoff() *Backoff {
	return &Backoff{
		Base:   500 * time.Millisecond,
		Max:    30 * time.Second,
		Jitter: 0.2,
		rnd:    rand.Float64,
	}
}

// Next returns the next delay and advances the schedule.
func (b *Backoff) Next() time.Duration {
	d := b.Base
	for i := 0; i < b.n; i++ {
		d *= 2
		if d >= b.Max {
			d = b.Max
			break
		}
	}
	b.n++

	// rnd in [0,1) maps to a multiplier in [1-Jitter, 1+Jitter).
	factor := 1 + b.Jitter*(2*b.rnd()-1)
	return time.Duration(float64(d) * factor)
}

// Reset returns the schedule to its base delay, called once a connection has
// stayed up for StableConnectionThreshold.
func (b *Backoff) Reset() { b.n = 0 }
