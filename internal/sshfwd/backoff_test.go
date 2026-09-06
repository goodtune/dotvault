package sshfwd

import (
	"sync"
	"testing"
	"time"
)

func TestBackoffSequenceWithoutJitter(t *testing.T) {
	b := NewBackoff()
	b.rnd = func() float64 { return 0.5 } // midpoint => no adjustment

	want := []time.Duration{
		500 * time.Millisecond,
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		30 * time.Second,
		30 * time.Second,
		30 * time.Second,
	}
	for i, w := range want {
		if got := b.Next(); got != w {
			t.Errorf("Next() #%d = %v, want %v", i, got, w)
		}
	}
}

func TestBackoffJitterStaysWithinTwentyPercent(t *testing.T) {
	for _, r := range []float64{0, 0.25, 0.5, 0.75, 1} {
		b := NewBackoff()
		b.rnd = func() float64 { return r }
		got := b.Next()
		lo := time.Duration(float64(500*time.Millisecond) * 0.8)
		hi := time.Duration(float64(500*time.Millisecond) * 1.2)
		if got < lo || got > hi {
			t.Errorf("rnd=%v: Next() = %v, want within [%v, %v]", r, got, lo, hi)
		}
	}

	// Direction: rnd=1 must produce a strictly greater delay than rnd=0.
	// Catches reversed sign in the jitter formula.
	b0 := NewBackoff()
	b0.rnd = func() float64 { return 0 }
	d0 := b0.Next()

	b1 := NewBackoff()
	b1.rnd = func() float64 { return 1 }
	d1 := b1.Next()

	if d1 <= d0 {
		t.Errorf("jitter direction broken: rnd=1 (%v) must exceed rnd=0 (%v)", d1, d0)
	}

	// Magnitude: the edge values must be close to the expected bounds,
	// not just inside them. Catches under-sized Jitter constant.
	expectedMin := time.Duration(float64(500*time.Millisecond) * 0.8) // rnd=0 → 400ms
	expectedMax := time.Duration(float64(500*time.Millisecond) * 1.2) // rnd=1 → 600ms
	tolerance := 5 * time.Millisecond

	if d0 < expectedMin-tolerance || d0 > expectedMin+tolerance {
		t.Errorf("rnd=0: Next() = %v, want close to %v (±%v)", d0, expectedMin, tolerance)
	}
	if d1 < expectedMax-tolerance || d1 > expectedMax+tolerance {
		t.Errorf("rnd=1: Next() = %v, want close to %v (±%v)", d1, expectedMax, tolerance)
	}
}

func TestBackoffResetReturnsToBase(t *testing.T) {
	b := NewBackoff()
	b.rnd = func() float64 { return 0.5 }
	for i := 0; i < 5; i++ {
		b.Next()
	}
	b.Reset()
	if got := b.Next(); got != 500*time.Millisecond {
		t.Errorf("after Reset(), Next() = %v, want 500ms", got)
	}
}

// TestBackoffConcurrentNextAndReset is the regression test for the C2 data
// race: ManagedRemote's run loop calls Next() from its own goroutine while a
// separate stable-connection timer goroutine calls Reset(), with no
// synchronisation of their own — Backoff itself must provide it. Run under
// `go test -race`; without Backoff's internal mutex this reliably reports a
// race on the shared n field.
func TestBackoffConcurrentNextAndReset(t *testing.T) {
	b := NewBackoff()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				b.Next()
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				b.Reset()
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestBackoffNeverExceedsMax(t *testing.T) {
	b := NewBackoff()
	b.rnd = func() float64 { return 1 } // maximum positive jitter
	for i := 0; i < 50; i++ {
		if got := b.Next(); got > time.Duration(float64(b.Max)*1.2) {
			t.Fatalf("Next() #%d = %v, exceeds Max+jitter", i, got)
		}
	}
}
