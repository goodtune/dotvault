package tokengate

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type gate struct{ needs, signalled atomic.Bool }

func (g *gate) NeedsReauth() bool     { return g.needs.Load() }
func (g *gate) ReauthSignalled() bool { return g.signalled.Load() }

// plainGate implements Gate alone, as the agent's test stubs do.
type plainGate struct{ needs atomic.Bool }

func (g *plainGate) NeedsReauth() bool { return g.needs.Load() }

func TestWaitWithoutGateReturnsAtOnce(t *testing.T) {
	if err := Wait(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := WaitForReplacement(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestWaitReturnsWhenTheGateClears(t *testing.T) {
	g := &plainGate{}
	g.needs.Store(true)
	time.AfterFunc(250*time.Millisecond, func() { g.needs.Store(false) })
	start := time.Now()
	if err := Wait(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 200*time.Millisecond {
		t.Fatal("returned before the gate cleared")
	}
}

func TestWaitIsBoundedByTheContext(t *testing.T) {
	g := &plainGate{}
	g.needs.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := Wait(ctx, g); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
}

// Wait waits out a signalled re-auth too: it is the agent's semantics, which
// must not change.
func TestWaitIgnoresTheSignal(t *testing.T) {
	g := &gate{}
	g.needs.Store(true)
	g.signalled.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := Wait(ctx, g); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want a wait to the deadline", err)
	}
}

func TestWaitForReplacementFailsFastWhenSignalled(t *testing.T) {
	g := &gate{}
	g.needs.Store(true)
	g.signalled.Store(true)
	start := time.Now()
	if err := WaitForReplacement(context.Background(), g); !errors.Is(err, ErrSignalled) {
		t.Fatalf("err = %v, want ErrSignalled", err)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("did not fail fast")
	}
}

func TestWaitForReplacementStopsWhenTheReplacementGivesUp(t *testing.T) {
	g := &gate{}
	g.needs.Store(true)
	time.AfterFunc(200*time.Millisecond, func() { g.signalled.Store(true) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := WaitForReplacement(ctx, g); !errors.Is(err, ErrSignalled) {
		t.Fatalf("err = %v, want ErrSignalled once the replacement failed", err)
	}
}

func TestWaitForReplacementWaitsForAReplacementInFlight(t *testing.T) {
	g := &gate{}
	g.needs.Store(true)
	time.AfterFunc(200*time.Millisecond, func() { g.needs.Store(false) })
	if err := WaitForReplacement(context.Background(), g); err != nil {
		t.Fatal(err)
	}
}

// A gate that cannot report the signal is waited on as Wait would.
func TestWaitForReplacementWithAPlainGate(t *testing.T) {
	g := &plainGate{}
	g.needs.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := WaitForReplacement(ctx, g); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
}

type reporter struct {
	mu   sync.Mutex
	errs []error
}

func (r *reporter) NotifyRejected(err error) { r.mu.Lock(); r.errs = append(r.errs, err); r.mu.Unlock() }

func TestSlots(t *testing.T) {
	var gs GateSlot
	if gs.Get() != nil {
		t.Fatal("empty GateSlot is not nil")
	}
	gs.Set(nil)
	if gs.Get() != nil {
		t.Fatal("Set(nil) stored something")
	}
	g1, g2 := &plainGate{}, &gate{}
	gs.Set(g1)
	gs.Set(g2) // a different concrete type must not panic
	if gs.Get() != g2 {
		t.Fatal("GateSlot did not keep the latest gate")
	}

	var rs ReporterSlot
	rs.Report(errors.New("nobody listening")) // no reporter: a no-op
	r := &reporter{}
	rs.Set(r)
	rs.Report(errors.New("x"))
	if len(r.errs) != 1 {
		t.Fatalf("reported %d, want 1", len(r.errs))
	}
}

func TestSlotsAreSafeForConcurrentUse(t *testing.T) {
	var gs GateSlot
	var rs ReporterSlot
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(2)
		go func() { defer wg.Done(); gs.Set(&plainGate{}); rs.Set(&reporter{}) }()
		go func() { defer wg.Done(); _ = gs.Get(); rs.Report(errors.New("x")) }()
	}
	wg.Wait()
}
