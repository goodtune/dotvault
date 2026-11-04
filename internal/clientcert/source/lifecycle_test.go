package source

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/goodtune/dotvault/internal/clientcert"
	"github.com/goodtune/dotvault/internal/tokengate"
)

// stubGate is a tokengate.Gate (and Signaller) a test opens and closes.
// engaged is NeedsReauth; signalled is ReauthSignalled, the lifecycle
// manager having given up and needing a token from outside.
type stubGate struct{ engaged, signalled atomic.Bool }

func (g *stubGate) NeedsReauth() bool     { return g.engaged.Load() || g.signalled.Load() }
func (g *stubGate) ReauthSignalled() bool { return g.signalled.Load() }

// recordingReporter is a RejectionReporter that keeps what it was told.
type recordingReporter struct {
	mu   sync.Mutex
	errs []error
}

func (r *recordingReporter) NotifyRejected(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, err)
}

func (r *recordingReporter) reported() []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]error(nil), r.errs...)
}

func wire(t *testing.T, src clientcert.Source, g tokengate.Gate, r tokengate.Reporter) {
	t.Helper()
	w, ok := src.(LifecycleWirer)
	if !ok {
		t.Fatalf("%T does not accept the lifecycle seams", src)
	}
	if g != nil {
		w.SetReauthGate(g)
	}
	if r != nil {
		w.SetReauthReporter(r)
	}
}

// A sign that would start while the token is being replaced waits for the
// replacement, then signs with the token the client holds afterwards: the
// token read before the wait is the one being replaced.
func TestEphemeralWaitsOutTokenReplacement(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	src := newSource(t, f, defaultOptions(clock))
	g := &stubGate{}
	g.engaged.Store(true)
	wire(t, src, g, nil)

	type result struct {
		p   *clientcert.Pair
		err error
	}
	done := make(chan result, 1)
	go func() {
		p, err := src.Current(context.Background())
		done <- result{p, err}
	}()

	time.Sleep(300 * time.Millisecond)
	if n := f.signs.Load() + f.lookups.Load(); n != 0 {
		t.Fatalf("Vault called %d times while the token was being replaced", n)
	}
	f.setToken("s.replacement")
	g.engaged.Store(false)

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Current after the replacement: %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Current did not proceed once the replacement cleared")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.signTokens) != 1 || f.signTokens[0] != "s.replacement" {
		t.Fatalf("signed with %q, want the replacement token", f.signTokens)
	}
	// The common name is looked up with the same token the sign presents.
	if len(f.lookupTokens) != 1 || f.lookupTokens[0] != "s.replacement" {
		t.Fatalf("looked up the common name with %q, want the replacement token", f.lookupTokens)
	}
}

// Current can read a candidate token the lifecycle manager is still judging
// and find the gate already clear by the time the sign starts. The sign must
// present what the client holds once the gate is clear, not the candidate:
// a rejected candidate is replaced before the gate opens.
func TestEphemeralRereadsTheTokenOnceTheGateIsClear(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.setToken("s.candidate")
	src := newSource(t, f, defaultOptions(clock))
	wire(t, src, &stubGate{}, nil)
	f.mu.Lock()
	f.afterToken = func() { f.setToken("s.settled") }
	f.mu.Unlock()

	if _, err := src.Current(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.signTokens) != 1 || f.signTokens[0] != "s.settled" {
		t.Fatalf("signed with %q, want the token held once the gate was clear", f.signTokens)
	}
	if len(f.lookupTokens) != 1 || f.lookupTokens[0] != "s.settled" {
		t.Fatalf("looked up with %q, want the token held once the gate was clear", f.lookupTokens)
	}
}

// Without a gate (the client facade) there is no lifecycle to defer to, and
// the sign keeps the token Current read.
func TestEphemeralWithoutGateKeepsTheTokenCurrentRead(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.setToken("s.read")
	src := newSource(t, f, defaultOptions(clock))
	f.mu.Lock()
	f.afterToken = func() { f.setToken("s.later") }
	f.mu.Unlock()

	if _, err := src.Current(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.signTokens) != 1 || f.signTokens[0] != "s.read" {
		t.Fatalf("signed with %q, want the token Current read", f.signTokens)
	}
}

// A replacement that never clears is bounded, and its failure is transient:
// ErrReauthInProgress, not a denial, and no Vault call was made.
func TestEphemeralReplacementThatNeverClearsIsBounded(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	src := newSource(t, f, defaultOptions(clock))
	src.(*ephemeral).reauthWait = 200 * time.Millisecond
	g := &stubGate{}
	g.engaged.Store(true)
	rep := &recordingReporter{}
	wire(t, src, g, rep)

	start := time.Now()
	_, err := src.Current(context.Background())
	if !errors.Is(err, clientcert.ErrReauthInProgress) {
		t.Fatalf("err = %v, want ErrReauthInProgress", err)
	}
	var re *vaultapi.ResponseError
	if errors.As(err, &re) {
		t.Fatalf("err = %v carries a Vault response; want a transient error", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("Current took %s, want it bounded by the wait", took)
	}
	if n := f.signs.Load() + f.lookups.Load(); n != 0 {
		t.Fatalf("Vault called %d times", n)
	}
	if got := rep.reported(); len(got) != 0 {
		t.Fatalf("reported %v; a wait that timed out is not a rejection", got)
	}
}

// The wait never exceeds the sign's own detached timeout.
func TestEphemeralReauthWaitDefaultsToSignTimeout(t *testing.T) {
	clock := newTestClock()
	src := newSource(t, newFakeSigner(t, clock), defaultOptions(clock))
	if got := src.(*ephemeral).reauthWait; got <= 0 || got > signTimeout {
		t.Fatalf("reauthWait = %s, want positive and at most signTimeout (%s)", got, signTimeout)
	}
}

// A cached certificate still inside its refresh window is served without
// waiting: it needs no Vault call, so a replacement cannot affect it.
func TestEphemeralFreshCacheDoesNotWaitOnReplacement(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	src := newSource(t, f, defaultOptions(clock))
	if _, err := src.Current(context.Background()); err != nil {
		t.Fatal(err)
	}
	g := &stubGate{}
	g.engaged.Store(true)
	wire(t, src, g, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := src.Current(ctx); err != nil {
		t.Fatalf("cached Current during a replacement: %v", err)
	}
}

func TestEphemeralReportsSignRejection(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.setSignErr(forbidden())
	src := newSource(t, f, defaultOptions(clock))
	rep := &recordingReporter{}
	wire(t, src, nil, rep)

	if _, err := src.Current(context.Background()); err == nil {
		t.Fatal("expected the sign to fail")
	}
	got := rep.reported()
	if len(got) != 1 {
		t.Fatalf("reported %d times, want once", len(got))
	}
	var re *vaultapi.ResponseError
	if !errors.As(got[0], &re) || re.StatusCode != 403 {
		t.Fatalf("reported %v, want the 403", got[0])
	}
}

func TestEphemeralReportsLookupRejection(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.lookupErr = forbidden()
	src := newSource(t, f, defaultOptions(clock))
	rep := &recordingReporter{}
	wire(t, src, nil, rep)

	if _, err := src.Current(context.Background()); err == nil {
		t.Fatal("expected the lookup to fail")
	}
	if got := rep.reported(); len(got) != 1 {
		t.Fatalf("reported %d times, want once", len(got))
	}
	if f.signs.Load() != 0 {
		t.Fatal("signed after the lookup was rejected")
	}
}

func TestEphemeralDoesNotReportOtherFailures(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.setSignErr(&vaultapi.ResponseError{StatusCode: 500, Errors: []string{"internal error"}})
	src := newSource(t, f, defaultOptions(clock))
	rep := &recordingReporter{}
	wire(t, src, nil, rep)

	if _, err := src.Current(context.Background()); err == nil {
		t.Fatal("expected the sign to fail")
	}
	if got := rep.reported(); len(got) != 0 {
		t.Fatalf("reported %v; a 500 is not a token rejection", got)
	}
}

// The fallback source forwards the seams to the ephemeral source it holds.
func TestFallbackAcceptsLifecycleSeams(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.setSignErr(forbidden())
	o := defaultOptions(clock)
	src, err := NewFromParams(Params{Enabled: true, Held: true, Method: "mtls", StorageDir: t.TempDir(), Ephemeral: o}, f)
	if err != nil {
		t.Fatal(err)
	}
	rep := &recordingReporter{}
	wire(t, src, &stubGate{}, rep)
	if _, err := src.Current(context.Background()); err == nil {
		t.Fatal("expected the fallback sign to fail")
	}
	if got := rep.reported(); len(got) != 1 {
		t.Fatalf("reported %d times through the fallback, want once", len(got))
	}
}

// A signalled re-auth needs a login or a borrow, not a replacement that will
// finish on its own: the sign fails at once with ErrNoToken rather than
// waiting out reauthWait for ErrReauthInProgress.
func TestEphemeralSignalledReauthFailsFast(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	src := newSource(t, f, defaultOptions(clock))
	g := &stubGate{}
	g.signalled.Store(true)
	wire(t, src, g, nil)

	start := time.Now()
	_, err := src.Current(context.Background())
	if !errors.Is(err, clientcert.ErrNoToken) {
		t.Fatalf("err = %v, want ErrNoToken", err)
	}
	if errors.Is(err, clientcert.ErrReauthInProgress) {
		t.Fatalf("err = %v, a signalled re-auth is not a replacement in progress", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("took %s, want an immediate answer", took)
	}
	if n := f.signs.Load() + f.lookups.Load(); n != 0 {
		t.Fatalf("Vault called %d times", n)
	}
}

// A replacement that gives up while the sign waits for it ends the wait at
// once, with the same answer.
func TestEphemeralReplacementThatGivesUpEndsTheWait(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	src := newSource(t, f, defaultOptions(clock))
	g := &stubGate{}
	g.engaged.Store(true)
	wire(t, src, g, nil)
	time.AfterFunc(200*time.Millisecond, func() { g.engaged.Store(false); g.signalled.Store(true) })

	start := time.Now()
	_, err := src.Current(context.Background())
	if !errors.Is(err, clientcert.ErrNoToken) {
		t.Fatalf("err = %v, want ErrNoToken", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("took %s, want the wait to end when the replacement gave up", took)
	}
}
