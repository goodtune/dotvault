package sshfwd

import (
	"context"
	"sync"
	"testing"
	"time"
)

// stubDeps builds a Manager whose remotes never actually dial. runFn records
// which hosts were started and blocks until its context is cancelled, so a
// stopped remote is observable.
func stubManager(t *testing.T) (*Manager, *runRecorder) {
	t.Helper()
	rec := &runRecorder{started: map[string]int{}, stopped: map[string]int{}}
	m := NewManager(Deps{})
	m.newRunner = rec.runner
	t.Cleanup(m.Close)
	return m, rec
}

type runRecorder struct {
	mu      sync.Mutex
	started map[string]int
	stopped map[string]int
}

func (r *runRecorder) runner(host string) func(context.Context) {
	return func(ctx context.Context) {
		r.mu.Lock()
		r.started[host]++
		r.mu.Unlock()

		<-ctx.Done()

		r.mu.Lock()
		r.stopped[host]++
		r.mu.Unlock()
	}
}

func (r *runRecorder) counts(host string) (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.started[host], r.stopped[host]
}

func (r *runRecorder) waitStopped(t *testing.T, host string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, stopped := r.counts(host); stopped >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, stopped := r.counts(host)
	t.Fatalf("host %s stopped %d times, want %d", host, stopped, want)
}

// waitStarted mirrors waitStopped. It exists because ManagedRemote.start
// launches its goroutine with a bare `go` and returns immediately — there is
// no guarantee the goroutine has run its first statement by the time
// Reconcile returns, so a test asserting "started" counts must poll for them
// rather than read them synchronously right after Reconcile.
func (r *runRecorder) waitStarted(t *testing.T, host string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if started, _ := r.counts(host); started >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	started, _ := r.counts(host)
	t.Fatalf("host %s started %d times, want %d", host, started, want)
}

func remote(host string) Remote {
	return Remote{Host: host, RemoteSocket: DefaultRemoteSocket}
}

func TestReconcileStartsNewRemotes(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	if err := m.Reconcile(ctx, []Remote{remote("foo.example.com")}); err != nil {
		t.Fatalf("Reconcile() = %v", err)
	}
	rec.waitStarted(t, "foo.example.com", 1)
}

func TestReconcileKeepsUnchangedRemotes(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	r := []Remote{remote("foo.example.com")}
	if err := m.Reconcile(ctx, r); err != nil {
		t.Fatal(err)
	}
	rec.waitStarted(t, "foo.example.com", 1)

	if err := m.Reconcile(ctx, r); err != nil {
		t.Fatal(err)
	}
	started, stopped := rec.counts("foo.example.com")
	if started != 1 || stopped != 0 {
		t.Errorf("unchanged remote restarted: started=%d stopped=%d, want 1/0", started, stopped)
	}
}

// TestReconcileKeepsUnchangedRemoteAcrossSeparateLoads is the regression test
// for the Enabled *bool identity bug: two Remote values built from separate
// local variables (standing in for two separate sshfwd.Load calls, which
// re-decode YAML and so never share a pointer for the same boolean) must
// still compare as unchanged. A naive Remote{} == Remote{} comparison would
// see two different *bool addresses and restart the connection on every
// reconcile — the exact failure this feature exists to avoid.
func TestReconcileKeepsUnchangedRemoteAcrossSeparateLoads(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	on1 := true
	first := remote("foo.example.com")
	first.Enabled = &on1
	if err := m.Reconcile(ctx, []Remote{first}); err != nil {
		t.Fatal(err)
	}
	rec.waitStarted(t, "foo.example.com", 1)

	on2 := true // a distinct *bool, same as a fresh Load would produce
	second := remote("foo.example.com")
	second.Enabled = &on2
	if err := m.Reconcile(ctx, []Remote{second}); err != nil {
		t.Fatal(err)
	}

	// Give a wrongly-restarting implementation a chance to actually restart
	// before asserting it didn't: waitStarted only proves "at least once",
	// waitStopped only proves the stop it wants, so an unwanted extra
	// restart needs a brief real wait to surface here.
	time.Sleep(100 * time.Millisecond)
	started, stopped := rec.counts("foo.example.com")
	if started != 1 || stopped != 0 {
		t.Errorf("remote built from a distinct *bool pointer was restarted: started=%d stopped=%d, want 1/0", started, stopped)
	}
}

func TestReconcileAddsWithoutDisturbingExisting(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	if err := m.Reconcile(ctx, []Remote{remote("foo.example.com")}); err != nil {
		t.Fatal(err)
	}
	rec.waitStarted(t, "foo.example.com", 1)

	if err := m.Reconcile(ctx, []Remote{remote("foo.example.com"), remote("bar.example.com")}); err != nil {
		t.Fatal(err)
	}
	rec.waitStarted(t, "bar.example.com", 1)

	if started, stopped := rec.counts("foo.example.com"); started != 1 || stopped != 0 {
		t.Errorf("foo disturbed by adding bar: started=%d stopped=%d", started, stopped)
	}
}

func TestReconcileStopsRemovedRemotes(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	if err := m.Reconcile(ctx, []Remote{remote("foo.example.com"), remote("bar.example.com")}); err != nil {
		t.Fatal(err)
	}
	if err := m.Reconcile(ctx, []Remote{remote("bar.example.com")}); err != nil {
		t.Fatal(err)
	}
	rec.waitStopped(t, "foo.example.com", 1)
	if _, stopped := rec.counts("bar.example.com"); stopped != 0 {
		t.Errorf("bar stopped %d times, want 0", stopped)
	}
}

func TestReconcileRestartsModifiedRemote(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	if err := m.Reconcile(ctx, []Remote{remote("foo.example.com")}); err != nil {
		t.Fatal(err)
	}
	rec.waitStarted(t, "foo.example.com", 1)

	changed := remote("foo.example.com")
	changed.Port = 2222
	if err := m.Reconcile(ctx, []Remote{changed}); err != nil {
		t.Fatal(err)
	}
	rec.waitStopped(t, "foo.example.com", 1)
	rec.waitStarted(t, "foo.example.com", 2)
}

func TestReconcileTreatsDisabledAsRemoved(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	if err := m.Reconcile(ctx, []Remote{remote("foo.example.com")}); err != nil {
		t.Fatal(err)
	}
	off := false
	disabled := remote("foo.example.com")
	disabled.Enabled = &off
	if err := m.Reconcile(ctx, []Remote{disabled}); err != nil {
		t.Fatal(err)
	}
	rec.waitStopped(t, "foo.example.com", 1)

	statuses := m.Status()
	if len(statuses) != 1 {
		t.Fatalf("Status() returned %d entries, want 1", len(statuses))
	}
	if statuses[0].State != string(StateDisabled) {
		t.Errorf("disabled remote state = %q, want %q", statuses[0].State, StateDisabled)
	}
}

func TestReconcileRejectsInvalidRemote(t *testing.T) {
	m, _ := stubManager(t)
	err := m.Reconcile(context.Background(), []Remote{{Host: "", RemoteSocket: "~/x.sock"}})
	if err == nil {
		t.Fatal("Reconcile() accepted an invalid remote; must reject")
	}
}

func TestCloseStopsEverything(t *testing.T) {
	rec := &runRecorder{started: map[string]int{}, stopped: map[string]int{}}
	m := NewManager(Deps{})
	m.newRunner = rec.runner

	if err := m.Reconcile(context.Background(), []Remote{remote("a.example.com"), remote("b.example.com")}); err != nil {
		t.Fatal(err)
	}
	m.Close()
	rec.waitStopped(t, "a.example.com", 1)
	rec.waitStopped(t, "b.example.com", 1)
}

// TestReconcileAfterCloseIsRejected guards against a Manager silently coming
// back to life after Close: a Reconcile racing (or simply arriving after)
// Close must not repopulate the map and start goroutines nothing will ever
// stop again.
func TestReconcileAfterCloseIsRejected(t *testing.T) {
	rec := &runRecorder{started: map[string]int{}, stopped: map[string]int{}}
	m := NewManager(Deps{})
	m.newRunner = rec.runner

	if err := m.Reconcile(context.Background(), []Remote{remote("foo.example.com")}); err != nil {
		t.Fatal(err)
	}
	rec.waitStarted(t, "foo.example.com", 1)

	m.Close()
	rec.waitStopped(t, "foo.example.com", 1)

	if err := m.Reconcile(context.Background(), []Remote{remote("foo.example.com")}); err == nil {
		t.Fatal("Reconcile() after Close() succeeded; want it rejected")
	}
	if got := m.Status(); len(got) != 0 {
		t.Errorf("Status() after a rejected post-Close Reconcile = %v, want empty", got)
	}
}

// TestReconcileRejectsDuplicateHost pins the case-insensitive identity rule
// shared with File.Find: two entries for the same host (even differing only
// in case) are a config error, not a silent last-one-wins.
func TestReconcileRejectsDuplicateHost(t *testing.T) {
	m, _ := stubManager(t)
	err := m.Reconcile(context.Background(), []Remote{remote("foo.example.com"), remote("FOO.example.com")})
	if err == nil {
		t.Fatal("Reconcile() accepted duplicate (case-insensitive) hosts; must reject")
	}
}

// TestReconcileLeavesUnchangedDisabledRemoteAlone guards against recreating
// an already-disabled, unchanged entry on every pass — which would discard
// its status row for no observable benefit.
func TestReconcileLeavesUnchangedDisabledRemoteAlone(t *testing.T) {
	m, _ := stubManager(t)
	ctx := context.Background()

	off := false
	disabled := remote("foo.example.com")
	disabled.Enabled = &off
	if err := m.Reconcile(ctx, []Remote{disabled}); err != nil {
		t.Fatal(err)
	}
	before := m.Status()
	if len(before) != 1 {
		t.Fatalf("Status() returned %d entries, want 1", len(before))
	}

	off2 := false
	disabledAgain := remote("foo.example.com")
	disabledAgain.Enabled = &off2
	if err := m.Reconcile(ctx, []Remote{disabledAgain}); err != nil {
		t.Fatal(err)
	}
	after := m.Status()
	if len(after) != 1 || after[0].State != string(StateDisabled) {
		t.Fatalf("Status() after re-reconciling an unchanged disabled remote = %+v, want one disabled entry", after)
	}
}

// TestStatusIsOrderedByHost pins the sort.Slice in Status: CLI output must
// not depend on Go's randomised map iteration order.
func TestStatusIsOrderedByHost(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	if err := m.Reconcile(ctx, []Remote{remote("zeta.example.com"), remote("alpha.example.com"), remote("mid.example.com")}); err != nil {
		t.Fatal(err)
	}
	rec.waitStarted(t, "zeta.example.com", 1)
	rec.waitStarted(t, "alpha.example.com", 1)
	rec.waitStarted(t, "mid.example.com", 1)

	got := m.Status()
	if len(got) != 3 {
		t.Fatalf("Status() returned %d entries, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Host >= got[i].Host {
			t.Errorf("Status() not sorted by host: %q before %q", got[i-1].Host, got[i].Host)
		}
	}
}

// TestReconcileConcurrentWithItselfAndClose exercises the brief's explicit
// "safe to call concurrently" contract: overlapping Reconcile calls, plus a
// concurrent Close, must not race (run under -race) or panic.
func TestReconcileConcurrentWithItselfAndClose(t *testing.T) {
	rec := &runRecorder{started: map[string]int{}, stopped: map[string]int{}}
	m := NewManager(Deps{})
	m.newRunner = rec.runner
	ctx := context.Background()

	hosts := []Remote{
		remote("one.example.com"), remote("two.example.com"), remote("three.example.com"),
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Vary the set slightly across goroutines so churn (add/remove)
			// overlaps with steady-state reconciles, not just repeats of the
			// same call.
			set := hosts
			if i%2 == 0 {
				set = hosts[:2]
			}
			_ = m.Reconcile(ctx, set)
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.Close()
	}()
	wg.Wait()

	// The concurrent Close is guaranteed to have landed by now (it was
	// joined by wg.Wait() above), so the manager is permanently closed:
	// this call must be rejected, not resurrect anything.
	if err := m.Reconcile(ctx, hosts); err == nil {
		t.Error("Reconcile() after a concurrent Close settled succeeded; want it rejected")
	}
	m.Close() // idempotent; must not panic or deadlock a second time
}
