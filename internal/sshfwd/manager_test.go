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

func remote(host string) Remote {
	return Remote{Host: host, RemoteSocket: DefaultRemoteSocket}
}

func TestReconcileStartsNewRemotes(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	if err := m.Reconcile(ctx, []Remote{remote("foo.example.com")}); err != nil {
		t.Fatalf("Reconcile() = %v", err)
	}
	if started, _ := rec.counts("foo.example.com"); started != 1 {
		t.Errorf("foo started %d times, want 1", started)
	}
}

func TestReconcileKeepsUnchangedRemotes(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	r := []Remote{remote("foo.example.com")}
	if err := m.Reconcile(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := m.Reconcile(ctx, r); err != nil {
		t.Fatal(err)
	}
	started, stopped := rec.counts("foo.example.com")
	if started != 1 || stopped != 0 {
		t.Errorf("unchanged remote restarted: started=%d stopped=%d, want 1/0", started, stopped)
	}
}

func TestReconcileAddsWithoutDisturbingExisting(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	if err := m.Reconcile(ctx, []Remote{remote("foo.example.com")}); err != nil {
		t.Fatal(err)
	}
	if err := m.Reconcile(ctx, []Remote{remote("foo.example.com"), remote("bar.example.com")}); err != nil {
		t.Fatal(err)
	}
	if started, stopped := rec.counts("foo.example.com"); started != 1 || stopped != 0 {
		t.Errorf("foo disturbed by adding bar: started=%d stopped=%d", started, stopped)
	}
	if started, _ := rec.counts("bar.example.com"); started != 1 {
		t.Errorf("bar started %d times, want 1", started)
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
	changed := remote("foo.example.com")
	changed.Port = 2222
	if err := m.Reconcile(ctx, []Remote{changed}); err != nil {
		t.Fatal(err)
	}
	rec.waitStopped(t, "foo.example.com", 1)
	if started, _ := rec.counts("foo.example.com"); started != 2 {
		t.Errorf("modified remote started %d times, want 2 (restart)", started)
	}
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
