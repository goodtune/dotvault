package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/events"
)

// fakeDesktop is a peer daemon's web API on a Unix socket: an events stream
// that emits a scripted list of notices, and a CSRF-protected sync endpoint
// that counts the syncs it was asked for.
type fakeDesktop struct {
	path   string
	syncs  atomic.Int32
	csrfMu sync.Mutex
	tokens map[string]bool
}

func newFakeDesktop(t *testing.T, path string, emit []events.Event) *fakeDesktop {
	t.Helper()
	d := &fakeDesktop{path: path, tokens: map[string]bool{}}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix domain sockets unavailable on this platform: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ": connected\n\n")
		fmt.Fprint(w, "event: something-else\ndata: {\"key\":\"ignored\",\"version\":1}\n\n")
		for _, e := range emit {
			fmt.Fprintf(w, "event: kv-write\nid: %s@%d\ndata: {\"key\":%q,\"version\":%d}\n\n", e.Key, e.Version, e.Key, e.Version)
		}
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	n := 0
	mux.HandleFunc("GET /api/v1/csrf", func(w http.ResponseWriter, r *http.Request) {
		d.csrfMu.Lock()
		n++
		tok := fmt.Sprintf("tok-%d", n)
		d.tokens[tok] = true
		d.csrfMu.Unlock()
		fmt.Fprintf(w, `{"token":%q}`, tok)
	})
	mux.HandleFunc("POST /api/v1/sync", func(w http.ResponseWriter, r *http.Request) {
		d.csrfMu.Lock()
		ok := d.tokens[r.Header.Get("X-CSRF-Token")]
		delete(d.tokens, r.Header.Get("X-CSRF-Token"))
		d.csrfMu.Unlock()
		if !ok {
			http.Error(w, `{"error":"invalid or missing CSRF token"}`, http.StatusForbidden)
			return
		}
		d.syncs.Add(1)
		fmt.Fprint(w, `{"status":"sync triggered"}`)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return d
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStreamEventsDeliversKVWrites(t *testing.T) {
	sock := filepath.Join(sockDir(t), "a.sock")
	newFakeDesktop(t, sock, []events.Event{{Key: "gh", Version: 7}, {Key: "jfrog", Version: 2}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan events.Event, 4)
	done := make(chan error, 1)
	go func() { done <- StreamEvents(ctx, sock, func(e events.Event) { got <- e }) }()

	for _, want := range []events.Event{{Key: "gh", Version: 7}, {Key: "jfrog", Version: 2}} {
		select {
		case e := <-got:
			if e.Key != want.Key || e.Version != want.Version {
				t.Fatalf("got %+v, want %+v", e, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no event for %+v", want)
		}
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("StreamEvents returned nil; it must say why the stream ended")
	}
	select {
	case e := <-got:
		t.Fatalf("unexpected extra event %+v (non-kv-write events must be ignored)", e)
	default:
	}
}

func TestStreamEventsReportsMissingEndpoint(t *testing.T) {
	sock := filepath.Join(sockDir(t), "old.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix domain sockets unavailable on this platform: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)

	err = StreamEvents(context.Background(), sock, func(events.Event) {})
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusNotFound {
		t.Fatalf("err = %v, want a 404 *StatusError", err)
	}
}

func TestStreamEventsMissingSocketIsUnreachable(t *testing.T) {
	err := StreamEvents(context.Background(), filepath.Join(sockDir(t), "absent.sock"), func(events.Event) {})
	if !errors.Is(err, ErrPeerUnreachable) {
		t.Fatalf("err = %v, want ErrPeerUnreachable", err)
	}
}

func TestPostSyncSpendsACSRFToken(t *testing.T) {
	sock := filepath.Join(sockDir(t), "a.sock")
	d := newFakeDesktop(t, sock, nil)

	if err := PostSync(context.Background(), sock); err != nil {
		t.Fatalf("PostSync: %v", err)
	}
	if n := d.syncs.Load(); n != 1 {
		t.Fatalf("syncs = %d, want 1", n)
	}
}

// The scenario the relay exists for: desktop A rotates a token and reports it
// (twice — a duplicate must not count), desktop B knows nothing about A.
// The relaying host must sync itself once and ask B, and only B, to sync.
func TestRelaySpreadsANoticeToTheOtherPeers(t *testing.T) {
	dir := sockDir(t)
	a := newFakeDesktop(t, filepath.Join(dir, "dotvault.a.sock"), []events.Event{
		{Key: "gh", Version: 30},
		{Key: "gh", Version: 30},
	})
	b := newFakeDesktop(t, filepath.Join(dir, "dotvault.b.sock"), nil)

	var local atomic.Int32
	r := NewRelay(NewPool([]string{filepath.Join(dir, "dotvault.*.sock")}), func() { local.Add(1) })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	waitFor(t, "local sync", func() bool { return local.Load() >= 1 })
	waitFor(t, "peer B sync", func() bool { return b.syncs.Load() >= 1 })
	// Give a mistaken second relay time to land before asserting it did not.
	time.Sleep(200 * time.Millisecond)

	if n := local.Load(); n != 1 {
		t.Errorf("local syncs = %d, want 1 (the duplicate notice must be ignored)", n)
	}
	if n := b.syncs.Load(); n != 1 {
		t.Errorf("peer B syncs = %d, want 1", n)
	}
	if n := a.syncs.Load(); n != 0 {
		t.Errorf("peer A syncs = %d, want 0: it wrote the secret", n)
	}
}

func TestRelayStopsStreamsForVanishedPeers(t *testing.T) {
	// The pool resolves nothing, so a tracked stream belongs to a peer that
	// has gone and must be cancelled and forgotten.
	r := NewRelay(NewPool([]string{filepath.Join(sockDir(t), "dotvault.*.sock")}), nil)
	var cancelled atomic.Bool
	r.streams["gone.sock"] = func() { cancelled.Store(true) }

	r.reconcile(context.Background())

	if !cancelled.Load() {
		t.Fatal("stream for a vanished peer was not cancelled")
	}
	r.mu.Lock()
	_, still := r.streams["gone.sock"]
	r.mu.Unlock()
	if still {
		t.Fatal("vanished peer still tracked")
	}
}
