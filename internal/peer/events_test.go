package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
	r := NewRelay(NewPool([]string{filepath.Join(dir, "dotvault.*.sock")}), func(events.Event) { local.Add(1) }, WithFanOut())

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
	r.streams["gone.sock"] = &relayStream{cancel: func() { cancelled.Store(true) }, wake: make(chan struct{}, 1)}

	r.reconcile(context.Background(), false)

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

// fakeSocket creates a plain socket node so the pool admits path as a member
// without anything serving it; the tests below replace the transport.
func fakeSocket(t *testing.T, path string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix domain sockets unavailable on this platform: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
}

func runRelay(t *testing.T, r *Relay) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

// An older peer answers 404. It must not be asked again at the fast retry
// rate, or every host borrowing from it would poll it every second.
func TestRelayBacksOffToTheCapOnMissingEndpoint(t *testing.T) {
	dir := sockDir(t)
	fakeSocket(t, filepath.Join(dir, "dotvault.old.sock"))
	r := NewRelay(NewPool([]string{filepath.Join(dir, "dotvault.*.sock")}), nil)
	r.minBackoff, r.maxBackoff = time.Millisecond, time.Hour
	var calls atomic.Int32
	r.stream = func(context.Context, string, func(events.Event)) error {
		calls.Add(1)
		return &StatusError{Status: http.StatusNotFound}
	}
	runRelay(t, r)

	waitFor(t, "first attempt", func() bool { return calls.Load() >= 1 })
	time.Sleep(100 * time.Millisecond)
	if n := calls.Load(); n != 1 {
		t.Fatalf("attempts = %d, want 1: a 404 must back off to the cap", n)
	}
}

// Other failures retry with a growing backoff, starting small.
func TestRelayRetriesFailedStreams(t *testing.T) {
	dir := sockDir(t)
	fakeSocket(t, filepath.Join(dir, "dotvault.a.sock"))
	r := NewRelay(NewPool([]string{filepath.Join(dir, "dotvault.*.sock")}), nil)
	r.minBackoff, r.maxBackoff = time.Millisecond, 20*time.Millisecond
	var calls atomic.Int32
	r.stream = func(context.Context, string, func(events.Event)) error {
		calls.Add(1)
		return ErrPeerUnreachable
	}
	runRelay(t, r)
	waitFor(t, "several retries", func() bool { return calls.Load() >= 4 })
}

// A forward that reconnects while its stream is backing off must be retried
// at once, not after the rest of a backoff that can reach five minutes.
func TestRelayKickWakesABackingOffStream(t *testing.T) {
	dir := sockDir(t)
	fakeSocket(t, filepath.Join(dir, "dotvault.a.sock"))
	r := NewRelay(NewPool([]string{filepath.Join(dir, "dotvault.*.sock")}), nil)
	r.minBackoff, r.maxBackoff = time.Hour, time.Hour
	var calls atomic.Int32
	r.stream = func(context.Context, string, func(events.Event)) error {
		calls.Add(1)
		return ErrPeerUnreachable
	}
	runRelay(t, r)

	waitFor(t, "first attempt", func() bool { return calls.Load() == 1 })
	r.Kick()
	waitFor(t, "retry after Kick", func() bool { return calls.Load() >= 2 })
}

// A burst of notices must not become a burst of syncs against the other
// peers: one in flight, at most one queued behind it.
func TestRelaySyncsAreSingleFlightPerPeer(t *testing.T) {
	dir := sockDir(t)
	fakeSocket(t, filepath.Join(dir, "dotvault.a.sock"))
	fakeSocket(t, filepath.Join(dir, "dotvault.b.sock"))
	r := NewRelay(NewPool([]string{filepath.Join(dir, "dotvault.*.sock")}), nil, WithFanOut())
	r.spacing = 0
	release := make(chan struct{})
	var syncs atomic.Int32
	r.postSync = func(ctx context.Context, path string) error {
		syncs.Add(1)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	}
	notices := make(chan events.Event)
	handled := make(chan struct{})
	r.stream = func(ctx context.Context, path string, fn func(events.Event)) error {
		if filepath.Base(path) != "dotvault.a.sock" {
			<-ctx.Done()
			return ctx.Err()
		}
		for {
			select {
			case e := <-notices:
				fn(e)
				handled <- struct{}{}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	runRelay(t, r)

	// Every notice is fully handled before the first sync is released, so
	// the count below depends only on the single-flight logic.
	for v := 1; v <= 10; v++ {
		notices <- events.Event{Key: "gh", Version: v}
		<-handled
	}
	waitFor(t, "first sync", func() bool { return syncs.Load() >= 1 })
	if n := syncs.Load(); n != 1 {
		t.Fatalf("syncs in flight = %d, want 1", n)
	}
	close(release)
	waitFor(t, "queued sync", func() bool { return syncs.Load() >= 2 })
	time.Sleep(50 * time.Millisecond)
	if n := syncs.Load(); n != 2 {
		t.Fatalf("syncs = %d, want 2: ten notices collapse to one in flight plus one queued", n)
	}
}

func TestValidEventRejectsHostileKeys(t *testing.T) {
	for _, e := range []events.Event{
		{Key: "", Version: 1},
		{Key: "gh", Version: 0},
		{Key: "../other-user/gh", Version: 1},
		{Key: "/gh", Version: 1},
		{Key: "a//b", Version: 1},
		{Key: strings.Repeat("a", maxEventKeyLen+1), Version: 1},
		{Key: "gh\x1b[2J", Version: 1}, // terminal escape into a log line
		{Key: "gh\x7f", Version: 1},
	} {
		if validEvent(e) {
			t.Errorf("validEvent(%q@%d) = true, want false", e.Key, e.Version)
		}
	}
	for _, e := range []events.Event{{Key: "gh", Version: 1}, {Key: "databricks/prod", Version: 9}} {
		if !validEvent(e) {
			t.Errorf("validEvent(%q@%d) = false, want true", e.Key, e.Version)
		}
	}
}

// A peer's Source and Time are its claims; only a known Source survives, and
// Time is this host's receipt.
func TestSanitiseDropsUnknownSourceAndRestampsTime(t *testing.T) {
	old := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	got := sanitise(events.Event{Key: "gh", Version: 1, Source: "rm -rf", Time: old})
	if got.Source != "" {
		t.Errorf("Source = %q, want it dropped", got.Source)
	}
	if !got.Time.After(old) {
		t.Errorf("Time = %v, want this host's receipt time", got.Time)
	}
	if kept := sanitise(events.Event{Key: "gh", Version: 1, Source: "refresh"}); kept.Source != "refresh" {
		t.Errorf("Source = %q, want refresh kept", kept.Source)
	}
}

func TestStreamEventsJoinsMultiLineData(t *testing.T) {
	sock := filepath.Join(sockDir(t), "m.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix domain sockets unavailable on this platform: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: kv-write\r\ndata:{\"key\":\"gh\",\r\ndata: \"version\":4}\r\n\r\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan events.Event, 1)
	go func() { _ = StreamEvents(ctx, sock, func(e events.Event) { got <- e }) }()
	select {
	case e := <-got:
		if e.Key != "gh" || e.Version != 4 {
			t.Fatalf("got %+v, want gh@4", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("multi-line CRLF event not delivered")
	}
}

// Without WithFanOut the relay only listens: the client facade subscribes
// this way, and a library must never make other hosts sync.
func TestRelayWithoutFanOutOnlyListens(t *testing.T) {
	dir := sockDir(t)
	newFakeDesktop(t, filepath.Join(dir, "dotvault.a.sock"), []events.Event{{Key: "gh", Version: 3}})
	newFakeDesktop(t, filepath.Join(dir, "dotvault.b.sock"), nil)

	got := make(chan events.Event, 1)
	r := NewRelay(NewPool([]string{filepath.Join(dir, "dotvault.*.sock")}), func(e events.Event) { got <- e })
	var syncs atomic.Int32
	r.postSync = func(context.Context, string) error { syncs.Add(1); return nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	select {
	case e := <-got:
		if e.Key != "gh" || e.Version != 3 {
			t.Fatalf("got %+v, want gh@3", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("notice not delivered")
	}
	// Run returns only once every sync it started has finished, so after it
	// the count is final rather than a guess about timing.
	cancel()
	<-done
	if n := syncs.Load(); n != 0 {
		t.Fatalf("a listen-only relay asked peers to sync %d times", n)
	}
}

// A shared table lets the daemon recognise its own write coming back.
func TestRelaySharedSeenSuppressesOwnEcho(t *testing.T) {
	dir := sockDir(t)
	newFakeDesktop(t, filepath.Join(dir, "dotvault.a.sock"), []events.Event{{Key: "gh", Version: 9}, {Key: "gh", Version: 10}})

	seen := events.NewSeen()
	seen.Admit(events.Event{Key: "gh", Version: 9}) // this host wrote v9 itself
	got := make(chan events.Event, 2)
	r := NewRelay(NewPool([]string{filepath.Join(dir, "dotvault.*.sock")}), func(e events.Event) { got <- e }, WithSeen(seen))
	runRelay(t, r)

	select {
	case e := <-got:
		if e.Version != 10 {
			t.Fatalf("got gh@%d first, want the echo of gh@9 suppressed", e.Version)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gh@10 not delivered")
	}
}
