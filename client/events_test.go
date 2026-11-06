package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/events"
)

// newEventServer serves GET /api/v1/events on a Unix socket, writing each
// notice from the channel as it arrives — the shape of a dotvault daemon's
// change-notice stream.
func newEventServer(t *testing.T, sock string, notices <-chan string) {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix domain sockets unavailable on this platform: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ": connected\n\n")
		w.(http.Flusher).Flush()
		for {
			select {
			case n := <-notices:
				fmt.Fprintf(w, "event: kv-write\ndata: %s\n\n", n)
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
}

func nextWithin(t *testing.T, s *Subscription, d time.Duration) Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	e, err := s.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	return e
}

func TestSubscribeDeliversEachWriteOnceAcrossSockets(t *testing.T) {
	dir := clientSockDir(t)
	first := make(chan string, 4)
	second := make(chan string, 4)
	newEventServer(t, filepath.Join(dir, "a.sock"), first)
	newEventServer(t, filepath.Join(dir, "b.sock"), second)

	// No API socket, so Subscribe listens to every peer.
	c, err := New(&Config{Vault: VaultConfig{
		Address:      "http://127.0.0.1:8200",
		TokenSockets: []string{filepath.Join(dir, "a.sock"), filepath.Join(dir, "b.sock")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := c.Subscribe(context.Background())
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	first <- `{"key":"gh","version":40,"source":"refresh"}`
	e := nextWithin(t, sub, 5*time.Second)
	if e.Key != "gh" || e.Version != 40 || e.Source != "refresh" {
		t.Fatalf("got %+v, want gh@40 from refresh", e)
	}

	// The same write heard again from another peer only after the first was
	// delivered, so coalescing cannot hide it: only dedup keeps it out. The
	// marker follows on the same stream, so once it arrives the duplicate has
	// been handled.
	second <- `{"key":"gh","version":40,"source":"refresh"}`
	second <- `{"key":"databricks/prod","version":3}`
	e = nextWithin(t, sub, 5*time.Second)
	if e.Key != "databricks/prod" || e.Version != 3 {
		t.Fatalf("got %+v, want databricks/prod@3 (the duplicate gh@40 must not appear)", e)
	}
}

func TestSubscribeUsesOnlyTheAPISocketWhenSet(t *testing.T) {
	dir := clientSockDir(t)
	local := make(chan string, 4)
	peerCh := make(chan string, 4)
	newEventServer(t, filepath.Join(dir, "api.sock"), local)
	newEventServer(t, filepath.Join(dir, "peer.sock"), peerCh)

	c, err := New(&Config{Vault: VaultConfig{
		Address:      "http://127.0.0.1:8200",
		APISocket:    filepath.Join(dir, "api.sock"),
		TokenSockets: []string{filepath.Join(dir, "peer.sock")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := c.Subscribe(context.Background())
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	peerCh <- `{"key":"peer-only","version":1}`
	local <- `{"key":"gh","version":2}`
	e := nextWithin(t, sub, 5*time.Second)
	if e.Key != "gh" {
		t.Fatalf("got %+v, want gh from the API socket (the peer must not be listened to)", e)
	}
}

func TestSubscriptionCoalescesPerKey(t *testing.T) {
	s := newTestSubscription()
	s.push(evt("gh", 1))
	s.push(evt("jfrog", 1))
	s.push(evt("gh", 2))

	ctx := context.Background()
	first, _ := s.Next(ctx)
	second, _ := s.Next(ctx)
	if first.Key != "gh" || first.Version != 2 {
		t.Errorf("first = %+v, want gh@2 (latest write, in gh's original place)", first)
	}
	if second.Key != "jfrog" {
		t.Errorf("second = %+v, want jfrog", second)
	}
}

func newTestSubscription() *Subscription {
	return &Subscription{pending: map[string]Event{}, notify: make(chan struct{}, 1), done: make(chan struct{}), cancel: func() {}}
}

func TestSubscriptionCoalescesToTheHigherVersion(t *testing.T) {
	s := newTestSubscription()
	s.push(evt("gh", 5))
	s.push(evt("gh", 4)) // a slower socket reporting an older write
	if e, _ := s.Next(context.Background()); e.Version != 5 {
		t.Fatalf("got gh@%d, want gh@5", e.Version)
	}
}

func TestSubscriptionBoundsPendingKeys(t *testing.T) {
	s := newTestSubscription()
	for i := 0; i <= maxPending; i++ {
		s.push(evt(fmt.Sprintf("k%d", i), 1))
	}
	if len(s.pending) != maxPending || len(s.order) != maxPending {
		t.Fatalf("pending = %d/%d, want %d", len(s.pending), len(s.order), maxPending)
	}
	if e, _ := s.Next(context.Background()); e.Key != "k1" {
		t.Fatalf("first = %q, want k1 (the oldest, k0, dropped)", e.Key)
	}
}

func TestSubscriptionConcurrentReadersEachGetAnEvent(t *testing.T) {
	s := newTestSubscription()
	got := make(chan string, 2)
	for i := 0; i < 2; i++ {
		go func() {
			e, err := s.Next(context.Background())
			if err == nil {
				got <- e.Key
			}
		}()
	}
	time.Sleep(20 * time.Millisecond) // let both readers block
	s.push(evt("a", 1))
	s.push(evt("b", 1))
	for i := 0; i < 2; i++ {
		select {
		case <-got:
		case <-time.After(5 * time.Second):
			t.Fatal("a reader slept beside a pending event")
		}
	}
}

func TestSubscriptionDrainsBeforeReportingContextEnd(t *testing.T) {
	s := newTestSubscription()
	close(s.done) // the context Subscribe was given has ended
	s.push(evt("gh", 1))
	if e, err := s.Next(context.Background()); err != nil || e.Key != "gh" {
		t.Fatalf("Next = %+v, %v; want the event already received", e, err)
	}
	if _, err := s.Next(context.Background()); !errors.Is(err, ErrSubscriptionClosed) {
		t.Fatalf("Next = %v, want ErrSubscriptionClosed once drained", err)
	}
}

func TestSubscriptionCloseDiscardsPending(t *testing.T) {
	s := newTestSubscription()
	close(s.done)
	s.push(evt("gh", 1))
	_ = s.Close()
	if _, err := s.Next(context.Background()); !errors.Is(err, ErrSubscriptionClosed) {
		t.Fatalf("Next after Close = %v, want ErrSubscriptionClosed", err)
	}
}

func TestSubscribeWithoutSocketsIsPeerUnavailable(t *testing.T) {
	c, err := New(&Config{Vault: VaultConfig{Address: "http://127.0.0.1:8200"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Subscribe(context.Background()); !errors.Is(err, ErrPeerUnavailable) {
		t.Fatalf("err = %v, want ErrPeerUnavailable", err)
	}
}

func TestSubscriptionCloseEndsNext(t *testing.T) {
	dir := clientSockDir(t)
	c, err := New(&Config{Vault: VaultConfig{Address: "http://127.0.0.1:8200", TokenSockets: []string{filepath.Join(dir, "absent.sock")}}})
	if err != nil {
		t.Fatal(err)
	}
	// No daemon is listening: Subscribe still succeeds and keeps retrying.
	sub, err := c.Subscribe(context.Background())
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := sub.Next(context.Background())
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	sub.Close()
	sub.Close() // idempotent
	select {
	case err := <-errc:
		if !errors.Is(err, ErrSubscriptionClosed) {
			t.Fatalf("Next after Close: %v, want ErrSubscriptionClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Next did not return after Close")
	}
}

func evt(key string, version int) events.Event { return events.Event{Key: key, Version: version} }
