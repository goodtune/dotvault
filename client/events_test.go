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
	local := make(chan string, 4)
	remote := make(chan string, 4)
	newEventServer(t, filepath.Join(dir, "api.sock"), local)
	newEventServer(t, filepath.Join(dir, "peer.sock"), remote)

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

	// The local daemon relays what the peer announced, so the same write
	// arrives on both sockets; it must be delivered once.
	local <- `{"key":"gh","version":40,"source":"refresh"}`
	remote <- `{"key":"gh","version":40,"source":"refresh"}`
	e := nextWithin(t, sub, 5*time.Second)
	if e.Key != "gh" || e.Version != 40 || e.Source != "refresh" {
		t.Fatalf("got %+v, want gh@40 from refresh", e)
	}

	remote <- `{"key":"databricks/prod","version":3}`
	e = nextWithin(t, sub, 5*time.Second)
	if e.Key != "databricks/prod" || e.Version != 3 {
		t.Fatalf("got %+v, want databricks/prod@3 (the duplicate gh@40 must not appear)", e)
	}
}

func TestSubscriptionCoalescesPerKey(t *testing.T) {
	s := &Subscription{pending: map[string]Event{}, notify: make(chan struct{}, 1), done: make(chan struct{}), cancel: func() {}}
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
