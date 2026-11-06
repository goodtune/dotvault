package web

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/events"
)

func TestHandleEventsStreamsKeyAndVersion(t *testing.T) {
	s := testServer(t)
	s.events = events.NewHub()
	ts := httptest.NewServer(http.HandlerFunc(s.handleEvents))
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q", ct)
	}

	sc := bufio.NewScanner(resp.Body)
	// The opening comment arrives before any event, which is what proves
	// the subscription is registered: publishing earlier could be missed.
	if !sc.Scan() || sc.Text() != ": connected" {
		t.Fatalf("first line = %q, want the opening comment", sc.Text())
	}
	s.events.Publish(events.Event{Key: "gh", Version: 31, Source: "refresh"})

	var lines []string
	for sc.Scan() {
		if sc.Text() == "" && len(lines) > 0 {
			break
		}
		if sc.Text() != "" {
			lines = append(lines, sc.Text())
		}
	}
	got := strings.Join(lines, "\n")
	for _, want := range []string{"event: kv-write", "id: gh@31", `"key":"gh"`, `"version":31`} {
		if !strings.Contains(got, want) {
			t.Errorf("event %q missing %q", got, want)
		}
	}
}

func TestHandleEventsEndsOnServerShutdown(t *testing.T) {
	s := testServer(t)
	s.events = events.NewHub()
	ts := httptest.NewServer(http.HandlerFunc(s.handleEvents))
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Scan() // opening comment

	s.shutdownCancel()
	done := make(chan struct{})
	go func() {
		for sc.Scan() {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not end on shutdown; it would hold http.Server.Shutdown open")
	}
}

func TestHandleEventsRefusesOverTheSubscriberCap(t *testing.T) {
	s := testServer(t)
	s.events = events.NewHub()
	for i := 0; i < events.MaxSubscribers; i++ {
		_, cancel, err := s.events.Subscribe()
		if err != nil {
			t.Fatalf("Subscribe %d: %v", i, err)
		}
		t.Cleanup(cancel)
	}
	rec := httptest.NewRecorder()
	s.handleEvents(rec, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
