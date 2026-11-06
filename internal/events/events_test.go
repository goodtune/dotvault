package events

import (
	"testing"
	"time"
)

func TestHubDeliversToEverySubscriber(t *testing.T) {
	h := NewHub()
	a, cancelA := h.Subscribe()
	defer cancelA()
	b, cancelB := h.Subscribe()
	defer cancelB()

	h.Publish(Event{Key: "gh", Version: 3})

	for name, ch := range map[string]<-chan Event{"a": a, "b": b} {
		select {
		case e := <-ch:
			if e.Key != "gh" || e.Version != 3 {
				t.Errorf("%s got %+v, want gh@3", name, e)
			}
			if e.Time.IsZero() {
				t.Errorf("%s: Publish did not stamp a time", name)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s received nothing", name)
		}
	}
}

func TestHubCancelStopsDeliveryAndClosesChannel(t *testing.T) {
	h := NewHub()
	ch, cancel := h.Subscribe()
	cancel()
	cancel() // idempotent

	h.Publish(Event{Key: "gh", Version: 1})
	if _, ok := <-ch; ok {
		t.Fatal("cancelled subscriber still received an event")
	}
}

func TestHubPublishNeverBlocksOnSlowSubscriber(t *testing.T) {
	h := NewHub()
	_, cancel := h.Subscribe() // never read
	defer cancel()

	done := make(chan struct{})
	go func() {
		for i := 0; i < subscriberBuffer*4; i++ {
			h.Publish(Event{Key: "gh", Version: i})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a subscriber that does not read")
	}
}

func TestNilHubIsSafe(t *testing.T) {
	var h *Hub
	h.Publish(Event{Key: "gh", Version: 1})
	ch, cancel := h.Subscribe()
	cancel()
	if _, ok := <-ch; ok {
		t.Fatal("nil hub subscription delivered an event")
	}
}

func TestSeenAdmitsEachVersionOnce(t *testing.T) {
	s := NewSeen()
	if !s.Admit(Event{Key: "gh", Version: 5}) {
		t.Fatal("first sight of gh@5 refused")
	}
	if s.Admit(Event{Key: "gh", Version: 5}) {
		t.Fatal("duplicate gh@5 admitted")
	}
	if !s.Admit(Event{Key: "gh", Version: 6}) {
		t.Fatal("gh@6 refused")
	}
	if !s.Admit(Event{Key: "jfrog", Version: 5}) {
		t.Fatal("same version on a different key refused")
	}
}

// A revoked secret is wiped and re-enrolled, which restarts its KVv2 version
// at 1. A high-water mark would refuse every event for it from then on.
func TestSeenAdmitsVersionRestartAfterWipe(t *testing.T) {
	s := NewSeen()
	for v := 30; v <= 32; v++ {
		s.Admit(Event{Key: "gh", Version: v})
	}
	if !s.Admit(Event{Key: "gh", Version: 1}) {
		t.Fatal("gh@1 after a wipe refused")
	}
	if !s.Admit(Event{Key: "gh", Version: 2}) {
		t.Fatal("gh@2 after a wipe refused")
	}
}
