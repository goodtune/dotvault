package events

import (
	"fmt"
	"testing"
	"time"
)

func TestHubDeliversToEverySubscriber(t *testing.T) {
	h := NewHub()
	a, cancelA, _ := h.Subscribe()
	defer cancelA()
	b, cancelB, _ := h.Subscribe()
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
	ch, cancel, _ := h.Subscribe()
	cancel()
	cancel() // idempotent

	h.Publish(Event{Key: "gh", Version: 1})
	if _, ok := <-ch; ok {
		t.Fatal("cancelled subscriber still received an event")
	}
}

func TestHubPublishNeverBlocksOnSlowSubscriber(t *testing.T) {
	h := NewHub()
	_, cancel, _ := h.Subscribe() // never read
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

func TestNilHubIsQuietNotClosed(t *testing.T) {
	var h *Hub
	h.Publish(Event{Key: "gh", Version: 1})
	ch, cancel, err := h.Subscribe()
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	select {
	case _, ok := <-ch:
		t.Fatalf("nil hub subscription yielded (ok=%v); it must stay open and quiet", ok)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if _, ok := <-ch; ok {
		t.Fatal("cancel did not close the channel")
	}
}

func TestHubCapsSubscribers(t *testing.T) {
	h := NewHub()
	var cancels []func()
	for i := 0; i < MaxSubscribers; i++ {
		_, c, err := h.Subscribe()
		if err != nil {
			t.Fatalf("subscriber %d refused: %v", i, err)
		}
		cancels = append(cancels, c)
	}
	if _, _, err := h.Subscribe(); err != ErrTooManySubscribers {
		t.Fatalf("subscriber over the cap: err = %v, want ErrTooManySubscribers", err)
	}
	cancels[0]()
	if _, _, err := h.Subscribe(); err != nil {
		t.Fatalf("subscriber after a cancel refused: %v", err)
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
	for v := 1; v <= 3; v++ {
		if !s.Admit(Event{Key: "gh", Version: v}) {
			t.Fatalf("gh@%d after a wipe refused", v)
		}
	}
}

// The overlap case: the old life reached v5, the new life's v1 restarts the
// window, and its v2 — also seen in the old life — must still be admitted.
func TestSeenRestartForgetsOldLifeVersions(t *testing.T) {
	s := NewSeen()
	for v := 2; v <= 5; v++ {
		s.Admit(Event{Key: "gh", Version: v})
	}
	if !s.Admit(Event{Key: "gh", Version: 1}) {
		t.Fatal("gh@1 after a wipe refused")
	}
	if !s.Admit(Event{Key: "gh", Version: 2}) {
		t.Fatal("new life's gh@2 refused because the old life had a v2")
	}
}

func TestSeenRefusesVersionlessEvents(t *testing.T) {
	s := NewSeen()
	for _, v := range []int{0, -1} {
		if s.Admit(Event{Key: "gh", Version: v}) {
			t.Fatalf("gh@%d admitted", v)
		}
	}
	if !s.Admit(Event{Key: "gh", Version: 1}) {
		t.Fatal("gh@1 refused after version-less events")
	}
}

func TestSeenBoundsDistinctKeys(t *testing.T) {
	s := NewSeen()
	for i := 0; i < maxSeenKeys+10; i++ {
		s.Admit(Event{Key: fmt.Sprintf("k%d", i), Version: 1})
	}
	s.mu.Lock()
	n := len(s.versions)
	s.mu.Unlock()
	if n > maxSeenKeys {
		t.Fatalf("Seen tracks %d keys, want at most %d", n, maxSeenKeys)
	}
}
