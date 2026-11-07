package main

import (
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/enrol"
	"github.com/goodtune/dotvault/internal/events"
)

func TestSecretChangeHookPublishesOnlyLocalWrites(t *testing.T) {
	hub := events.NewHub()
	ch, cancel, _ := hub.Subscribe()
	defer cancel()
	syncs := 0
	hook := secretChangeHook(func() { syncs++ }, hub, events.NewSeen())("refresh")

	hook(enrol.Change{Key: "gh", Version: 4, Local: false})
	hook(enrol.Change{Key: "gh", Version: 0, Local: true}) // Vault reported no version
	hook(enrol.Change{Key: "gh", Version: 5, Local: true})

	if syncs != 3 {
		t.Errorf("syncs = %d, want 3: every change re-renders files", syncs)
	}
	select {
	case e := <-ch:
		if e.Key != "gh" || e.Version != 5 || e.Source != "refresh" {
			t.Errorf("published %+v, want gh@5 from refresh", e)
		}
	case <-time.After(time.Second):
		t.Fatal("local write was not published")
	}
	select {
	case e := <-ch:
		t.Fatalf("observed or version-less change was published too: %+v", e)
	default:
	}
}

// A notice relayed from a peer is re-announced on this daemon's hub, so a
// host borrowing from this one hears it.
func TestRelayedNoticeSyncsAndReannounces(t *testing.T) {
	hub := events.NewHub()
	ch, cancel, _ := hub.Subscribe()
	defer cancel()
	syncs := 0
	relayedNotice(func() { syncs++ }, hub)(events.Event{Key: "gh", Version: 7, Source: "refresh"})

	if syncs != 1 {
		t.Errorf("syncs = %d, want 1", syncs)
	}
	select {
	case e := <-ch:
		if e.Key != "gh" || e.Version != 7 {
			t.Errorf("re-announced %+v, want gh@7", e)
		}
	case <-time.After(time.Second):
		t.Fatal("relayed notice not re-announced")
	}
}

// The daemon records its own writes in the table the relay consults, so its
// own notice echoed back by a peer is not acted on again.
func TestSecretChangeHookRecordsOwnWritesInSeen(t *testing.T) {
	seen := events.NewSeen()
	hook := secretChangeHook(func() {}, events.NewHub(), seen)("refresh")
	hook(enrol.Change{Key: "gh", Version: 12, Local: true})
	if seen.Admit(events.Event{Key: "gh", Version: 12}) {
		t.Fatal("own write not recorded: its echo would be relayed again")
	}
}
