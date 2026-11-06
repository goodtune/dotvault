package main

import (
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/enrol"
	"github.com/goodtune/dotvault/internal/events"
)

func TestSecretChangeHookPublishesOnlyLocalWrites(t *testing.T) {
	hub := events.NewHub()
	ch, cancel := hub.Subscribe()
	defer cancel()
	syncs := 0
	hook := secretChangeHook(func() { syncs++ }, hub)("refresh")

	hook(enrol.Change{Key: "gh", Version: 4, Local: false})
	hook(enrol.Change{Key: "gh", Version: 5, Local: true})

	if syncs != 2 {
		t.Errorf("syncs = %d, want 2: every change re-renders files", syncs)
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
		t.Fatalf("observed change was published too: %+v", e)
	default:
	}
}
