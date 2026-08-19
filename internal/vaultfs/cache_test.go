package vaultfs

import (
	"context"
	"testing"
	"time"
)

func TestCacheServesRepeatedReadsWithoutHittingVault(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	tree := NewTree(store, false, time.Hour)

	for range 5 {
		if _, err := tree.Document(context.Background(), "gh"); err != nil {
			t.Fatalf("Document: %v", err)
		}
		if _, err := tree.Readdir(context.Background(), ""); err != nil {
			t.Fatalf("Readdir: %v", err)
		}
	}
	lists, reads, _, _ := store.counts()
	if reads != 1 {
		t.Errorf("reads = %d, want 1 — repeated stats of one file should not re-read it", reads)
	}
	if lists != 1 {
		t.Errorf("lists = %d, want 1", lists)
	}
}

// A lookup for a name that does not exist is the most common request a mounted
// filesystem gets. Without negative caching each one is a Vault round trip.
func TestCacheRemembersMisses(t *testing.T) {
	store := newMemStore()
	store.listErr = errDenied // force the read fallback so misses reach the store
	tree := NewTree(store, false, time.Hour)

	for range 4 {
		if doc, err := tree.Document(context.Background(), "nope"); err != nil || doc != nil {
			t.Fatalf("Document = %v, %v; want nil, nil", doc, err)
		}
	}
	if _, reads, _, _ := store.counts(); reads != 1 {
		t.Errorf("reads = %d, want 1 — a miss should be cached too", reads)
	}
}

func TestCacheExpiresAfterTTL(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	tree := NewTree(store, false, time.Minute)

	// Drive the clock rather than sleeping.
	now := time.Now()
	tree.cache.now = func() time.Time { return now }

	if _, err := tree.Document(context.Background(), "gh"); err != nil {
		t.Fatalf("Document: %v", err)
	}
	if _, reads, _, _ := store.counts(); reads != 1 {
		t.Fatalf("reads = %d, want 1", reads)
	}

	now = now.Add(2 * time.Minute)
	if _, err := tree.Document(context.Background(), "gh"); err != nil {
		t.Fatalf("Document after expiry: %v", err)
	}
	if _, reads, _, _ := store.counts(); reads != 2 {
		t.Errorf("reads = %d, want 2 — the entry should have expired", reads)
	}
}

func TestZeroTTLDisablesCaching(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	tree := NewTree(store, false, 0)

	for range 3 {
		if _, err := tree.Document(context.Background(), "gh"); err != nil {
			t.Fatalf("Document: %v", err)
		}
	}
	if _, reads, _, _ := store.counts(); reads != 3 {
		t.Errorf("reads = %d, want 3 — a zero TTL means no caching at all", reads)
	}
}

func TestInvalidateAllDropsEverything(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	tree := NewTree(store, false, time.Hour)

	if _, err := tree.Document(context.Background(), "gh"); err != nil {
		t.Fatalf("Document: %v", err)
	}
	if _, err := tree.Readdir(context.Background(), ""); err != nil {
		t.Fatalf("Readdir: %v", err)
	}
	tree.InvalidateAll()

	if _, err := tree.Document(context.Background(), "gh"); err != nil {
		t.Fatalf("Document: %v", err)
	}
	if _, err := tree.Readdir(context.Background(), ""); err != nil {
		t.Fatalf("Readdir: %v", err)
	}
	lists, reads, _, _ := store.counts()
	if lists != 2 || reads != 2 {
		t.Errorf("lists = %d, reads = %d; want 2 and 2 after InvalidateAll", lists, reads)
	}
}
