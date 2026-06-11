package groups

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// countingResolver records lookups and serves a fixed map.
type countingResolver struct {
	calls   int
	entries map[string][]string
	err     error
}

func (r *countingResolver) Groups(_ context.Context, user string) ([]string, error) {
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	return r.entries[user], nil
}

func TestCachedServesFromCacheWithinTTL(t *testing.T) {
	inner := &countingResolver{entries: map[string][]string{"alice": {"sydney"}}}
	c := NewCached(inner, time.Minute).(*cached)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		got, err := c.Groups(ctx, "alice")
		if err != nil {
			t.Fatalf("Groups: %v", err)
		}
		if want := []string{"sydney"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("Groups = %v, want %v", got, want)
		}
	}
	if inner.calls != 1 {
		t.Fatalf("inner lookups = %d, want 1 (cached)", inner.calls)
	}

	// Past the TTL the next lookup goes to the backend again.
	now = now.Add(2 * time.Minute)
	if _, err := c.Groups(ctx, "alice"); err != nil {
		t.Fatalf("Groups after expiry: %v", err)
	}
	if inner.calls != 2 {
		t.Fatalf("inner lookups after expiry = %d, want 2", inner.calls)
	}
}

func TestCachedCachesEmptyMembership(t *testing.T) {
	inner := &countingResolver{entries: map[string][]string{}}
	c := NewCached(inner, time.Minute)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		got, err := c.Groups(ctx, "stranger")
		if err != nil {
			t.Fatalf("Groups: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("Groups = %v, want empty", got)
		}
	}
	if inner.calls != 1 {
		t.Fatalf("inner lookups = %d, want 1 (empty membership cached)", inner.calls)
	}
}

func TestCachedDoesNotCacheErrors(t *testing.T) {
	inner := &countingResolver{err: errors.New("backend down")}
	c := NewCached(inner, time.Minute)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := c.Groups(ctx, "alice"); err == nil {
			t.Fatal("Groups succeeded, want error")
		}
	}
	if inner.calls != 2 {
		t.Fatalf("inner lookups = %d, want 2 (errors retried, not cached)", inner.calls)
	}
}

func TestCachedCopyIsolation(t *testing.T) {
	inner := &countingResolver{entries: map[string][]string{"alice": {"a", "b"}}}
	c := NewCached(inner, time.Minute)
	ctx := context.Background()
	first, _ := c.Groups(ctx, "alice")
	first[0] = "mutated"
	second, _ := c.Groups(ctx, "alice")
	if want := []string{"a", "b"}; !reflect.DeepEqual(second, want) {
		t.Fatalf("cache entry mutated through returned slice: %v", second)
	}
}

func TestNewCachedZeroTTLBypasses(t *testing.T) {
	inner := &countingResolver{}
	if got := NewCached(inner, 0); got != Resolver(inner) {
		t.Fatal("NewCached with zero TTL should return the inner resolver unwrapped")
	}
}
