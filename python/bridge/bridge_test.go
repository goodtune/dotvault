//go:build cgo

package main

// This test file is deliberately cgo-free: a _test.go may not import "C". It
// exercises the pure-Go helpers (categoryOf, the handle table, syncEnv) through
// the cgo-free seams in bridge.go (lookupID/dropID, cSetenv/cUnsetenv).

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/goodtune/dotvault/client"
)

func TestCategoryOf(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, catOK},
		{"login required", fmt.Errorf("wrap: %w", client.ErrLoginRequired), catLoginRequired},
		{"denied", fmt.Errorf("wrap: %w", client.ErrDenied), catDenied},
		{"unreachable", fmt.Errorf("wrap: %w", client.ErrUnreachable), catUnreachable},
		{"auth failed", fmt.Errorf("wrap: %w", client.ErrAuthFailed), catAuthFailed},
		{"unknown", errors.New("something else"), catOther},
		{"unknown handle", errUnknownHandle, catOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := categoryOf(tt.err); got != tt.want {
				t.Fatalf("categoryOf(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func TestHandleTableLifecycle(t *testing.T) {
	// store issues a positive handle and lookupID resolves it.
	c := &client.Client{}
	h := store(c)
	if h <= 0 {
		t.Fatalf("store returned non-positive handle %d", h)
	}
	got, ok := lookupID(h)
	if !ok || got != c {
		t.Fatalf("lookupID(%d) = %v, %v; want the stored client", h, got, ok)
	}

	// A second store issues a distinct handle (monotonic, never reused).
	h2 := store(&client.Client{})
	if h2 == h {
		t.Fatalf("store reused handle %d", h)
	}

	// dropID removes only the named handle.
	dropID(h)
	if _, ok := lookupID(h); ok {
		t.Fatalf("lookupID(%d) still resolves after drop", h)
	}
	if _, ok := lookupID(h2); !ok {
		t.Fatalf("dropID(%d) also removed unrelated handle %d", h, h2)
	}

	// An unknown handle never resolves.
	if _, ok := lookupID(h2 + 1000); ok {
		t.Fatal("lookupID resolved a never-issued handle")
	}
}

func TestSyncEnvReadsLiveCEnvironment(t *testing.T) {
	// The Go runtime snapshots env at init; syncEnv must reflect a value set in
	// the live C environment afterwards. Manipulate the C environment (as the
	// host process would) and confirm syncEnv propagates it into Go.
	cSetenv("DOTVAULT_TOKEN", "s.synced-token")
	t.Cleanup(func() { cUnsetenv("DOTVAULT_TOKEN") })

	syncEnv()
	if got := os.Getenv("DOTVAULT_TOKEN"); got != "s.synced-token" {
		t.Fatalf("after syncEnv, os env = %q, want the C-set value", got)
	}

	// Unsetting in C must propagate as an unset in Go, not a stale value.
	cUnsetenv("DOTVAULT_TOKEN")
	syncEnv()
	if got, ok := os.LookupEnv("DOTVAULT_TOKEN"); ok {
		t.Fatalf("after unset+syncEnv, os env still set to %q", got)
	}
}
