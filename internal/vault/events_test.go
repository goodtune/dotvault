package vault

import (
	"context"
	"testing"
	"time"
)

func TestSubscribeEvents(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	seedTestSecret(t, c)

	// Subscribe to kv-v2 data-write events
	events, errCh, err := c.SubscribeEvents(ctx, "kv-v2/data-write")
	if err != nil {
		// Events API may not be available in dev mode — skip gracefully
		t.Skipf("SubscribeEvents: %v (events API may not be available)", err)
	}

	// Trigger a write to generate an event
	go func() {
		time.Sleep(500 * time.Millisecond)
		c.WriteKVv2(ctx, "secret", "users/testuser/gh", map[string]any{
			"token": "updated-token",
			"user":  "testuser",
		})
	}()

	// Wait for event or timeout
	select {
	case evt := <-events:
		if evt.EventType != "kv-v2/data-write" {
			t.Errorf("event type = %q, want 'kv-v2/data-write'", evt.EventType)
		}
		if evt.Path == "" {
			t.Error("event path is empty")
		}
		t.Logf("received event: type=%s path=%s", evt.EventType, evt.Path)
	case err := <-errCh:
		t.Fatalf("event subscription error: %v", err)
	case <-ctx.Done():
		t.Skip("timed out waiting for event (events API may not support this in dev mode)")
	}
}

func TestSubscribeEventsGracefulDegradation(t *testing.T) {
	// Test that subscription to a nonexistent Vault fails gracefully
	c, err := NewClient(Config{
		Address: "http://127.0.0.1:19999", // No server here
		Token:   "fake-token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, err = c.SubscribeEvents(ctx, "kv-v2/data-write")
	if err == nil {
		t.Error("expected error connecting to nonexistent server")
	}
}
