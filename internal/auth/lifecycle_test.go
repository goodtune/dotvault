package auth

import (
	"context"
	"testing"
	"time"
)

func TestLifecycleManager_Start(t *testing.T) {
	skipIfNoVault(t)

	vc := mustVaultClient(t)
	vc.SetToken("dev-root-token")

	lm := NewLifecycleManager(vc, 1*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Start should not block
	errCh := lm.Start(ctx)

	// Should get at least one check cycle without error
	select {
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			t.Fatalf("lifecycle error: %v", err)
		}
	case <-time.After(2 * time.Second):
		// Good — no error within timeout
	}
}

func TestLifecycleManager_NeedsReauth(t *testing.T) {
	skipIfNoVault(t)

	vc := mustVaultClient(t)
	vc.SetToken("dev-root-token")

	lm := NewLifecycleManager(vc, 1*time.Second)

	// With a valid root token, should not need reauth
	if lm.NeedsReauth() {
		t.Error("NeedsReauth() = true for valid root token")
	}
}
