package integration

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/vault"
)

// TestLifecycleRecoversFromExpiredToken exercises the full
// expire-and-recover cycle described in the design notes:
//
//  1. Mint a short-lived token via the dev Vault and load it onto the
//     client. Start the lifecycle manager pointing at a writable token
//     file.
//  2. Let the token expire — the next lookup-self returns 403 and the
//     manager should signal re-auth (the OnReauth callback fires and the
//     in-memory client token is cleared by the daemon path).
//  3. Mint a fresh token via the same parent and write it to the token
//     file out-of-band — as if an interactive `dotvault login` had run.
//  4. The manager's next check should observe the broken state, reload
//     the new token from disk, swap it in, and clear needs-reauth.
//
// This guards against the regression the spec calls out: that a daemon
// would previously latch its broken token and require a restart to pick
// up a freshly-minted credential even when one was available on disk.
func TestLifecycleRecoversFromExpiredToken(t *testing.T) {
	skipIfNoVault(t)

	rootClient, err := vault.NewClient(vault.Config{
		Address: "http://127.0.0.1:8200",
		Token:   "dev-root-token",
	})
	if err != nil {
		t.Fatalf("NewClient (root): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mintShortToken := func(t *testing.T, ttl string) string {
		t.Helper()
		secret, err := rootClient.Raw().Auth().Token().CreateWithContext(ctx, &vaultapi.TokenCreateRequest{
			TTL:       ttl,
			Renewable: boolPtr(false),
			NoParent:  true,
		})
		if err != nil {
			t.Fatalf("token create: %v", err)
		}
		if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
			t.Fatal("token create: empty auth response")
		}
		return secret.Auth.ClientToken
	}

	initialToken := mintShortToken(t, "2s")

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".vault-token")
	if err := os.WriteFile(tokenPath, []byte(initialToken), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	vc, err := vault.NewClient(vault.Config{
		Address: "http://127.0.0.1:8200",
		Token:   initialToken,
	})
	if err != nil {
		t.Fatalf("NewClient (daemon): %v", err)
	}

	lm := auth.NewLifecycleManager(vc, 250*time.Millisecond, false)
	lm.SetTokenFilePath(tokenPath)

	var reauthFired atomic.Int64
	lm.SetOnReauth(func() {
		reauthFired.Add(1)
		// The web server clears the in-memory token here in production;
		// mirror that behaviour so the test verifies the same observable
		// state the SPA would see (vc.Token() returns "" → status reports
		// authenticated=false).
		vc.SetToken("")
	})

	loopCtx, loopCancel := context.WithCancel(ctx)
	defer loopCancel()
	errCh := lm.Start(loopCtx)
	go func() {
		for range errCh {
		}
	}()

	// 1. Wait for the token to expire and the manager to detect it.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if reauthFired.Load() > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if reauthFired.Load() == 0 {
		t.Fatal("lifecycle manager never signalled re-auth after token expiry")
	}
	if got := vc.Token(); got != "" {
		t.Fatalf("client token = %q after expiry, want cleared (\"\") via OnReauth", got)
	}

	// 2. Mint a fresh token (longer TTL so it survives the rest of the test)
	//    and write it to the token file out-of-band.
	newToken := mintShortToken(t, "1h")
	if newToken == initialToken {
		t.Fatal("freshly-minted token equals expired token — should be different")
	}
	if err := os.WriteFile(tokenPath, []byte(newToken), 0600); err != nil {
		t.Fatalf("write new token file: %v", err)
	}

	// 3. The manager polls at 250ms while in the broken state — it
	//    should reload the token and recover within a couple of cycles.
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if vc.Token() == newToken && !lm.NeedsReauth() {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}

	if got := vc.Token(); got != newToken {
		t.Fatalf("client token = %q after recovery window, want %q", got, newToken)
	}
	if lm.NeedsReauth() {
		t.Error("NeedsReauth() = true after successful recovery from token file")
	}
}

func boolPtr(b bool) *bool { return &b }
