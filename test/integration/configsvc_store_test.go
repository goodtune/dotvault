package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/configsvc/store"
	"github.com/goodtune/dotvault/internal/configsvc/store/storetest"
	"github.com/goodtune/dotvault/internal/vault"
)

// TestConfigsvcVaultStore runs the store conformance suite against the
// docker-compose dev Vault. The base path is unique per run so repeated
// invocations don't see each other's layers.
func TestConfigsvcVaultStore(t *testing.T) {
	skipIfNoVault(t)
	ctx := context.Background()

	// Ensure the KVv2 mount exists. The error is deliberately ignored —
	// EnableKVv2 fails when the mount already exists, which is the normal
	// case on a long-running dev Vault (same pattern as the e2e test).
	vc, err := vault.NewClient(vault.Config{
		Address: "http://127.0.0.1:8200",
		Token:   "dev-root-token",
	})
	if err != nil {
		t.Skip("Vault not available")
	}
	_ = vc.EnableKVv2(ctx, "secret")

	st, err := store.OpenVault(ctx, store.VaultStoreConfig{
		Address: "http://127.0.0.1:8200",
		Mount:   "secret",
		Path:    fmt.Sprintf("dotvault-config-test/%d", time.Now().UnixNano()),
		Auth:    "token",
		Token:   "dev-root-token",
	})
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	defer st.Close()

	storetest.Run(t, st)
}
