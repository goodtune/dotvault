// Package vaulttest provides a shared Vault dev server via testcontainers
// for use in unit and integration tests.
//
// Usage in TestMain:
//
//	func TestMain(m *testing.M) {
//	    ctx := context.Background()
//	    vc, cleanup, err := vaulttest.Start(ctx)
//	    if err != nil {
//	        log.Fatalf("start vault: %v", err)
//	    }
//	    defer cleanup()
//	    vaultClient = vc        // package-level var
//	    os.Exit(m.Run())
//	}
package vaulttest

import (
	"context"
	"fmt"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// DevRootToken is the root token used for the Vault dev server.
	DevRootToken = "test-root-token"

	// Image is the Docker image used for the Vault dev server.
	Image = "hashicorp/vault:1.19"
)

// Start launches a Vault dev server in a container and returns a connected
// client, a cleanup function, and any error. The caller must invoke cleanup
// when done (typically via defer in TestMain).
func Start(ctx context.Context) (*vault.Client, func(), error) {
	req := testcontainers.ContainerRequest{
		Image:        Image,
		ExposedPorts: []string{"8200/tcp"},
		Env: map[string]string{
			"VAULT_DEV_ROOT_TOKEN_ID": DevRootToken,
			"VAULT_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
		},
		Cmd: []string{"server", "-dev"},
		WaitingFor: wait.ForHTTP("/v1/sys/health").
			WithPort("8200/tcp").
			WithStartupTimeout(30 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("start vault container: %w", err)
	}

	cleanup := func() {
		_ = container.Terminate(context.Background())
	}

	host, err := container.Host(ctx)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("get container host: %w", err)
	}

	port, err := container.MappedPort(ctx, "8200/tcp")
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("get mapped port: %w", err)
	}

	addr := fmt.Sprintf("http://%s:%s", host, port.Port())

	vc, err := vault.NewClient(vault.Config{
		Address: addr,
		Token:   DevRootToken,
	})
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("create vault client: %w", err)
	}

	// Verify connectivity.
	if _, err := vc.LookupSelf(ctx); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("vault not ready: %w", err)
	}

	return vc, cleanup, nil
}
