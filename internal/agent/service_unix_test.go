//go:build !windows

package agent

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

// TestServiceRunFanOut covers the multi-endpoint fan-out introduced for the
// Windows Pageant pipe, exercised here over two Unix sockets (the Pageant
// branch itself is Windows-only). It confirms Run supervises one listener per
// endpoint, both share the single backend (the same identity is served on
// both), and ctx cancellation stops every goroutine so Run returns.
func TestServiceRunFanOut(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "primary", "agent.sock")
	secondary := filepath.Join(dir, "secondary", "agent.sock")

	_, _, pub, signer := genEd25519(t, "shared")
	src := &fakeSource{name: "a", ids: []Identity{{PubKey: pub, Comment: "shared"}}, signer: signer}
	backend := NewBackend([]Source{src})

	svc := &Service{
		Backend:   backend,
		addr:      primary,
		endpoints: []string{primary, secondary},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()

	// Both endpoints must come up and serve the shared backend's identity.
	for _, sock := range []string{primary, secondary} {
		waitForSocket(t, sock)
		conn, err := dialEndpoint(ctx, sock)
		if err != nil {
			t.Fatalf("dial %s: %v", sock, err)
		}
		keys, err := agent.NewClient(conn).List()
		conn.Close()
		if err != nil {
			t.Fatalf("List on %s: %v", sock, err)
		}
		if len(keys) != 1 {
			t.Errorf("endpoint %s served %d keys, want 1 (shared backend)", sock, len(keys))
		}
	}

	// Cancellation must stop every listener goroutine; Run returns once all
	// have drained (the WaitGroup join).
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Service.Run did not return after ctx cancel")
	}
}
