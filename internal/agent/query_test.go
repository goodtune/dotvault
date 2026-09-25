//go:build !windows

package agent

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

// TestKeysToStatusesUnparseableBlob covers the defensive branch: a daemon that
// advertises a key whose blob the client can't parse must surface a placeholder
// line, not silently drop it. Hard to reach via a real listener (the backend
// only serves well-formed blobs), so exercised directly on the pure helper.
func TestKeysToStatusesUnparseableBlob(t *testing.T) {
	_, _, pub, _ := genEd25519(t, "good")
	keys := []*agent.Key{
		{Format: "garbage", Blob: []byte("not a valid public key"), Comment: "broken"},
		{Format: pub.Type(), Blob: pub.Marshal(), Comment: "fine"},
	}
	got := keysToStatuses(keys)
	if len(got) != 2 {
		t.Fatalf("want 2 statuses, got %d", len(got))
	}
	if !strings.HasPrefix(got[0].Fingerprint, "(unparseable:") {
		t.Errorf("unparseable blob should be surfaced as a placeholder, got %q", got[0].Fingerprint)
	}
	if got[0].Comment != "broken" {
		t.Errorf("placeholder should retain the comment, got %q", got[0].Comment)
	}
	if !strings.HasPrefix(got[1].Fingerprint, "SHA256:") {
		t.Errorf("well-formed key should fingerprint normally, got %q", got[1].Fingerprint)
	}
}

// TestQueryListeningRoundTrip stands up a real listener backed by fake sources,
// then uses QueryListening (the dotvault status path) to list what the "daemon"
// serves — proving status observes the live endpoint rather than re-deriving
// from config. The cert identity's parsed expiry confirms the blob round-trips
// its true validity from the wire.
func TestQueryListeningRoundTrip(t *testing.T) {
	dir := sockTempDir(t)
	sock := filepath.Join(dir, "agent.sock")

	_, _, pub, signer := genEd25519(t, "laptop")
	kvSrc := &fakeSource{name: "kv", ids: []Identity{{PubKey: pub, Comment: "users/alice/ssh/laptop"}}, signer: signer}

	ca := newFakeCA(t)
	caSrc, err := newVaultCASource("vault-ca:dotvault-user", ca, "ssh", "dotvault-user", nil, "alice", 15*time.Minute, true)
	if err != nil {
		t.Fatalf("newVaultCASource: %v", err)
	}

	backend := NewBackend([]Source{kvSrc, caSrc})
	ln := NewListener(sock, backend)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- ln.Serve(ctx) }()
	waitForSocket(t, sock)

	ids, err := QueryListening(context.Background(), sock)
	if err != nil {
		t.Fatalf("QueryListening: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("want 2 identities, got %d: %+v", len(ids), ids)
	}

	var sawKey, sawCert bool
	for _, id := range ids {
		if id.Comment == "users/alice/ssh/laptop" {
			sawKey = true
			if id.IsCert {
				t.Errorf("plain key reported as cert: %+v", id)
			}
		}
		if id.IsCert {
			sawCert = true
			// The expiry must be recovered from the advertised cert blob, not
			// from config — proving the live-validity claim.
			if id.ExpiresAt == "" || id.TTLSeconds <= 0 {
				t.Errorf("cert identity missing live expiry/ttl: %+v", id)
			}
			// The comment survives the round trip through the agent
			// protocol verbatim, so this pins the exact string a user
			// sees in `ssh-add -l` / `dotvault status` — source name
			// plus the user the certificate was minted for.
			if want := "vault-ca:dotvault-user - by dotvault for alice"; id.Comment != want {
				t.Errorf("cert comment = %q, want %q", id.Comment, want)
			}
		}
		if id.Fingerprint == "" {
			t.Errorf("identity missing fingerprint: %+v", id)
		}
	}
	if !sawKey || !sawCert {
		t.Errorf("expected both the KV key and the cert; sawKey=%v sawCert=%v", sawKey, sawCert)
	}

	cancel()
	<-errCh
}

// TestQueryListeningUnreachable confirms a dial against a non-existent endpoint
// returns an error (which the status command surfaces as "unexpected") rather
// than blocking or creating the socket.
func TestQueryListeningUnreachable(t *testing.T) {
	dir := sockTempDir(t)
	sock := filepath.Join(dir, "nonexistent.sock")

	if _, err := QueryListening(context.Background(), sock); err == nil {
		t.Fatalf("expected an error dialling a non-existent endpoint")
	}
	// And it must NOT have created the socket — status never stands up a listener.
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("QueryListening created %s; it must never create the endpoint", sock)
	}
}

// TestQueryListeningUnresponsiveEndpoint is the regression test for the hang
// reported against a socket-activated daemon: the endpoint exists and accepts
// (systemd holds the listening fd, so connect() completes into its backlog
// whether or not anything reads), but no reply ever comes because the daemon
// is still waiting for a Vault token it cannot obtain. Bounding only the dial
// left `dotvault status` blocked in List() until Ctrl+C. The whole exchange
// must be bounded, so the query returns an error instead.
//
// The listener here accepts and then does nothing, which is exactly what an
// unaccepted systemd backlog looks like from the client's side.
func TestQueryListeningUnresponsiveEndpoint(t *testing.T) {
	dir := sockTempDir(t)
	sock := filepath.Join(dir, "silent.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Hold the connection open and never speak the agent protocol.
		accepted <- conn
	}()

	// A caller deadline shorter than queryTimeout wins, keeping the test quick
	// while exercising the same code path.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := QueryListening(ctx, sock)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from an endpoint that accepts but never replies")
		}
	// Comfortably clear of queryTimeout: a guard equal to the budget would
	// race it and flake if caller-deadline propagation ever regressed.
	case <-time.After(3 * queryTimeout):
		t.Fatal("QueryListening blocked on a connected but silent endpoint; the agent-protocol exchange is unbounded")
	}

	select {
	case conn := <-accepted:
		conn.Close()
	default:
	}
}

// TestQueryListeningHonoursCallerCancellation confirms Ctrl+C (a cancelled
// parent context) unblocks the query rather than waiting out queryTimeout.
func TestQueryListeningHonoursCallerCancellation(t *testing.T) {
	dir := sockTempDir(t)
	sock := filepath.Join(dir, "silent2.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	// Hold the accepted conn open for the life of the test without parking a
	// goroutine on a timer that outlives it.
	held := make(chan net.Conn, 1)
	go func() {
		if conn, err := ln.Accept(); err == nil {
			held <- conn
		}
	}()
	t.Cleanup(func() {
		select {
		case conn := <-held:
			conn.Close()
		default:
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := QueryListening(ctx, sock)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error after the caller cancelled")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("QueryListening ignored caller cancellation")
	}
}
