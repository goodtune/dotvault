//go:build !windows

package agent

import (
	"context"
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

var _ = ssh.FingerprintSHA256

// TestQueryListeningRoundTrip stands up a real listener backed by a fake
// source, then uses QueryListening (the dotvault status path) to list what the
// "daemon" serves — proving status observes the live endpoint rather than
// re-deriving from config. The cert identity's parsed expiry confirms the blob
// round-trips its true validity.
func TestQueryListeningRoundTrip(t *testing.T) {
	dir := t.TempDir()
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
	dir := t.TempDir()
	sock := filepath.Join(dir, "nonexistent.sock")

	if _, err := QueryListening(context.Background(), sock); err == nil {
		t.Fatalf("expected an error dialling a non-existent endpoint")
	}
	// And it must NOT have created the socket — status never stands up a listener.
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("QueryListening created %s; it must never create the endpoint", sock)
	}
}
