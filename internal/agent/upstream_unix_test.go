//go:build !windows

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// genUpstreamKey returns a fresh ed25519 private key and its ssh.PublicKey.
func genUpstreamKey(t *testing.T) (ed25519.PrivateKey, ssh.PublicKey) {
	t.Helper()
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub, err := ssh.NewPublicKey(pk)
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}
	return sk, pub
}

// serveUpstreamAgent stands up an in-memory ssh-agent keyring over a Unix
// socket and returns its path. Each accepted connection is serviced by
// agent.ServeAgent until the listener closes, matching how upstreamSource dials
// a fresh connection per operation.
func serveUpstreamAgent(t *testing.T, keys ...ed25519.PrivateKey) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "upstream.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	keyring := agent.NewKeyring()
	for _, k := range keys {
		// ed25519.PrivateKey satisfies crypto.Signer, which ssh.NewSignerFromKey
		// (called by the keyring) accepts directly.
		if err := keyring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatalf("keyring add: %v", err)
		}
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Close the server-side fd when the client disconnects:
			// agent.ServeAgent returns on EOF but does not close the conn
			// itself, so leaving it open would leak fds across the many
			// per-operation dials these tests make.
			go func(c net.Conn) {
				defer c.Close()
				_ = agent.ServeAgent(keyring, c)
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return sock
}

func TestUpstreamSourceListAndSign(t *testing.T) {
	priv, pub := genUpstreamKey(t)
	sock := serveUpstreamAgent(t, priv)

	src := newUpstreamSource("agent:"+sock, sock)
	ctx := context.Background()

	ids, err := src.Identities(ctx)
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("want 1 identity, got %d", len(ids))
	}
	if !keyEqual(ids[0].PubKey, pub) {
		t.Errorf("advertised key does not match the upstream key")
	}

	data := []byte("sign me")
	sig, matched, err := src.Sign(ctx, pub, data, 0)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !matched {
		t.Fatalf("Sign should have matched the upstream key")
	}
	if err := pub.Verify(data, sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}

func TestUpstreamSourceSignFallthrough(t *testing.T) {
	priv, _ := genUpstreamKey(t)
	sock := serveUpstreamAgent(t, priv)

	// A key the upstream does not hold must fall through (matched=false, no
	// error) so the backend can try the next source.
	_, otherPub := genUpstreamKey(t)
	_, matched, err := newUpstreamSource("agent", sock).Sign(context.Background(), otherPub, []byte("x"), 0)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if matched {
		t.Errorf("Sign should not have matched a foreign key")
	}
}

func TestUpstreamSourceUnreachable(t *testing.T) {
	// A socket that nobody serves: Identities surfaces the dial error so status
	// can report the upstream as unreachable.
	src := newUpstreamSource("agent", filepath.Join(t.TempDir(), "nope.sock"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := src.Identities(ctx); err == nil {
		t.Errorf("Identities should error when the upstream is unreachable")
	}
}

func TestUpstreamSourceType(t *testing.T) {
	if got := newUpstreamSource("agent", "/x").Type(); got != "agent" {
		t.Errorf("Type() = %q, want agent", got)
	}
}

// TestUpstreamSourceDialError confirms a dial failure is wrapped, not swallowed.
func TestUpstreamSourceDialError(t *testing.T) {
	src := &upstreamSource{
		name:     "agent",
		endpoint: "/x",
		dial: func(context.Context) (net.Conn, error) {
			return nil, errors.New("boom")
		},
	}
	if _, err := src.Identities(context.Background()); err == nil {
		t.Errorf("want dial error from Identities")
	}
	if _, _, err := src.Sign(context.Background(), nil, nil, 0); err == nil {
		t.Errorf("want dial error from Sign")
	}
}
