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

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %s did not become connectable", path)
}

func TestUnixListenerServeRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "sub", "agent.sock")
	_, _, pub, signer := genEd25519(t, "a")
	src := &fakeSource{name: "a", ids: []Identity{{PubKey: pub, Comment: "a"}}, signer: signer}
	b := NewBackend([]Source{src})

	ln := NewListener(sock, b)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- ln.Serve(ctx) }()

	waitForSocket(t, sock)

	// Socket must be owner-only (0600), the directory 0700.
	if fi, err := os.Stat(sock); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("socket perm = %v, want 0600", fi.Mode().Perm())
	}
	if fi, err := os.Stat(filepath.Dir(sock)); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Errorf("dir perm = %v, want 0700", fi.Mode().Perm())
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(conn)
	keys, err := client.List()
	if err != nil {
		t.Fatalf("client List: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(keys))
	}
	data := []byte("challenge")
	sig, err := client.Sign(pub, data)
	if err != nil {
		t.Fatalf("client Sign: %v", err)
	}
	if err := pub.Verify(data, sig); err != nil {
		t.Errorf("verify: %v", err)
	}
	conn.Close()

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("Serve returned error on shutdown: %v", err)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("socket not cleaned up after shutdown")
	}
}

func TestUnixListenerStaleSocketRemoved(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	// A leftover plain file at the path: nothing is listening, so the
	// listener should remove it and bind successfully.
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	b := NewBackend(nil)
	ln := NewListener(sock, b)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- ln.Serve(ctx) }()
	waitForSocket(t, sock)
	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("Serve: %v", err)
	}
}

func TestUnixListenerAlreadyRunning(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	b := NewBackend(nil)

	ln1 := NewListener(sock, b)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- ln1.Serve(ctx) }()
	waitForSocket(t, sock)

	// A second listener on the same live socket must refuse rather than
	// clobber the running instance.
	ln2 := NewListener(sock, b)
	err := ln2.Serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Errorf("want already-running error, got %v", err)
	}

	cancel()
	<-errCh
}

func TestListenerCloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	b := NewBackend(nil)
	ln := NewListener(sock, b)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ln.Serve(ctx)
	waitForSocket(t, sock)
	if err := ln.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
