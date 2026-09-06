//go:build !windows

package agent

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh/agent"
)

// isolateDiscovery points every environment-derived discovery input at a
// caller-owned temp tree, so a scan sees only what the test put there. Without
// it a developer machine's real ssh-agent (its /tmp socket, its SSH_AUTH_SOCK)
// joins the results and the assertions become machine-dependent.
//
// It returns the runtime dir, which is where a test places the agent it wants
// discovered.
func isolateDiscovery(t *testing.T) string {
	t.Helper()
	rt := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", rt)
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())
	tempAgentGlobsOverride = func() []string { return nil }
	t.Cleanup(func() { tempAgentGlobsOverride = nil })
	return rt
}

// serveBackendAt serves a real dotvault Backend over a Unix socket, which is
// what makes the loop-guard tests meaningful: the thing discovery must refuse
// to delegate to is this daemon, and only a real Backend answers the
// IDExtension probe the way one does.
func serveBackendAt(t *testing.T, sock string, b *Backend) {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = agent.ServeAgent(b, c)
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
}

func TestDiscoverFindsRuntimeDirAgents(t *testing.T) {
	rt := isolateDiscovery(t)
	priv, _ := genUpstreamKey(t)
	serveUpstreamAgentAt(t, filepath.Join(rt, "ssh-agent.socket"), priv)
	if err := os.MkdirAll(filepath.Join(rt, "gnupg"), 0o700); err != nil {
		t.Fatal(err)
	}
	gpg := filepath.Join(rt, "gnupg", "S.gpg-agent.ssh")
	serveUpstreamAgentAt(t, gpg, priv)

	got := discoverUpstreamEndpoints(context.Background(), nil, dialEndpoint)
	want := []string{filepath.Join(rt, "ssh-agent.socket"), gpg}
	if len(got) != len(want) {
		t.Fatalf("discovered %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("discovered[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDiscoverPrefersSSHAuthSock(t *testing.T) {
	rt := isolateDiscovery(t)
	priv, _ := genUpstreamKey(t)
	serveUpstreamAgentAt(t, filepath.Join(rt, "ssh-agent.socket"), priv)
	primary := filepath.Join(t.TempDir(), "primary.sock")
	serveUpstreamAgentAt(t, primary, priv)
	t.Setenv("SSH_AUTH_SOCK", primary)

	got := discoverUpstreamEndpoints(context.Background(), nil, dialEndpoint)
	if len(got) == 0 || got[0] != primary {
		t.Errorf("discovered %v, want $SSH_AUTH_SOCK (%q) first", got, primary)
	}
}

func TestDiscoverSkipsNonSockets(t *testing.T) {
	rt := isolateDiscovery(t)
	// A regular file where an agent socket would be must never be dialled.
	if err := os.WriteFile(filepath.Join(rt, "ssh-agent.socket"), []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := discoverUpstreamEndpoints(context.Background(), nil, dialEndpoint); len(got) != 0 {
		t.Errorf("discovered %v, want nothing (the path is a regular file)", got)
	}
}

// TestDiscoverExcludesOwnEndpointByPath is the cheap half of the loop guard:
// an endpoint this daemon serves, named exactly, is dropped before anything is
// dialled.
func TestDiscoverExcludesOwnEndpointByPath(t *testing.T) {
	rt := isolateDiscovery(t)
	self := filepath.Join(rt, "ssh-agent.socket")
	priv, _ := genUpstreamKey(t)
	serveUpstreamAgentAt(t, self, priv)

	if got := discoverUpstreamEndpoints(context.Background(), []string{self}, dialEndpoint); len(got) != 0 {
		t.Errorf("discovered %v, want nothing (that endpoint is ours)", got)
	}
}

// TestDiscoverExcludesOwnEndpointByProbe is the half that matters in practice.
// Once a user points SSH_AUTH_SOCK at dotvault — the entire purpose of the
// arrangement — the top discovery candidate IS dotvault, reached by a path
// (here a symlink) that never string-equals the one we bound. Delegating to it
// would recurse until the listener ran out of connections, so the daemon has
// to recognise itself over the wire.
func TestDiscoverExcludesOwnEndpointByProbe(t *testing.T) {
	rt := isolateDiscovery(t)
	real := filepath.Join(t.TempDir(), "dotvault-agent.sock")
	serveBackendAt(t, real, NewBackend(nil))

	// A different path to the same daemon, which no amount of string
	// comparison against `real` would catch.
	link := filepath.Join(rt, "ssh-agent.socket")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	t.Setenv("SSH_AUTH_SOCK", link)

	// Deliberately NOT passing `real` as an exclusion: the probe alone must
	// be enough.
	if got := discoverUpstreamEndpoints(context.Background(), nil, dialEndpoint); len(got) != 0 {
		t.Errorf("discovered %v, want nothing (every path leads back to this daemon)", got)
	}
}

// TestDiscoverKeepsForeignAgents confirms the probe rejects only *us*: a
// genuine third-party agent answers SSH_AGENT_FAILURE to the identity
// extension, which must read as "not dotvault", not as "unusable".
func TestDiscoverKeepsForeignAgents(t *testing.T) {
	rt := isolateDiscovery(t)
	priv, _ := genUpstreamKey(t)
	sock := filepath.Join(rt, "ssh-agent.socket")
	serveUpstreamAgentAt(t, sock, priv)

	got := discoverUpstreamEndpoints(context.Background(), nil, dialEndpoint)
	if len(got) != 1 || got[0] != sock {
		t.Errorf("discovered %v, want [%q]", got, sock)
	}
}

func TestBackendExtensionAnswersIdentityProbe(t *testing.T) {
	b := NewBackend(nil)
	reply, err := b.Extension(IDExtension, nil)
	if err != nil {
		t.Fatalf("Extension(%s): %v", IDExtension, err)
	}
	if string(reply) != string(processAgentID) || len(reply) == 0 {
		t.Errorf("Extension reply = %q, want this process's agent ID", reply)
	}
	// Everything else stays unsupported: extensions are not proxied, and some
	// (session-bind@openssh.com) would be a lie if they were.
	if _, err := b.Extension("session-bind@openssh.com", nil); err != agent.ErrExtensionUnsupported {
		t.Errorf("unknown extension err = %v, want ErrExtensionUnsupported", err)
	}
}
