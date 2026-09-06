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
// that never string-equals the one we bound. Delegating to it would recurse
// until the listener ran out of connections, so the daemon has to recognise
// itself over the wire.
//
// The daemon is reached here through a SECOND REAL LISTENER on the same
// backend, not a symlink. That distinction is the test: an earlier version
// used a symlink and passed vacuously, because the ownership pre-filter
// rejected it before any dial and the probe never ran at all. Two genuine
// sockets leave the wire probe as the only thing that can tell them apart.
func TestDiscoverExcludesOwnEndpointByProbe(t *testing.T) {
	rt := isolateDiscovery(t)
	backend := NewBackend(nil)

	bound := filepath.Join(t.TempDir(), "dotvault-agent.sock")
	serveBackendAt(t, bound, backend)

	// A second, independent socket served by the same daemon — the shape an
	// SSH RemoteForward or a bind mount produces.
	alsoUs := filepath.Join(rt, "ssh-agent.socket")
	serveBackendAt(t, alsoUs, backend)
	t.Setenv("SSH_AUTH_SOCK", alsoUs)

	// Only the bound path is declared as ours. The other is a different file
	// entirely, so no amount of path comparison can exclude it.
	got := discoverUpstreamEndpoints(context.Background(), []string{bound}, dialEndpoint)
	if len(got) != 0 {
		t.Errorf("discovered %v, want nothing — every endpoint is served by this daemon", got)
	}
}

// TestDiscoverProbeIsWhatExcludesSelf pins the previous test against going
// vacuous again: with the identity probe disabled, the same setup must yield
// the endpoint, proving the probe is doing the work rather than some earlier
// filter quietly dropping it.
func TestDiscoverProbeIsWhatExcludesSelf(t *testing.T) {
	rt := isolateDiscovery(t)
	backend := NewBackend(nil)
	bound := filepath.Join(t.TempDir(), "dotvault-agent.sock")
	serveBackendAt(t, bound, backend)
	alsoUs := filepath.Join(rt, "ssh-agent.socket")
	serveBackendAt(t, alsoUs, backend)

	saved := processAgentID
	processAgentID = nil // the documented "probe cannot run" degradation
	t.Cleanup(func() { processAgentID = saved })

	got := discoverUpstreamEndpoints(context.Background(), []string{bound}, dialEndpoint)
	if len(got) != 1 || got[0] != alsoUs {
		t.Fatalf("discovered %v, want [%q]: without the probe nothing else excludes it", got, alsoUs)
	}
}

// TestDiscoverFollowsSymlinkedSocket covers the candidate shape that matters
// most in practice and that an Lstat-based check silently dropped: the tmux
// convention points SSH_AUTH_SOCK at a stable symlink, and 1Password documents
// one on macOS. The user's real agent must be found through it.
func TestDiscoverFollowsSymlinkedSocket(t *testing.T) {
	rt := isolateDiscovery(t)
	priv, _ := genUpstreamKey(t)
	real := filepath.Join(t.TempDir(), "real-agent.sock")
	serveUpstreamAgentAt(t, real, priv)

	link := filepath.Join(rt, "ssh-agent.socket")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	got := discoverUpstreamEndpoints(context.Background(), nil, dialEndpoint)
	if len(got) != 1 || got[0] != link {
		t.Errorf("discovered %v, want the symlinked agent [%q]", got, link)
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
