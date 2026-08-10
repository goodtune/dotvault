package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/sshfwd"
)

// shortSocketDir returns a short-lived directory under /tmp, cleaned up at
// test end, for a Unix socket path. t.TempDir() nests under a per-test
// directory whose length can exceed the ~103-byte sun_path limit depending
// on the host's $TMPDIR (observed on this host); a short fixed prefix avoids
// that without disabling the test.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	dir := filepath.Join("/tmp", "dv-"+hex.EncodeToString(b))
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir %q: %v", dir, err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// fakeSignerSource is a minimal, inert sshfwd.SignerSource: these tests
// never dial a real connection, so List/SignWithFlags are never actually
// invoked — it exists purely to satisfy sshForwardDeps' non-nil-backend
// precondition (see TestSSHForwardDepsRejectsNilBackend) with something
// other than nil.
type fakeSignerSource struct{}

func (fakeSignerSource) List() ([]*sshagent.Key, error) { return nil, nil }
func (fakeSignerSource) SignWithFlags(key ssh.PublicKey, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error) {
	return nil, nil
}

// TestSSHForwardDepsRequiresAgent asserts the agent.enabled precondition:
// with no agent, there is no SSH identity to sign with.
func TestSSHForwardDepsRequiresAgent(t *testing.T) {
	cfg := &config.Config{
		Web: config.WebConfig{Enabled: true, Listen: "127.0.0.1:9000"},
	}

	_, err := sshForwardDeps(cfg, nil, "alice")
	if err == nil {
		t.Fatal("sshForwardDeps returned nil error with agent.enabled false, want an error naming agent.enabled")
	}
	if !strings.Contains(err.Error(), "agent.enabled") {
		t.Errorf("error %q does not name agent.enabled", err)
	}
}

// TestSSHForwardDepsRejectsNilBackend covers M2: agent.enabled true but no
// backend supplied must fail construction rather than let a nil interface
// reach sshfwd.Signers, which would panic inside a background reconnect
// goroutine (a process crash) the first time a remote tried to dial.
func TestSSHForwardDepsRejectsNilBackend(t *testing.T) {
	cfg := &config.Config{
		Agent: config.AgentConfig{Enabled: true},
		Web:   config.WebConfig{Enabled: true, Listen: "127.0.0.1:9000"},
	}

	_, err := sshForwardDeps(cfg, nil, "alice")
	if err == nil {
		t.Fatal("sshForwardDeps returned nil error with a nil backend, want an error")
	}
	if !strings.Contains(err.Error(), "backend") {
		t.Errorf("error %q does not mention the missing backend", err)
	}
}

// TestSSHForwardDepsRequiresLocalAPISurface asserts the second precondition:
// neither a local API socket nor the web UI configured means there is
// nothing for a managed forward to expose on the far end.
func TestSSHForwardDepsRequiresLocalAPISurface(t *testing.T) {
	cfg := &config.Config{
		Agent: config.AgentConfig{Enabled: true},
	}

	_, err := sshForwardDeps(cfg, fakeSignerSource{}, "alice")
	if err == nil {
		t.Fatal("sshForwardDeps returned nil error with neither web nor api enabled, want an error naming both")
	}
	if !strings.Contains(err.Error(), "api.enabled") || !strings.Contains(err.Error(), "web.enabled") {
		t.Errorf("error %q does not name both api.enabled and web.enabled", err)
	}
}

// TestSSHForwardDepsPrefersAPISocket is the load-bearing exposure test: when
// both a local API socket and the web TCP listener are configured, the
// socket must win. The socket is 0600 inside a 0700 directory; the TCP
// listener accepts a connection from any uid on the box. A regression that
// silently prefers the TCP listener is a real exposure change, not a
// cosmetic default swap.
//
// It asserts both halves of that claim: the label (TargetName) AND the
// actual dialer (Target) land on the socket. Checking only the label would
// pass under a mutation that sets TargetName to the socket path while still
// dialling TCP — exactly the exposure regression this test exists to catch.
func TestSSHForwardDepsPrefersAPISocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		// cfg.APISocketPath() (via apiSocketCandidate) always returns "" on
		// Windows — there is no local API socket there yet — so the socket
		// branch this test exercises is unreachable on that platform. A
		// Windows daemon always forwards the loopback TCP listener instead;
		// that path is covered by TestSSHForwardDepsFallsBackToWebListen.
		t.Skip("local API socket is not supported on windows; see resolveAPISocket")
	}

	// t.TempDir() nests under a per-test directory long enough on some
	// hosts (this one included) to blow the ~103-byte sun_path limit for a
	// Unix socket; shortSocketDir sidesteps that the same way the other
	// socket-path-sensitive tests in this repo do.
	socketPath := filepath.Join(shortSocketDir(t), "api.sock")
	cfg := &config.Config{
		Agent: config.AgentConfig{Enabled: true},
		API:   config.APIConfig{Enabled: true, Unix: config.APIUnixConfig{Path: socketPath}},
		Web:   config.WebConfig{Enabled: true, Listen: "127.0.0.1:9000"},
	}

	deps, err := sshForwardDeps(cfg, fakeSignerSource{}, "alice")
	if err != nil {
		t.Fatalf("sshForwardDeps: %v", err)
	}
	if deps.TargetName != socketPath {
		t.Errorf("TargetName = %q, want the api socket path %q (socket must be preferred over the TCP listener)", deps.TargetName, socketPath)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on %q: %v", socketPath, err)
	}
	defer ln.Close()
	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			close(accepted)
			conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := deps.Target(ctx)
	if err != nil {
		t.Fatalf("deps.Target: %v", err)
	}
	defer conn.Close()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("deps.Target did not dial the api socket listener")
	}
}

// TestSSHForwardDepsFallsBackToWebListen: with the local API socket off and
// the web UI on, the TCP listener is the only surface available and must be
// used — both the label and the actual dial target.
func TestSSHForwardDepsFallsBackToWebListen(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	cfg := &config.Config{
		Agent: config.AgentConfig{Enabled: true},
		Web:   config.WebConfig{Enabled: true, Listen: ln.Addr().String()},
	}

	deps, err := sshForwardDeps(cfg, fakeSignerSource{}, "alice")
	if err != nil {
		t.Fatalf("sshForwardDeps: %v", err)
	}
	if deps.TargetName != cfg.Web.Listen {
		t.Errorf("TargetName = %q, want the web listen address %q", deps.TargetName, cfg.Web.Listen)
	}

	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			close(accepted)
			conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := deps.Target(ctx)
	if err != nil {
		t.Fatalf("deps.Target: %v", err)
	}
	defer conn.Close()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("deps.Target did not dial the web TCP listener")
	}
}

// TestSSHForwardDepsPolicyCarriesCAsAndPin verifies that both the
// admin-owned SSH config section (certificate_authorities) and a per-remote
// pin (Remote.HostKey) reach the HostKeyPolicy the returned Deps.Policy
// builds — the two trust inputs a connection attempt actually checks against.
//
// sshForwardDeps no longer stores cfg.SSH into the shared sshPolicyConfig
// itself (see its doc comment — that's startSSHForwards' job now), so this
// test seeds the atomic value explicitly and resets it afterwards, keeping
// this test's CA assertion unconfounded by any other test's global state.
func TestSSHForwardDepsPolicyCarriesCAsAndPin(t *testing.T) {
	prev := currentSSHPolicyConfig()
	t.Cleanup(func() { updateSSHPolicyConfig(prev) })

	ca := "@cert-authority * ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBOGY visitor"
	cfg := &config.Config{
		Agent: config.AgentConfig{Enabled: true},
		Web:   config.WebConfig{Enabled: true, Listen: "127.0.0.1:9000"},
		SSH:   config.SSHConfig{CertificateAuthorities: []string{ca}},
	}
	updateSSHPolicyConfig(cfg.SSH)

	deps, err := sshForwardDeps(cfg, fakeSignerSource{}, "alice")
	if err != nil {
		t.Fatalf("sshForwardDeps: %v", err)
	}

	remote := sshfwd.Remote{Host: "example.com", HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBOGY pinned"}
	policy := deps.Policy(remote)
	if policy == nil {
		t.Fatal("Policy returned nil")
	}
	if len(policy.CAs) != 1 || policy.CAs[0] != ca {
		t.Errorf("policy.CAs = %v, want [%q]", policy.CAs, ca)
	}
	if policy.Pinned != remote.HostKey {
		t.Errorf("policy.Pinned = %q, want %q", policy.Pinned, remote.HostKey)
	}
}

// TestStartSSHForwardsHappyPath is the direct unit analogue of the smoke
// test's stated expectation ("daemon starts; with no ssh.yaml present it
// reconciles zero remotes without complaint") that Task 15's manual smoke
// test could not exercise on this host. paths.SSHConfigPath resolves under
// $HOME/XDG_CONFIG_HOME, so pointing HOME at an empty temp directory gives a
// deterministic "no ssh.yaml" starting point without touching any real
// per-user state.
func TestStartSSHForwardsHappyPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	cfg := &config.Config{
		Agent: config.AgentConfig{Enabled: true},
		Web:   config.WebConfig{Enabled: true, Listen: "127.0.0.1:9000"},
	}

	mgr, registry, path := startSSHForwards(context.Background(), cfg, fakeSignerSource{}, "alice")
	if mgr == nil {
		t.Fatal("startSSHForwards returned a nil Manager on the happy path")
	}
	t.Cleanup(mgr.Close)
	if registry == nil {
		t.Fatal("startSSHForwards returned a nil Registry on the happy path")
	}
	if path == "" {
		t.Fatal("startSSHForwards returned an empty ssh.yaml path on the happy path")
	}
	if got := mgr.Status(); len(got) != 0 {
		t.Errorf("Status = %v, want empty — no ssh.yaml exists yet", got)
	}

	// The Registry must be backed by the same path and Manager: List sees
	// zero remotes (matching Status), and a subsequent Resync (as the
	// config-refresh loop performs) is a no-op against the same file.
	remotes, err := registry.List()
	if err != nil {
		t.Fatalf("registry.List: %v", err)
	}
	if len(remotes) != 0 {
		t.Errorf("registry.List() = %v, want empty", remotes)
	}
}

// TestStartSSHForwardsSkipsWithoutAgent and
// TestStartSSHForwardsSkipsWithoutLocalAPISurface cover the two
// precondition-failure paths through startSSHForwards itself (not just
// through sshForwardDeps): both must return a nil Manager/Registry so the
// daemon's "if sshManager != nil" wiring correctly skips the subsystem.
func TestStartSSHForwardsSkipsWithoutAgent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	cfg := &config.Config{
		Web: config.WebConfig{Enabled: true, Listen: "127.0.0.1:9000"},
	}

	mgr, registry, path := startSSHForwards(context.Background(), cfg, nil, "alice")
	if mgr != nil {
		t.Errorf("mgr = %v, want nil when agent.enabled is false", mgr)
	}
	if registry != nil {
		t.Errorf("registry = %v, want nil when agent.enabled is false", registry)
	}
	if path != "" {
		t.Errorf("path = %q, want empty when agent.enabled is false", path)
	}
}

func TestStartSSHForwardsSkipsWithoutLocalAPISurface(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	cfg := &config.Config{
		Agent: config.AgentConfig{Enabled: true},
	}

	mgr, registry, path := startSSHForwards(context.Background(), cfg, fakeSignerSource{}, "alice")
	if mgr != nil {
		t.Errorf("mgr = %v, want nil with neither api nor web enabled", mgr)
	}
	if registry != nil {
		t.Errorf("registry = %v, want nil with neither api nor web enabled", registry)
	}
	if path != "" {
		t.Errorf("path = %q, want empty with neither api nor web enabled", path)
	}
}
