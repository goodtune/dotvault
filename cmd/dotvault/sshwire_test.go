package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/sshfwd"
)

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

// TestSSHForwardDepsRequiresLocalAPISurface asserts the second precondition:
// neither a local API socket nor the web UI configured means there is
// nothing for a managed forward to expose on the far end.
func TestSSHForwardDepsRequiresLocalAPISurface(t *testing.T) {
	cfg := &config.Config{
		Agent: config.AgentConfig{Enabled: true},
	}

	_, err := sshForwardDeps(cfg, nil, "alice")
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
func TestSSHForwardDepsPrefersAPISocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "api.sock")
	cfg := &config.Config{
		Agent: config.AgentConfig{Enabled: true},
		API:   config.APIConfig{Enabled: true, Unix: config.APIUnixConfig{Path: socketPath}},
		Web:   config.WebConfig{Enabled: true, Listen: "127.0.0.1:9000"},
	}

	deps, err := sshForwardDeps(cfg, nil, "alice")
	if err != nil {
		t.Fatalf("sshForwardDeps: %v", err)
	}
	if deps.TargetName != socketPath {
		t.Errorf("TargetName = %q, want the api socket path %q (socket must be preferred over the TCP listener)", deps.TargetName, socketPath)
	}
}

// TestSSHForwardDepsFallsBackToWebListen: with the local API socket off and
// the web UI on, the TCP listener is the only surface available and must be
// used.
func TestSSHForwardDepsFallsBackToWebListen(t *testing.T) {
	cfg := &config.Config{
		Agent: config.AgentConfig{Enabled: true},
		Web:   config.WebConfig{Enabled: true, Listen: "127.0.0.1:9000"},
	}

	deps, err := sshForwardDeps(cfg, nil, "alice")
	if err != nil {
		t.Fatalf("sshForwardDeps: %v", err)
	}
	if deps.TargetName != cfg.Web.Listen {
		t.Errorf("TargetName = %q, want the web listen address %q", deps.TargetName, cfg.Web.Listen)
	}
}

// TestSSHForwardDepsPolicyCarriesCAsAndPin verifies that both the
// admin-owned SSH config section (certificate_authorities) and a per-remote
// pin (Remote.HostKey) reach the HostKeyPolicy the returned Deps.Policy
// builds — the two trust inputs a connection attempt actually checks against.
func TestSSHForwardDepsPolicyCarriesCAsAndPin(t *testing.T) {
	ca := "@cert-authority * ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBOGY visitor"
	cfg := &config.Config{
		Agent: config.AgentConfig{Enabled: true},
		Web:   config.WebConfig{Enabled: true, Listen: "127.0.0.1:9000"},
		SSH:   config.SSHConfig{CertificateAuthorities: []string{ca}},
	}

	deps, err := sshForwardDeps(cfg, nil, "alice")
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
