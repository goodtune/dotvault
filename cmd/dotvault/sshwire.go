package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"

	"golang.org/x/crypto/ssh"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/sshfwd"
)

// sshPolicyConfig holds the live config.SSHConfig section (the admin-owned
// certificate_authorities list and insecure_ignore_host_key flag) that
// sshForwardDeps' Policy closure consults on every dial attempt.
//
// It is a package-level atomic value rather than something the closure
// captures by copy, specifically so the config-refresh loop can update it in
// place: the SSH section is classified dynamic (see
// TestStaticSectionsCoverConfig), and a changed CA list or a flipped
// insecure flag must apply to the very next connection attempt without a
// daemon restart. Deps.Policy is invoked once per connection attempt (see
// sshfwd.Deps' doc comment), so reading through this indirection on every
// call is exactly what makes that true.
var sshPolicyConfig atomic.Value // holds config.SSHConfig

// updateSSHPolicyConfig stores a freshly (re)loaded SSH config section for
// sshForwardDeps' Policy closure to pick up on the next connection attempt.
// Called once by sshForwardDeps itself at construction and again by the
// config-refresh loop whenever a reload finds cfg.SSH changed.
func updateSSHPolicyConfig(c config.SSHConfig) {
	sshPolicyConfig.Store(c)
}

// currentSSHPolicyConfig returns the most recently stored SSH config
// section, or the zero value (no CAs, host-key verification on) if nothing
// has been stored yet.
func currentSSHPolicyConfig() config.SSHConfig {
	c, _ := sshPolicyConfig.Load().(config.SSHConfig)
	return c
}

// sshForwardDeps builds the sshfwd.Deps the managed-SSH-forward subsystem
// needs: the SSH identity (drawn from the daemon's own agent backend), the
// dial target (dotvault's own local API), and the host-key policy driven by
// the live SSH config section (see sshPolicyConfig above).
//
// Two preconditions are enforced here, neither fatal to the daemon — a
// caller that gets a non-nil error logs a WARN naming the missing setting
// and skips the whole subsystem, exactly like every other optional daemon
// feature:
//
//   - agent.enabled: the SSH identity comes from the agent backend (the same
//     one that serves the SSH agent listener), so there is nothing to sign
//     with otherwise.
//   - a local API surface: api.enabled (a per-user Unix socket) or
//     web.enabled (a loopback TCP listener). The whole point of a managed
//     forward is exposing dotvault's own API on the far end, and without
//     either there is no API to expose.
//
// When both surfaces are configured, the Unix socket is preferred: it is
// 0600 inside a 0700 directory, while the TCP listener accepts connections
// from any uid on the box. Getting this backwards would be a real exposure
// regression, not a cosmetic default — see TestSSHForwardDepsPrefersAPISocket.
//
// This function is deliberately a pure construction: it does not itself call
// updateSSHPolicyConfig. An earlier version did, which made it a "builder"
// with a hidden global side effect — every caller (including every test)
// silently rewrote package state, which prevented t.Parallel() and left at
// least one test unable to tell whether a value it observed came from its
// own argument or from the global the same call had just set. startSSHForwards,
// the one production caller, owns seeding sshPolicyConfig instead.
func sshForwardDeps(cfg *config.Config, backend sshfwd.SignerSource, username string) (sshfwd.Deps, error) {
	if !cfg.Agent.Enabled {
		return sshfwd.Deps{}, fmt.Errorf("managed SSH forwards require agent.enabled (the SSH identity is drawn from the agent backend)")
	}
	if backend == nil {
		// Unreachable in production today — main.go only calls this with a
		// non-nil backend when agent.Enabled is true (agentSvc.Backend is
		// constructed alongside it) — but a nil backend reaching
		// sshfwd.Signers would call List() on a nil interface: a panic
		// inside a background reconnect goroutine, i.e. a process crash.
		// Checking here makes the agent.enabled <-> non-nil-backend coupling
		// structural instead of relying on main.go never getting it wrong.
		return sshfwd.Deps{}, fmt.Errorf("managed SSH forwards require a non-nil agent backend (agent.enabled is true but no backend was supplied)")
	}

	apiSocketPath, err := cfg.APISocketPath()
	if err != nil {
		return sshfwd.Deps{}, fmt.Errorf("resolve api.unix.path: %w", err)
	}

	var (
		targetName string
		target     sshfwd.Dialer
	)
	switch {
	case apiSocketPath != "":
		// Preferred: the per-user Unix socket is 0600 inside a 0700
		// directory (see internal/web's local API socket doc comments).
		targetName = apiSocketPath
		target = func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", apiSocketPath)
		}
	case cfg.Web.Enabled:
		// Fallback only: the loopback TCP listener accepts a connection
		// from any uid on the box, so this is a strictly weaker surface
		// than the socket above.
		targetName = cfg.Web.Listen
		target = func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", cfg.Web.Listen)
		}
	default:
		return sshfwd.Deps{}, fmt.Errorf("managed SSH forwards require a local API surface: enable api.enabled (preferred) or web.enabled")
	}

	return sshfwd.Deps{
		Signers:    func() ([]ssh.Signer, error) { return sshfwd.Signers(backend) },
		User:       func() (string, error) { return username, nil },
		Target:     target,
		TargetName: targetName,
		Policy: func(r sshfwd.Remote) *sshfwd.HostKeyPolicy {
			// A fresh *HostKeyPolicy every call deliberately does not reuse
			// HostKeyPolicy's own CA-parse cache across dials (see its doc
			// comment in hostkey.go): a cached policy could not pick up a
			// reloaded CA list, and re-parsing on each attempt is cheap at
			// dial frequency.
			cur := currentSSHPolicyConfig()
			return &sshfwd.HostKeyPolicy{
				CAs:      cur.CertificateAuthorities,
				Pinned:   r.HostKey,
				Insecure: cur.InsecureIgnoreHostKey,
			}
		},
	}, nil
}

// startSSHForwards constructs and starts the managed-SSH-forward subsystem:
// the Manager (owns the live connections), the Verifier and Registry (the
// service layer `dotvault ssh add/list/remove` and the web UI CRUD mutate
// through), reconciled against whatever ssh.yaml currently holds.
//
// Returns nil, nil, "" when a precondition sshForwardDeps checks is unmet, or
// when ssh.yaml cannot be resolved or loaded — every failure is logged as a
// WARN here and is never fatal to the daemon, matching every other optional
// subsystem's startup posture.
func startSSHForwards(ctx context.Context, cfg *config.Config, backend sshfwd.SignerSource, username string) (mgr *sshfwd.Manager, registry *sshfwd.Registry, sshConfigPath string) {
	deps, err := sshForwardDeps(cfg, backend, username)
	if err != nil {
		slog.Warn("managed SSH forwards disabled", "error", err)
		return nil, nil, ""
	}
	updateSSHPolicyConfig(cfg.SSH)

	sshConfigPath, err = paths.SSHConfigPath()
	if err != nil {
		slog.Warn("managed SSH forwards disabled: could not resolve ssh.yaml path", "error", err)
		return nil, nil, ""
	}

	file, err := sshfwd.Load(sshConfigPath)
	if err != nil {
		slog.Warn("managed SSH forwards disabled: could not load ssh.yaml", "path", sshConfigPath, "error", err)
		return nil, nil, ""
	}

	mgr = sshfwd.NewManager(deps)
	if err := mgr.Reconcile(ctx, file.Remotes); err != nil {
		mgr.Close()
		slog.Warn("managed SSH forwards disabled: initial reconcile failed", "error", err)
		return nil, nil, ""
	}

	verifier := sshfwd.NewVerifier(deps)
	registry = sshfwd.NewRegistry(sshConfigPath, mgr, verifier)

	slog.Info("managed SSH forwards enabled", "target", deps.TargetName, "remotes", len(file.Remotes), "config", sshConfigPath)
	return mgr, registry, sshConfigPath
}
