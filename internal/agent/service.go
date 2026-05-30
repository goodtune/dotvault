package agent

import (
	"context"
	"log/slog"
	"runtime"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/vault"
)

// Service bundles the agent backend with its transport listener so the daemon
// lifecycle can treat the SSH agent as a single managed component. The backend
// survives token refreshes; only the listener is (re)started.
type Service struct {
	Backend  *Backend
	listener *Listener
	addr     string
}

// NewService resolves the endpoint, builds the key sources, and wires the
// backend + listener. gate is the token-lifecycle gate (may be nil).
func NewService(agentCfg config.AgentConfig, vc *vault.Client, kvMount, userPrefix, username string, gate ReauthGate) (*Service, error) {
	sources, err := NewSourcesFromConfig(agentCfg, vc, kvMount, userPrefix, username)
	if err != nil {
		return nil, err
	}
	addr := resolveEndpoint(agentCfg)
	backend := NewBackend(sources, WithReauthGate(gate), WithEndpoint(addr))
	return &Service{
		Backend:  backend,
		listener: NewListener(addr, backend),
		addr:     addr,
	}, nil
}

// Endpoint returns the resolved socket path / pipe name.
func (s *Service) Endpoint() string { return s.addr }

// Run serves the agent until ctx is cancelled. If the listener terminates
// unexpectedly (the endpoint vanished, a transient accept failure surfaced) it
// is rebuilt and restarted after a short backoff — the backend, and its cached
// identities, persist across the restart so token refreshes do not bounce the
// listener.
func (s *Service) Run(ctx context.Context) {
	const backoff = 2 * time.Second
	for {
		err := s.listener.Serve(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Error("ssh agent listener stopped unexpectedly, restarting", "error", err, "endpoint", s.addr)
		} else {
			slog.Warn("ssh agent listener returned without error before shutdown; restarting", "endpoint", s.addr)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		s.listener = NewListener(s.addr, s.Backend)
	}
}

// resolveEndpoint picks the platform endpoint, applying per-user defaults when
// the config leaves the path/pipe empty.
func resolveEndpoint(agentCfg config.AgentConfig) string {
	if runtime.GOOS == "windows" {
		if agentCfg.Windows.Pipe != "" {
			return agentCfg.Windows.Pipe
		}
		return config.DefaultAgentPipe
	}
	if agentCfg.Unix.Path != "" {
		if p, err := paths.ExpandHome(agentCfg.Unix.Path); err == nil {
			return p
		}
		return agentCfg.Unix.Path
	}
	return paths.DefaultAgentSocket()
}
