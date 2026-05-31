package agent

import (
	"context"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/vault"
)

// Service bundles the agent backend with its transport listener(s) so the
// daemon lifecycle can treat the SSH agent as a single managed component. The
// backend survives token refreshes; only the listeners are (re)started. On
// Windows the agent may serve more than one endpoint — the dotvault pipe plus,
// when enabled, a Pageant-convention pipe — all sharing the one backend.
type Service struct {
	Backend   *Backend
	addr      string   // primary endpoint, reported by Endpoint()
	endpoints []string // every endpoint to listen on (primary first)
}

// NewService resolves the endpoint(s), builds the key sources, and wires the
// backend + listeners. gate is the token-lifecycle gate (may be nil).
func NewService(agentCfg config.AgentConfig, vc *vault.Client, kvMount, userPrefix, username string, gate ReauthGate) (*Service, error) {
	sources, err := NewSourcesFromConfig(agentCfg, vc, kvMount, userPrefix, username)
	if err != nil {
		return nil, err
	}
	addr := ResolveEndpoint(agentCfg)
	backend := NewBackend(sources, WithReauthGate(gate), WithEndpoint(addr))
	return &Service{
		Backend:   backend,
		addr:      addr,
		endpoints: resolveServeEndpoints(agentCfg, addr),
	}, nil
}

// Endpoint returns the primary resolved socket path / pipe name — the one a
// client connects to by default and the one `dotvault status` queries.
// Querying only the primary is deliberate: every endpoint shares the one
// backend, so the identities served on the Pageant pipe are identical to those
// on the primary — a second query would report the same thing.
func (s *Service) Endpoint() string { return s.addr }

// Endpoints returns every endpoint the agent listens on (primary first),
// including the Pageant pipe on Windows when enabled.
func (s *Service) Endpoints() []string { return s.endpoints }

// Run serves the agent on every configured endpoint until ctx is cancelled,
// one supervised listener per endpoint. The listeners share the single backend
// (and its cached identities), so a token refresh does not bounce any of them.
func (s *Service) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, addr := range s.endpoints {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			s.serveEndpoint(ctx, addr)
		}(addr)
	}
	wg.Wait()
}

// serveEndpoint serves a single endpoint until ctx is cancelled. If the
// listener terminates unexpectedly (the endpoint vanished, a transient accept
// failure surfaced) it is rebuilt and restarted after a short backoff.
func (s *Service) serveEndpoint(ctx context.Context, addr string) {
	const backoff = 2 * time.Second
	listener := NewListener(addr, s.Backend)
	for {
		err := listener.Serve(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Error("ssh agent listener stopped unexpectedly, restarting", "error", err, "endpoint", addr)
		} else {
			slog.Warn("ssh agent listener returned without error before shutdown; restarting", "endpoint", addr)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		listener = NewListener(addr, s.Backend)
	}
}

// resolveServeEndpoints returns every endpoint the agent should listen on: the
// primary (configured/default) endpoint, plus — on Windows when the Putty
// option is enabled — a second pipe following the Pageant naming convention so
// PuTTY-family clients connect without configuration. A named pipe carries a
// single name, so the Pageant pipe is a parallel listener rather than an alias.
// Failure to derive the Pageant name is logged and skipped; the primary
// endpoint always stands.
func resolveServeEndpoints(agentCfg config.AgentConfig, primary string) []string {
	endpoints := []string{primary}
	if runtime.GOOS != "windows" || !agentCfg.Windows.PuttyEnabled() {
		return endpoints
	}
	p, err := pageantPipeName()
	if err != nil {
		slog.Warn("ssh agent: could not derive pageant pipe name; PuTTY clients will not auto-connect", "error", err)
		return endpoints
	}
	if p != "" && p != primary {
		endpoints = append(endpoints, p)
	}
	return endpoints
}

// ResolveEndpoint picks the platform endpoint, applying per-user defaults when
// the config leaves the path/pipe empty. Exported so the CLI status command can
// report the endpoint without constructing a full Service.
func ResolveEndpoint(agentCfg config.AgentConfig) string {
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
