package web

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/enrol"
	"github.com/goodtune/dotvault/internal/paths"
	internalsync "github.com/goodtune/dotvault/internal/sync"
	"github.com/goodtune/dotvault/internal/vault"
)

// Server is the web UI HTTP server.
type Server struct {
	cfg                config.WebConfig
	vaultCfg           config.VaultConfig
	syncCfg            config.SyncConfig
	vault              *vault.Client
	engine             *internalsync.Engine
	csrf               *CSRFStore
	oauth              *OAuthManager
	login              *auth.LoginTracker
	mux                *http.ServeMux
	server             *http.Server
	rules              []config.Rule
	enrolments         map[string]config.Enrolment
	kvMount            string
	userPrefix         string
	username           string
	authMethod         string
	authMount          string
	authRole           string
	tokenFilePath      string
	version            string
	vaultAddress       string
	loginTextHTML      string
	secretViewTextHTML string
	authDone           chan struct{}
	readyCh            chan error
	listenAddr         string
	enrolPromptMu      sync.RWMutex
	enrolPromptLabel   string
	enrolPromptCh      chan string
	enrolRunnerMu      sync.RWMutex
	enrolRunner        *EnrolmentRunner
	shutdownCtx        context.Context
	shutdownCancel     context.CancelFunc
}

// ServerConfig holds all dependencies for the web server.
type ServerConfig struct {
	WebCfg        config.WebConfig
	VaultCfg      config.VaultConfig
	SyncCfg       config.SyncConfig
	Rules         []config.Rule
	Vault         *vault.Client
	Engine        *internalsync.Engine
	Username      string
	TokenFilePath string
	Version       string
}

// NewServer creates a new web server.
func NewServer(sc ServerConfig) (*Server, error) {
	if err := paths.ValidateLoopback(sc.WebCfg.Listen); err != nil {
		return nil, fmt.Errorf("web.listen: %w", err)
	}

	s := &Server{
		cfg:                sc.WebCfg,
		vaultCfg:           sc.VaultCfg,
		syncCfg:            sc.SyncCfg,
		vault:              sc.Vault,
		engine:             sc.Engine,
		csrf:               NewCSRFStore(),
		oauth:              NewOAuthManager(),
		login:              auth.NewLoginTracker(sc.Vault),
		mux:                http.NewServeMux(),
		rules:              sc.Rules,
		kvMount:            sc.VaultCfg.KVMount,
		userPrefix:         sc.VaultCfg.UserPrefix,
		username:           sc.Username,
		authMethod:         sc.VaultCfg.AuthMethod,
		authMount:          sc.VaultCfg.AuthMount,
		authRole:           sc.VaultCfg.AuthRole,
		tokenFilePath:      sc.TokenFilePath,
		version:            sc.Version,
		vaultAddress:       sc.VaultCfg.Address,
		loginTextHTML:      renderMarkdown(sc.WebCfg.LoginText),
		secretViewTextHTML: renderMarkdown(sc.WebCfg.SecretViewText),
		authDone:           make(chan struct{}, 1),
		readyCh:            make(chan error, 1),
	}
	s.shutdownCtx, s.shutdownCancel = context.WithCancel(context.Background())

	s.registerRoutes()
	return s, nil
}

func (s *Server) registerRoutes() {
	// Auth routes — OIDC
	s.mux.HandleFunc("GET /auth/oidc/start", s.handleAuthStart)
	s.mux.HandleFunc("GET /auth/oidc/callback", s.handleAuthCallback)

	// Auth routes — LDAP
	s.mux.HandleFunc("POST /auth/ldap/login", s.requireCSRF(s.handleLDAPLogin))
	s.mux.HandleFunc("GET /auth/ldap/status", s.handleLDAPStatus)
	s.mux.HandleFunc("POST /auth/ldap/totp", s.requireCSRF(s.handleLDAPTOTP))

	// Auth routes — Token
	s.mux.HandleFunc("POST /auth/token/login", s.requireCSRF(s.handleTokenLogin))

	// API routes
	s.mux.HandleFunc("GET /api/v1/csrf", s.csrf.IssueHandler())
	s.mux.HandleFunc("GET /api/v1/status", s.handleStatus)
	s.mux.HandleFunc("GET /api/v1/rules", s.handleRules)
	s.mux.HandleFunc("GET /api/v1/config", s.handleConfig)
	s.mux.HandleFunc("GET /api/v1/config/download", s.handleConfigDownload)
	s.mux.HandleFunc("GET /api/v1/token", s.handleToken)
	s.mux.HandleFunc("GET /api/v1/secrets/", s.handleSecrets)
	s.mux.HandleFunc("POST /api/v1/sync", s.requireCSRF(s.handleSync))
	s.mux.HandleFunc("GET /api/v1/oauth/{rule}/start", s.handleOAuthStart)
	s.mux.HandleFunc("GET /api/v1/oauth/callback", s.handleOAuthCallback)

	// Enrolment prompt routes
	s.mux.HandleFunc("GET /api/v1/enrol/prompt", s.handleEnrolPrompt)
	s.mux.HandleFunc("POST /api/v1/enrol/secret", s.requireCSRF(s.handleEnrolSecret))

	// Enrolment runner routes
	s.mux.HandleFunc("POST /api/v1/enrol/{key}/start", s.requireCSRF(s.handleEnrolStart))
	s.mux.HandleFunc("POST /api/v1/enrol/{key}/skip", s.requireCSRF(s.handleEnrolSkip))
	s.mux.HandleFunc("POST /api/v1/enrol/{key}/reset", s.requireCSRF(s.handleEnrolReset))
	s.mux.HandleFunc("GET /api/v1/enrol/{key}/status", s.handleEnrolStatus)
	s.mux.HandleFunc("POST /api/v1/enrol/complete", s.requireCSRF(s.handleEnrolComplete))

	// Static SPA files
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		slog.Error("failed to create sub-filesystem for static", "error", err)
		return
	}
	fileServer := http.FileServer(http.FS(staticSub))
	s.mux.Handle("/", fileServer)
}

// Start begins serving HTTP. It signals WaitReady once the listener is bound,
// or sends the bind error so the caller can fail fast.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		s.readyCh <- err
		return err
	}
	// Preserve the configured hostname (e.g. "localhost") and only take
	// the port from the actual listener, so OIDC redirect URIs match
	// what users configure in Vault's allowed_redirect_uris.
	host, _, _ := net.SplitHostPort(s.cfg.Listen)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	s.listenAddr = net.JoinHostPort(host, port)

	s.server = &http.Server{
		Handler: s.middleware(s.mux),
	}

	slog.Info("starting web UI", "listen", s.listenAddr)
	s.readyCh <- nil // signal ready

	if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// WaitReady blocks until the web server is listening and returns any startup error.
func (s *Server) WaitReady() error {
	return <-s.readyCh
}

// Shutdown gracefully stops the server and cleans up resources.
func (s *Server) Shutdown(ctx context.Context) error {
	s.shutdownCancel()
	if s.login != nil {
		s.login.Close()
	}
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set security headers up front so they apply to every response,
		// including the 403 we may write below for a forbidden Host.
		// Browsers honour these headers on error responses too — without
		// them a 403 page could be MIME-sniffed or framed by an attacker.
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// DNS-rebinding defence. The listener is loopback-only by hard
		// invariant (paths.ValidateLoopback), but a hostile origin can
		// still resolve a name like rebound.attacker.test to 127.0.0.1
		// and have the user's browser send a request that reaches the
		// daemon. Without a Host check the response (which can include
		// Vault tokens, secrets, and the unredacted config download) is
		// readable by the attacker's page. Reject any Host whose
		// hostname is not a recognised loopback alias (127.0.0.1, ::1,
		// localhost) or the hostname the daemon was configured to
		// listen on via web.listen.
		if !s.hostAllowed(r) {
			// API consumers (the SPA fetch wrapper, scripts, tests)
			// rely on JSON error envelopes — fall back to plain text
			// only for non-API routes (e.g. a browser hitting `/`
			// directly). Mark the 403 no-store so the API invariant
			// holds for both the handler-level errors and the
			// middleware-level rejection.
			if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/auth/") {
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Pragma", "no-cache")
				writeError(w, "forbidden host", http.StatusForbidden)
			} else {
				http.Error(w, "forbidden host", http.StatusForbidden)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hostAllowed reports whether r.Host names a loopback identity. It strips
// the port and then applies two rules:
//   - IP literals: accepted iff net.IP.IsLoopback() (covers 127.0.0.1,
//     ::1, the long-form 0:0:0:0:0:0:0:1, ::ffff:127.0.0.1, and the
//     entire 127.0.0.0/8 range).
//   - Hostnames: a strict allowlist of "localhost" plus whatever
//     hostname the daemon was configured to listen on (e.g.
//     "my-loopback-alias" when web.listen is "my-loopback-alias:9000").
//
// Hostnames that happen to resolve to a loopback IP elsewhere on the
// network are still rejected — that's the DNS-rebinding defence.
func (s *Server) hostAllowed(r *http.Request) bool {
	if r.Host == "" {
		return false
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = unwrapIPv6(host)

	// IP literals: accept any form that resolves to a loopback address.
	// This covers "127.0.0.1", "::1", the long-form "0:0:0:0:0:0:0:1",
	// "::ffff:127.0.0.1", and the entire 127.0.0.0/8 loopback range —
	// all of which reach a loopback-bound listener and would already
	// have made it past the kernel's address check. ParseIP returns
	// nil for hostnames so this branch is IP-only; arbitrary names
	// still fall through to the strict allowlist below.
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}

	// Non-IP hostnames: strict allowlist (DNS-rebinding defence).
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if listenHost, _, err := net.SplitHostPort(s.cfg.Listen); err == nil {
		listenHost = unwrapIPv6(listenHost)
		if strings.EqualFold(host, listenHost) {
			return true
		}
	}
	return false
}

// unwrapIPv6 removes the surrounding brackets from a properly-bracketed
// IPv6-literal hostname (e.g. "[::1]" -> "::1") and returns the input
// unchanged otherwise. The unwrap fires only when the inner content
// looks like real IPv6 syntax — i.e. contains a colon AND parses as an
// IP. That distinguishes legitimate IPv6 forms (including IPv4-mapped
// "::ffff:127.0.0.1", which net.IP.To4 normalises and so wouldn't pass
// a "non-IPv4-mapped" filter) from bracketed non-IP strings like
// "[localhost]" that should stay bracketed and fail the allowlist
// comparison. Bracketed bare IPv4 literals like "[127.0.0.1]" also
// stay bracketed because brackets aren't standard URL syntax for IPv4
// — they're a tampered form and the strict path is to leave them.
func unwrapIPv6(host string) string {
	if len(host) < 2 || host[0] != '[' || host[len(host)-1] != ']' {
		return host
	}
	inner := host[1 : len(host)-1]
	if !strings.Contains(inner, ":") {
		return host
	}
	if net.ParseIP(inner) == nil {
		return host
	}
	return inner
}

func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.csrf.Validate(r) {
			writeError(w, "invalid or missing CSRF token", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// URL returns the web UI root URL.
func (s *Server) URL() string {
	return fmt.Sprintf("http://%s/", s.listenAddr)
}

func (s *Server) userKVPrefix() string {
	return s.userPrefix + s.username + "/"
}

// getEnrolRunner returns the enrolment runner, safe for concurrent access.
func (s *Server) getEnrolRunner() *EnrolmentRunner {
	s.enrolRunnerMu.RLock()
	defer s.enrolRunnerMu.RUnlock()
	return s.enrolRunner
}

// getEnrolments returns a shallow copy of the configured enrolments map,
// safe for concurrent access and for the caller to iterate or mutate
// without affecting server state.
func (s *Server) getEnrolments() map[string]config.Enrolment {
	s.enrolRunnerMu.RLock()
	defer s.enrolRunnerMu.RUnlock()
	if s.enrolments == nil {
		return nil
	}
	out := make(map[string]config.Enrolment, len(s.enrolments))
	for k, v := range s.enrolments {
		out[k] = v
	}
	return out
}

// InitEnrolments sets up the enrolment runner for web-driven enrolment.
// It checks Vault for already-completed enrolments and marks them as such.
func (s *Server) InitEnrolments(ctx context.Context, enrolments map[string]config.Enrolment) {
	if len(enrolments) == 0 {
		s.enrolRunnerMu.Lock()
		s.enrolments = enrolments
		s.enrolRunnerMu.Unlock()
		return
	}

	runner := NewEnrolmentRunner(enrolments)

	// Check Vault for already-complete enrolments.
	for _, info := range runner.States() {
		engine, ok := enrol.GetEngine(info.Engine)
		if !ok {
			continue
		}
		vaultPath := s.userKVPrefix() + info.Key
		secret, err := s.vault.ReadKVv2(ctx, s.kvMount, vaultPath)
		if err != nil {
			slog.Warn("failed to check enrolment in vault", "key", info.Key, "error", err)
			continue
		}
		if secret != nil && enrol.HasAllFields(secret.Data, engine.Fields()) {
			runner.MarkComplete(info.Key)
		}
	}

	s.enrolRunnerMu.Lock()
	s.enrolRunner = runner
	s.enrolments = enrolments
	s.enrolRunnerMu.Unlock()
}

// WaitForEnrolments blocks until the user completes the enrolment page.
// Returns immediately if there are no pending enrolments or no runner.
func (s *Server) WaitForEnrolments() {
	r := s.getEnrolRunner()
	if r == nil {
		return
	}
	r.Wait()
}

// EnrolPromptSecret implements a web-based PromptSecret. It sets the pending
// prompt state and blocks until the frontend submits a value via the
// /api/v1/enrol/secret endpoint, or the context is cancelled.
func (s *Server) EnrolPromptSecret(ctx context.Context, label string) (string, error) {
	ch := make(chan string, 1)

	s.enrolPromptMu.Lock()
	if s.enrolPromptCh != nil {
		s.enrolPromptMu.Unlock()
		return "", fmt.Errorf("enrol prompt already pending")
	}
	s.enrolPromptLabel = label
	s.enrolPromptCh = ch
	s.enrolPromptMu.Unlock()

	defer func() {
		s.enrolPromptMu.Lock()
		if s.enrolPromptCh == ch {
			s.enrolPromptLabel = ""
			s.enrolPromptCh = nil
		}
		s.enrolPromptMu.Unlock()
	}()

	select {
	case val := <-ch:
		return val, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
