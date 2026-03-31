package web

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/sync"
	"github.com/goodtune/dotvault/internal/vault"
)

// Server is the web UI HTTP server.
type Server struct {
	cfg           config.WebConfig
	vault         *vault.Client
	engine        *sync.Engine
	csrf          *CSRFStore
	oauth         *OAuthManager
	login         *auth.LoginTracker
	mux           *http.ServeMux
	server        *http.Server
	rules         []config.Rule
	kvMount       string
	userPrefix    string
	username      string
	authMethod    string
	authMount     string
	authRole      string
	tokenFilePath      string
	version            string
	vaultAddress       string
	loginTextHTML      string
	secretViewTextHTML string
	authDone           chan struct{}
	readyCh            chan error
	listenAddr         string
}

// ServerConfig holds all dependencies for the web server.
type ServerConfig struct {
	WebCfg        config.WebConfig
	VaultCfg      config.VaultConfig
	Rules         []config.Rule
	Vault         *vault.Client
	Engine        *sync.Engine
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
		cfg:           sc.WebCfg,
		vault:         sc.Vault,
		engine:        sc.Engine,
		csrf:          NewCSRFStore(),
		oauth:         NewOAuthManager(),
		login:         auth.NewLoginTracker(sc.Vault),
		mux:           http.NewServeMux(),
		rules:         sc.Rules,
		kvMount:       sc.VaultCfg.KVMount,
		userPrefix:    sc.VaultCfg.UserPrefix,
		username:      sc.Username,
		authMethod:    sc.VaultCfg.AuthMethod,
		authMount:     sc.VaultCfg.AuthMount,
		authRole:      sc.VaultCfg.AuthRole,
		tokenFilePath:      sc.TokenFilePath,
		version:            sc.Version,
		vaultAddress:       sc.VaultCfg.Address,
		loginTextHTML:      renderMarkdown(sc.WebCfg.LoginText),
		secretViewTextHTML: renderMarkdown(sc.WebCfg.SecretViewText),
		authDone:           make(chan struct{}, 1),
		readyCh:            make(chan error, 1),
	}

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
	s.mux.HandleFunc("GET /api/v1/secrets/", s.handleSecrets)
	s.mux.HandleFunc("POST /api/v1/sync", s.requireCSRF(s.handleSync))
	s.mux.HandleFunc("GET /api/v1/oauth/{rule}/start", s.handleOAuthStart)
	s.mux.HandleFunc("GET /api/v1/oauth/callback", s.handleOAuthCallback)

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
		// Content-Security-Policy
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.csrf.Validate(r) {
			http.Error(w, `{"error":"invalid or missing CSRF token"}`, http.StatusForbidden)
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

