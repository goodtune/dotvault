package web

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"

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
	mux           *http.ServeMux
	server        *http.Server
	rules         []config.Rule
	kvMount       string
	userPrefix    string
	username      string
	authMount     string
	authRole      string
	tokenFilePath string
	authDone      chan struct{}
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
		mux:           http.NewServeMux(),
		rules:         sc.Rules,
		kvMount:       sc.VaultCfg.KVMount,
		userPrefix:    sc.VaultCfg.UserPrefix,
		username:      sc.Username,
		authMount:     sc.VaultCfg.AuthMount,
		authRole:      sc.VaultCfg.AuthRole,
		tokenFilePath: sc.TokenFilePath,
		authDone:      make(chan struct{}, 1),
	}

	s.registerRoutes()
	return s, nil
}

func (s *Server) registerRoutes() {
	// Auth routes (OIDC browser-based login)
	s.mux.HandleFunc("GET /auth/start", s.handleAuthStart)
	s.mux.HandleFunc("GET /auth/callback", s.handleAuthCallback)

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

// Start begins serving HTTP.
func (s *Server) Start() error {
	s.server = &http.Server{
		Addr:    s.cfg.Listen,
		Handler: s.middleware(s.mux),
	}

	slog.Info("starting web UI", "listen", s.cfg.Listen)
	err := s.server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
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

func (s *Server) userKVPrefix() string {
	return s.userPrefix + s.username + "/"
}

