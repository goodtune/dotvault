package web

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/goodtune/dotvault/internal/agent"
	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/enrol"
	"github.com/goodtune/dotvault/internal/observability"
	"github.com/goodtune/dotvault/internal/paths"
	internalsync "github.com/goodtune/dotvault/internal/sync"
	"github.com/goodtune/dotvault/internal/vault"
)

// Server is the web UI HTTP server.
type Server struct {
	cfg                config.WebConfig
	vaultCfg           config.VaultConfig
	syncCfg            config.SyncConfig
	obsCfg             config.ObservabilityConfig
	vault              *vault.Client
	engine             *internalsync.Engine
	agentStatus        agentStatusProvider
	agentCfg           config.AgentConfig
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

	// initialSyncDone flips to true once the daemon calls
	// MarkInitialSyncComplete (wired into the sync engine's
	// AfterInitialSync hook in runDaemon — fires exactly once,
	// between the initial RunOnce and the long-running loop).
	// /readyz gates on it alongside the Vault-token check so k8s
	// readinessProbe consumers and the OTel httpcheckreceiver
	// don't observe a "ready" daemon before any secrets have been
	// written to disk — matching the sd_notify(READY=1) contract
	// on the systemd path.
	initialSyncDone atomic.Bool
}

// agentStatusProvider yields the SSH agent's current status snapshot for the
// dashboard. *agent.Backend satisfies it. Kept as an interface so the web
// server stays testable without constructing a real agent.
type agentStatusProvider interface {
	Status(ctx context.Context) agent.Status
}

// ServerConfig holds all dependencies for the web server.
type ServerConfig struct {
	WebCfg   config.WebConfig
	VaultCfg config.VaultConfig
	SyncCfg  config.SyncConfig
	ObsCfg   config.ObservabilityConfig
	Rules    []config.Rule
	Vault    *vault.Client
	Engine   *internalsync.Engine
	// Agent, when non-nil, exposes the SSH agent status on /api/v1/status.
	Agent agentStatusProvider
	// AgentCfg is the loaded agent configuration. It is the section the
	// config-download endpoint re-emits, so it round-trips through the same
	// YAML/.reg renderers as every other section even when the daemon loaded
	// its config from a Windows GPO.
	AgentCfg      config.AgentConfig
	Username      string
	TokenFilePath string
	Version       string
}

// NewServer creates a new web server.
func NewServer(sc ServerConfig) (*Server, error) {
	if err := paths.ValidateLoopback(sc.WebCfg.Listen); err != nil {
		return nil, fmt.Errorf("web.listen: %w", err)
	}

	// Retain the full observability config, including the Headers map.
	// The config-download endpoint serves the effective config
	// losslessly (config conversion is lossless in every direction), so
	// it needs the live header values. Enabling the web UI already
	// exposes secrets over the loopback connection (the secrets reveal
	// endpoint), so holding the OTLP header tokens on the Server struct
	// for the daemon's lifetime is consistent with that posture.
	// Operators who want tokens kept out of a downloaded config set them
	// via OTEL_EXPORTER_OTLP_HEADERS instead of the config file.
	s := &Server{
		cfg:                sc.WebCfg,
		vaultCfg:           sc.VaultCfg,
		syncCfg:            sc.SyncCfg,
		obsCfg:             sc.ObsCfg,
		vault:              sc.Vault,
		engine:             sc.Engine,
		agentStatus:        sc.Agent,
		agentCfg:           sc.AgentCfg,
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

	// Health probes. /healthz reports liveness — the daemon is
	// running and able to serve HTTP. /readyz reports readiness:
	// 200 only after BOTH a Vault token is present AND the
	// daemon has marked its initial sync complete (via
	// MarkInitialSyncComplete, called from the sync engine's
	// AfterInitialSync hook after the initial RunOnce returns).
	// This mirrors the sd_notify(READY=1) contract on the systemd
	// path so a Kubernetes readinessProbe or the OTel
	// httpcheckreceiver never observes a green daemon before
	// secrets exist on disk. Both probes are loopback-only and
	// return JSON.
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /readyz", s.handleReadyz)

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

		// Wrap the writer so the metrics middleware can read back the
		// status. wrapResponseWriter returns a variant that exposes
		// only the optional interfaces (Flusher / Hijacker /
		// ReaderFrom) that the underlying writer actually implements,
		// so handlers gating SSE / WebSocket behaviour on
		// `w.(http.Flusher)` etc. get an accurate assertion.
		rw, rec := wrapResponseWriter(w)
		defer func() {
			// If the handler panicked, the wrapped recorder may not
			// have seen a WriteHeader yet — net/http's top-level
			// recovery writes the 500 only after our defers run. In
			// that case, record the metric as a 500 ourselves so the
			// observability layer doesn't claim the request
			// succeeded. If headers WERE already sent before the
			// panic, the wire status is locked and we should leave
			// rec.status alone — a partial 200 stream that crashed
			// mid-body is a 2xx on the wire, even though it
			// represents a server-side failure. Re-panic after
			// recording so the standard server recovery still kicks
			// in.
			if rcv := recover(); rcv != nil {
				if !rec.wroteHeader {
					rec.status = http.StatusInternalServerError
				}
				observability.RecordWebRequest(
					r.Context(),
					routeLabel(r.URL.Path),
					statusClass(rec.status),
				)
				panic(rcv)
			}
			observability.RecordWebRequest(
				r.Context(),
				routeLabel(r.URL.Path),
				statusClass(rec.status),
			)
		}()

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
				rw.Header().Set("Cache-Control", "no-store")
				rw.Header().Set("Pragma", "no-cache")
				writeError(rw, "forbidden host", http.StatusForbidden)
			} else {
				http.Error(rw, "forbidden host", http.StatusForbidden)
			}
			return
		}
		next.ServeHTTP(rw, r)
	})
}

// statusRecorder is the bare http.ResponseWriter wrapper that
// captures the response status so the middleware can record it as a
// metric attribute. It implements only the mandatory ResponseWriter
// methods plus Unwrap; the optional interfaces (Flusher / Hijacker /
// ReaderFrom) are added at construction time by wrapResponseWriter,
// which picks one of the 8 statusRecorder* variants below based on
// what the underlying writer supports. The middleware-wrapper
// pattern matches what httpsnoop, go-chi and gorilla/mux use: it's
// the only way Go's static dispatch can give handlers an honest
// answer to assertions like `w.(http.Flusher)`.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

// Unwrap returns the underlying ResponseWriter so net/http's
// ResponseController machinery (Go 1.20+) can walk past the wrapper.
func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

func (s *statusRecorder) WriteHeader(code int) {
	// Forward only the first WriteHeader. Subsequent calls would
	// trigger net/http's "superfluous response.WriteHeader" log and
	// can confuse wrappers — they're a no-op for the recorded status
	// too, since net/http itself ignores them.
	if s.wroteHeader {
		return
	}
	s.status = code
	s.wroteHeader = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	// Mirror net/http's standard ResponseWriter: the first Write
	// triggers an implicit WriteHeader(StatusOK) on the
	// underlying writer too, not just the wrapper's status
	// field. Routing through s.WriteHeader keeps the recorded
	// status and the wire status in lockstep across non-standard
	// ResponseWriter implementations that don't auto-send
	// headers from Write.
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

// recordWriteHeader is the internal hook for the ReaderFrom variants
// fired before they hand the io.Reader off to the underlying writer's
// ReadFrom. It does the same WriteHeader(StatusOK) the standard
// net/http response would do at its first byte — going through
// s.WriteHeader so the implicit 200 reaches the underlying writer
// too (some ResponseWriter implementations skip header emission
// inside ReadFrom and rely on a prior WriteHeader call). Calling
// WriteHeader is a no-op if the handler already set a status.
func (s *statusRecorder) recordWriteHeader() {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
}

// wrapResponseWriter returns a ResponseWriter that wraps w with
// metrics-status capture and exposes exactly the optional interface
// set w itself implements. The second return value is the underlying
// recorder so callers can read back the captured status — the
// wrapped interface value would hide it behind a concrete variant.
//
// The 8-way switch mirrors the well-known middleware pattern (see
// httpsnoop, go-chi). Each variant embeds *statusRecorder so the
// mandatory ResponseWriter methods (Header, Write, WriteHeader) and
// Unwrap promote through; each adds explicit forwarding methods for
// the optional interfaces it claims.
func wrapResponseWriter(w http.ResponseWriter) (http.ResponseWriter, *statusRecorder) {
	sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	_, isF := w.(http.Flusher)
	_, isH := w.(http.Hijacker)
	_, isRF := w.(io.ReaderFrom)
	switch {
	case isF && isH && isRF:
		return &statusRecorderFHR{statusRecorder: sr}, sr
	case isF && isH:
		return &statusRecorderFH{statusRecorder: sr}, sr
	case isF && isRF:
		return &statusRecorderFR{statusRecorder: sr}, sr
	case isH && isRF:
		return &statusRecorderHR{statusRecorder: sr}, sr
	case isF:
		return &statusRecorderF{statusRecorder: sr}, sr
	case isH:
		return &statusRecorderH{statusRecorder: sr}, sr
	case isRF:
		return &statusRecorderR{statusRecorder: sr}, sr
	default:
		return sr, sr
	}
}

// statusRecorderF wraps a writer that implements http.Flusher only.
type statusRecorderF struct{ *statusRecorder }

func (s *statusRecorderF) Flush() { s.ResponseWriter.(http.Flusher).Flush() }

// statusRecorderH wraps a writer that implements http.Hijacker only.
type statusRecorderH struct{ *statusRecorder }

func (s *statusRecorderH) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return s.ResponseWriter.(http.Hijacker).Hijack()
}

// statusRecorderR wraps a writer that implements io.ReaderFrom only.
type statusRecorderR struct{ *statusRecorder }

func (s *statusRecorderR) ReadFrom(r io.Reader) (int64, error) {
	s.recordWriteHeader()
	return s.ResponseWriter.(io.ReaderFrom).ReadFrom(r)
}

// statusRecorderFH wraps a writer that implements Flusher + Hijacker.
type statusRecorderFH struct{ *statusRecorder }

func (s *statusRecorderFH) Flush() { s.ResponseWriter.(http.Flusher).Flush() }
func (s *statusRecorderFH) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return s.ResponseWriter.(http.Hijacker).Hijack()
}

// statusRecorderFR wraps a writer that implements Flusher + ReaderFrom.
type statusRecorderFR struct{ *statusRecorder }

func (s *statusRecorderFR) Flush() { s.ResponseWriter.(http.Flusher).Flush() }
func (s *statusRecorderFR) ReadFrom(r io.Reader) (int64, error) {
	s.recordWriteHeader()
	return s.ResponseWriter.(io.ReaderFrom).ReadFrom(r)
}

// statusRecorderHR wraps a writer that implements Hijacker + ReaderFrom.
type statusRecorderHR struct{ *statusRecorder }

func (s *statusRecorderHR) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return s.ResponseWriter.(http.Hijacker).Hijack()
}
func (s *statusRecorderHR) ReadFrom(r io.Reader) (int64, error) {
	s.recordWriteHeader()
	return s.ResponseWriter.(io.ReaderFrom).ReadFrom(r)
}

// statusRecorderFHR wraps a writer that implements all three optional
// interfaces — the common case under net/http's standard server.
type statusRecorderFHR struct{ *statusRecorder }

func (s *statusRecorderFHR) Flush() { s.ResponseWriter.(http.Flusher).Flush() }
func (s *statusRecorderFHR) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return s.ResponseWriter.(http.Hijacker).Hijack()
}
func (s *statusRecorderFHR) ReadFrom(r io.Reader) (int64, error) {
	s.recordWriteHeader()
	return s.ResponseWriter.(io.ReaderFrom).ReadFrom(r)
}

// statusClass returns a bounded label (1xx/2xx/3xx/4xx/5xx) so the
// time-series cardinality stays low. Out-of-range statuses (e.g. a
// handler that wrote a zero status) collapse to "unknown".
func statusClass(code int) string {
	switch {
	case code >= 100 && code < 200:
		return "1xx"
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500 && code < 600:
		return "5xx"
	default:
		return "unknown"
	}
}

// routeLabel maps request paths onto a small set of bounded route
// templates so the metric cardinality stays under control. Paths that
// don't match a known prefix collapse to "other".
func routeLabel(p string) string {
	switch {
	case p == "/":
		return "/"
	case p == "/healthz":
		return "/healthz"
	case p == "/readyz":
		return "/readyz"
	case strings.HasPrefix(p, "/auth/oidc/"):
		return "/auth/oidc/*"
	case strings.HasPrefix(p, "/auth/ldap/"):
		return "/auth/ldap/*"
	case strings.HasPrefix(p, "/auth/token/"):
		return "/auth/token/*"
	case strings.HasPrefix(p, "/api/v1/secrets/"):
		return "/api/v1/secrets/*"
	case strings.HasPrefix(p, "/api/v1/oauth/"):
		return "/api/v1/oauth/*"
	case strings.HasPrefix(p, "/api/v1/enrol/"):
		return "/api/v1/enrol/*"
	case p == "/api/v1/csrf",
		p == "/api/v1/status",
		p == "/api/v1/rules",
		p == "/api/v1/config",
		p == "/api/v1/config/download",
		p == "/api/v1/token",
		p == "/api/v1/sync":
		return p
	case strings.HasPrefix(p, "/api/v1/"):
		// Defensive collapse: a future endpoint added without
		// updating the explicit list above would otherwise leak
		// the verbatim request path (potentially including a
		// username segment) into the metric backend, unbounding
		// cardinality.
		return "/api/v1/*"
	default:
		return "other"
	}
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

// MarkInitialSyncComplete flips the readiness flag. The daemon calls
// this once engine.RunOnce returns at startup (success or per-rule
// failure — partial progress is still "we've tried"). /readyz only
// reports ready once this has fired AND the daemon holds a Vault
// token, so a k8s readinessProbe or the OTel httpcheckreceiver
// doesn't observe a green daemon before secrets exist on disk.
func (s *Server) MarkInitialSyncComplete() {
	s.initialSyncDone.Store(true)
}

// InitialSyncComplete reports whether MarkInitialSyncComplete has
// fired. Exposed for tests and the /readyz handler.
func (s *Server) InitialSyncComplete() bool {
	return s.initialSyncDone.Load()
}

// ForceReauth clears the in-memory Vault token so /api/v1/status reports
// authenticated=false on the next poll. The SPA is configured to redirect
// to the login screen whenever that flag flips, which effectively
// invalidates any browser session that was sitting on a stale "logged-in"
// view while the underlying token rotted. The token file on disk is
// intentionally left in place — operators may have written a fresh token
// out-of-band that the daemon can pick up without involving the user.
//
// Also resets the authDone channel so a fresh call to WaitForAuth (e.g.
// from a re-entry into the startup auth flow) will block until the user
// completes the new login.
func (s *Server) ForceReauth() {
	if s.vault != nil {
		s.vault.SetToken("")
	}
	// Drain any pending authDone signal — the previous auth is no
	// longer current and shouldn't satisfy a fresh WaitForAuth.
	select {
	case <-s.authDone:
	default:
	}
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
		if _, ok := enrol.GetEngine(info.Engine); !ok {
			continue
		}
		vaultPath := s.userKVPrefix() + info.Key
		secret, err := s.vault.ReadKVv2(ctx, s.kvMount, vaultPath)
		if err != nil {
			slog.Warn("failed to check enrolment in vault", "key", info.Key, "error", err)
			continue
		}
		if secret != nil && enrol.HasAllFields(secret.Data, info.Fields) {
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
