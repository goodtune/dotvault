package web

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pkg/browser"

	"github.com/goodtune/dotvault/internal/agent"
	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/clipboard"
	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/enrol"
	"github.com/goodtune/dotvault/internal/notify"
	"github.com/goodtune/dotvault/internal/observability"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/remoteconfig"
	"github.com/goodtune/dotvault/internal/sshfwd"
	internalsync "github.com/goodtune/dotvault/internal/sync"
	"github.com/goodtune/dotvault/internal/uds"
	"github.com/goodtune/dotvault/internal/vault"
)

// Server is the web UI HTTP server.
type Server struct {
	cfg         config.WebConfig
	vaultCfg    config.VaultConfig
	obsCfg      config.ObservabilityConfig
	vault       *vault.Client
	engine      *internalsync.Engine
	agentStatus agentStatusProvider
	agentCfg    config.AgentConfig
	// remoteCfg is the local-only remote_config section, retained so the
	// config-download endpoint round-trips it; remoteStatus (nil-safe)
	// reports the overlay's last fetch outcome for /api/v1/status.
	remoteCfg    config.RemoteConfig
	remoteStatus func() *remoteconfig.Status
	// apiCfg is the local-only api section, retained so the config-download
	// endpoint round-trips it (like agentCfg and remoteCfg).
	apiCfg config.APIConfig
	// webEnabled records whether the loopback TCP listener (and with it the
	// browser-facing surface: the SPA, the auth routes, the OAuth callbacks)
	// is in play. It is NOT the same question as "was this Server
	// constructed" — a Server exists whenever either surface is enabled, and
	// with web.enabled false it serves the API over the Unix socket alone.
	webEnabled bool
	// socketPath is the resolved local API socket path, or "" when the
	// socket surface is disabled.
	socketPath string
	// socketBound records that this Server successfully bound socketPath, so
	// Shutdown knows the node is *ours* to unlink.
	//
	// This is load-bearing, not bookkeeping. When a second daemon starts
	// against a socket a live instance already owns, uds.Listen correctly
	// refuses — and the losing daemon then runs its deferred Shutdown on the
	// way out. Unlinking unconditionally there would delete the *winning*
	// daemon's socket node: it would keep serving an unlinked inode that no
	// new client can dial, silently destroying the very surface the
	// already-running check exists to protect.
	//
	// Written by listen() before Serve starts and read by Shutdown, both on
	// the daemon's startup path with no concurrent Start; guarded by
	// startMu so the race detector sees the ordering explicitly rather than
	// relying on that happening to be true.
	socketBound bool
	// startMu guards socketBound (and s.server) across the Start/Shutdown
	// pair, which the daemon can interleave when startup fails.
	startMu sync.Mutex
	csrf    *CSRFStore
	oauth   *OAuthManager
	login   *auth.LoginTracker
	mux     *http.ServeMux
	server  *http.Server
	// rulesMu guards rules and syncCfg, which the daemon's config-refresh
	// loop swaps at runtime via UpdateDynamicConfig while request handlers
	// read them.
	rulesMu    sync.RWMutex
	rules      []config.Rule
	syncCfg    config.SyncConfig
	enrolments map[string]config.Enrolment
	kvMount    string
	userPrefix string
	username   string
	// authMethod is the base login method ("oidc"/"ldap"/"token"/"mtls"),
	// with any "+tpm" suffix already stripped. The web SPA dispatches its
	// login form on this exact value, so the wire format must carry a single
	// meaning — see NewServer. The orthogonal "should the token be sealed?"
	// decision lives in sealToken.
	authMethod string
	// sealToken records whether the configured auth method requested TPM
	// token-sealing (the "+tpm" suffix), preserved here because authMethod has
	// the suffix stripped for the SPA.
	sealToken          bool
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
	// openBrowser launches a URL in this host's default browser for the
	// remote-browse endpoint. NewServer always sets it (browser.OpenURL
	// unless ServerConfig.OpenBrowser overrides it, as tests do), so the
	// endpoint cannot be disabled via config; the handler's nil guard
	// (503) only protects hand-constructed Servers in tests.
	openBrowser func(string) error
	// browseOpenMu is the remote-browse single-flight gate: only one
	// browser-opener call may be in flight, because a hung launcher is
	// abandoned (not killed) by the handler's bounded wait and unbounded
	// concurrent requests would otherwise pile up stuck goroutines.
	browseOpenMu sync.Mutex
	// sendNotification delivers a desktop notification for the remote-notify
	// endpoint. NewServer always sets it (notify.Send unless
	// ServerConfig.SendNotification overrides it, as tests do); the handler's
	// nil guard (503) only protects hand-constructed Servers in tests.
	sendNotification notify.Notifier
	// notifyMu is the remote-notify single-flight gate, mirroring
	// browseOpenMu — a notification backend that hangs is abandoned, not
	// killed, so only one delivery runs at a time.
	notifyMu sync.Mutex
	// setClipboard writes text to this host's clipboard for the
	// remote-clipboard endpoint. NewServer always sets it (clipboard.Set
	// unless ServerConfig.SetClipboard overrides it, as tests do); the
	// handler's nil guard (503) only protects hand-constructed Servers in
	// tests.
	setClipboard clipboard.Setter
	// clipboardMu is the remote-clipboard single-flight gate, mirroring
	// browseOpenMu — a clipboard writer that hangs is abandoned, not killed,
	// so only one write runs at a time.
	clipboardMu sync.Mutex

	// sshRegistry is the single service layer through which the SSH CRUD
	// endpoints mutate ssh.yaml. Nil when managed forwards are not
	// configured, in which case the four handlers return 503 rather than
	// panic.
	sshRegistry *sshfwd.Registry
	// sshStatus, when non-nil, reports the live condition of every managed
	// remote for /api/v1/status's "ssh" block.
	sshStatus func() []sshfwd.RemoteStatus

	// reauthGate, when set, reports whether the daemon's own token has gone
	// invalid and is awaiting re-authentication. /api/v1/token consults it so
	// a borrowing client is told "not authenticated" rather than handed a
	// token known to be dead — which matters now that a local daemon can be
	// the authority for a whole machine's worth of clients. Stored in an
	// atomic.Value because the daemon wires it after construction (the
	// lifecycle manager is built later in startup), concurrently with
	// requests already being served. *auth.LifecycleManager satisfies it.
	reauthGate atomic.Value // reauthGateHolder

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
	AgentCfg config.AgentConfig
	// APICfg is the loaded local-API-socket configuration, retained for the
	// config-download round-trip (like AgentCfg).
	APICfg config.APIConfig
	// APISocketPath is the resolved path for the local API socket. Empty
	// serves no socket. The caller resolves it (config.APISocketPath) so this
	// package holds no path-defaulting policy; when it is set, Start binds it
	// with owner-only permissions in addition to — or instead of — the
	// loopback TCP listener that WebCfg.Enabled controls.
	APISocketPath string
	// RemoteCfg is the local-only remote_config section, retained for the
	// config-download round-trip (like AgentCfg).
	RemoteCfg config.RemoteConfig
	// RemoteStatus, when non-nil, reports the remote-config overlay's last
	// fetch outcome; surfaced on /api/v1/status alongside the per-rule sync
	// state. It may return nil before the first fetch.
	RemoteStatus  func() *remoteconfig.Status
	Username      string
	TokenFilePath string
	Version       string
	// OpenBrowser, when non-nil, overrides how the remote-browse endpoint
	// launches URLs in this host's default browser (tests inject a fake).
	// Nil selects the real browser.OpenURL.
	OpenBrowser func(string) error
	// SendNotification, when non-nil, overrides how the remote-notify
	// endpoint delivers desktop notifications (tests inject a fake). Nil
	// selects the real notify.Send.
	SendNotification notify.Notifier
	// SetClipboard, when non-nil, overrides how the remote-clipboard
	// endpoint writes to this host's clipboard (tests inject a fake). Nil
	// selects the real clipboard.Set.
	SetClipboard clipboard.Setter
	// SSHRegistry, when non-nil, backs the /api/v1/ssh/remotes CRUD
	// endpoints. Nil (managed forwards not configured) makes those
	// endpoints return 503.
	SSHRegistry *sshfwd.Registry
	// SSHStatus, when non-nil, reports the live condition of every managed
	// remote for /api/v1/status's "ssh" block.
	SSHStatus func() []sshfwd.RemoteStatus
}

// NewServer creates a new web server.
func NewServer(sc ServerConfig) (*Server, error) {
	// The loopback invariant is checked only when the TCP listener is
	// actually going to be bound. A socket-only server has no listen address
	// to validate, and web.listen may legitimately be empty there.
	if sc.WebCfg.Enabled {
		if err := paths.ValidateLoopback(sc.WebCfg.Listen); err != nil {
			return nil, fmt.Errorf("web.listen: %w", err)
		}
	}
	if !sc.WebCfg.Enabled && sc.APISocketPath == "" {
		return nil, fmt.Errorf("web server has no surface to serve: neither web.enabled nor api.enabled")
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
		apiCfg:             sc.APICfg,
		webEnabled:         sc.WebCfg.Enabled,
		socketPath:         sc.APISocketPath,
		remoteCfg:          sc.RemoteCfg,
		remoteStatus:       sc.RemoteStatus,
		csrf:               NewCSRFStore(),
		oauth:              NewOAuthManager(),
		login:              auth.NewLoginTracker(sc.Vault),
		mux:                http.NewServeMux(),
		rules:              sc.Rules,
		kvMount:            sc.VaultCfg.KVMount,
		userPrefix:         sc.VaultCfg.UserPrefix,
		username:           sc.Username,
		authMethod:         auth.BaseMethod(sc.VaultCfg.AuthMethod),
		sealToken:          auth.SealTokenAtRest(sc.VaultCfg.AuthMethod),
		authMount:          sc.VaultCfg.AuthMount,
		authRole:           sc.VaultCfg.AuthRole,
		tokenFilePath:      sc.TokenFilePath,
		version:            sc.Version,
		vaultAddress:       sc.VaultCfg.Address,
		loginTextHTML:      renderMarkdown(sc.WebCfg.LoginText),
		secretViewTextHTML: renderMarkdown(sc.WebCfg.SecretViewText),
		authDone:           make(chan struct{}, 1),
		readyCh:            make(chan error, 1),
		openBrowser:        sc.OpenBrowser,
		sendNotification:   sc.SendNotification,
		setClipboard:       sc.SetClipboard,
		sshRegistry:        sc.SSHRegistry,
		sshStatus:          sc.SSHStatus,
	}
	if s.openBrowser == nil {
		s.openBrowser = browser.OpenURL
	}
	if s.sendNotification == nil {
		s.sendNotification = notify.Send
	}
	if s.setClipboard == nil {
		s.setClipboard = clipboard.Set
	}
	s.shutdownCtx, s.shutdownCancel = context.WithCancel(context.Background())

	s.registerRoutes()
	return s, nil
}

// registerRoutes wires the mux. It is split in two because the two listeners
// front genuinely different surfaces.
//
// The API routes are safe on either listener: they read and write daemon
// state for a caller that has already proved it is the owning user (loopback
// plus the Host allowlist for TCP; 0600 filesystem permissions for the
// socket).
//
// The UI routes are registered only when the TCP listener exists, because
// every one of them is meaningless or actively broken without it. The auth
// and OAuth handlers build redirect URIs from the bound listen address, so on
// a socket-only daemon they would hand the identity provider a URI pointing
// nowhere; the SPA and the enrolment routes it drives need a browser that
// cannot reach a Unix socket in the first place. Registering them anyway
// would mean publishing a login surface whose only possible outcome is a
// confusing failure.
func (s *Server) registerRoutes() {
	s.registerAPIRoutes()
	if s.webEnabled {
		s.registerUIRoutes()
	}
}

// registerUIRoutes wires the browser-facing surface: interactive login, the
// OAuth callbacks, the enrolment routes the SPA drives, and the SPA itself.
// Requires the TCP listener — see registerRoutes.
func (s *Server) registerUIRoutes() {
	// Auth routes — OIDC
	s.mux.HandleFunc("GET /auth/oidc/start", s.handleAuthStart)
	s.mux.HandleFunc("GET /auth/oidc/callback", s.handleAuthCallback)

	// Auth routes — LDAP
	s.mux.HandleFunc("POST /auth/ldap/login", s.requireCSRF(s.handleLDAPLogin))
	s.mux.HandleFunc("GET /auth/ldap/status", s.handleLDAPStatus)
	s.mux.HandleFunc("POST /auth/ldap/totp", s.requireCSRF(s.handleLDAPTOTP))

	// Auth routes — Token
	s.mux.HandleFunc("POST /auth/token/login", s.requireCSRF(s.handleTokenLogin))

	s.mux.HandleFunc("GET /api/v1/oauth/{rule}/start", s.handleOAuthStart)
	s.mux.HandleFunc("GET /api/v1/oauth/callback", s.handleOAuthCallback)

	// Enrolment prompt routes
	s.mux.HandleFunc("GET /api/v1/enrol/prompt", s.handleEnrolPrompt)
	s.mux.HandleFunc("POST /api/v1/enrol/secret", s.requireCSRF(s.handleEnrolSecret))

	// Enrolment runner routes. Flat keys use the single-segment {key} form;
	// one-level grouped keys ("databricks/prod") are served either by the
	// {key} form percent-encoded ("databricks%2Fprod", which Go unescapes into
	// PathValue without splitting) or by the parallel two-segment {group}/{name}
	// form. The segment counts don't collide, so both shapes resolve
	// unambiguously — see enrolKeyFromRequest.
	s.mux.HandleFunc("POST /api/v1/enrol/{key}/start", s.requireCSRF(s.handleEnrolStart))
	s.mux.HandleFunc("POST /api/v1/enrol/{key}/skip", s.requireCSRF(s.handleEnrolSkip))
	s.mux.HandleFunc("POST /api/v1/enrol/{key}/reset", s.requireCSRF(s.handleEnrolReset))
	s.mux.HandleFunc("GET /api/v1/enrol/{key}/status", s.handleEnrolStatus)
	s.mux.HandleFunc("POST /api/v1/enrol/{group}/{name}/start", s.requireCSRF(s.handleEnrolStart))
	s.mux.HandleFunc("POST /api/v1/enrol/{group}/{name}/skip", s.requireCSRF(s.handleEnrolSkip))
	s.mux.HandleFunc("POST /api/v1/enrol/{group}/{name}/reset", s.requireCSRF(s.handleEnrolReset))
	s.mux.HandleFunc("GET /api/v1/enrol/{group}/{name}/status", s.handleEnrolStatus)
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

// registerAPIRoutes wires the surface served on every listener — TCP, the
// local API socket, or both.
func (s *Server) registerAPIRoutes() {
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
	// Deliberately not CSRF-wrapped — see handleRemoteBrowse for the
	// rationale (bare-curl consumer over a forwarded socket; nothing
	// sensitive read or returned). Cross-site browser traffic is rejected
	// by the handler's Origin check instead, and the side effect is limited
	// by a strict http/https scheme allowlist.
	s.mux.HandleFunc("POST /api/v1/remote/browse", s.handleRemoteBrowse)
	// Sibling of remote/browse — same forwarded-socket consumer and same
	// no-CSRF / Origin-check posture (see handleRemoteNotify).
	s.mux.HandleFunc("POST /api/v1/remote/notify", s.handleRemoteNotify)
	// Third peer action, same posture again (see handleRemoteClipboard).
	s.mux.HandleFunc("POST /api/v1/remote/clipboard", s.handleRemoteClipboard)

	// Managed SSH forward CRUD — ordinary CSRF protection, not the
	// peer-action Origin-check exemption above (see ssh.go's header
	// comment for why).
	s.mux.HandleFunc("GET /api/v1/ssh/remotes", s.handleSSHList)
	s.mux.HandleFunc("POST /api/v1/ssh/remotes", s.requireCSRF(s.handleSSHAdd))
	s.mux.HandleFunc("PATCH /api/v1/ssh/remotes/{host}", s.requireCSRF(s.handleSSHPatch))
	s.mux.HandleFunc("DELETE /api/v1/ssh/remotes/{host}", s.requireCSRF(s.handleSSHDelete))
}

// Start begins serving HTTP on every configured listener. It signals
// WaitReady once all of them are bound, or sends the bind error so the caller
// can fail fast.
//
// There may be one or two: the loopback TCP listener (web.enabled) and the
// per-user Unix socket (api.enabled). They share one http.Server and one mux,
// so a request means the same thing whichever way it arrived — the surfaces
// differ in who can reach them, not in what they do.
func (s *Server) Start() error {
	lns, err := s.listen()
	if err != nil {
		s.readyCh <- err
		return err
	}

	s.startMu.Lock()
	s.server = &http.Server{
		Handler: s.middleware(s.mux),
	}
	srv := s.server
	s.startMu.Unlock()

	s.readyCh <- nil // signal ready

	// One goroutine per listener. Shutdown closes all of them, so every Serve
	// returns ErrServerClosed on a clean stop; anything else is a real
	// failure.
	var wg sync.WaitGroup
	errCh := make(chan error, len(lns))
	for _, ln := range lns {
		wg.Add(1)
		go func(ln net.Listener) {
			defer wg.Done()
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		}(ln)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Report the first listener failure immediately rather than waiting for
	// the others to finish. With two listeners, waiting would mean a dead TCP
	// listener goes unreported for as long as the socket keeps serving — the
	// daemon would look healthy while half its surface was gone. A failure on
	// either listener takes the whole server down: the surfaces are two doors
	// into one daemon, and limping along behind one of them hides the fault
	// from whoever needs to fix it.
	select {
	case err := <-errCh:
		srv.Close()
		<-done
		return err
	case <-done:
		select {
		case err := <-errCh:
			return err
		default:
			return nil
		}
	}
}

// listen binds every configured listener, cleaning up the ones it already
// opened if a later bind fails — a half-bound server would otherwise leave a
// socket file behind that the next start would have to treat as stale.
func (s *Server) listen() ([]net.Listener, error) {
	var lns []net.Listener
	closeAll := func() {
		for _, ln := range lns {
			ln.Close()
		}
	}

	if s.webEnabled {
		ln, err := net.Listen("tcp", s.cfg.Listen)
		if err != nil {
			return nil, err
		}
		// Preserve the configured hostname (e.g. "localhost") and only take
		// the port from the actual listener, so OIDC redirect URIs match
		// what users configure in Vault's allowed_redirect_uris.
		host, _, _ := net.SplitHostPort(s.cfg.Listen)
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		s.listenAddr = net.JoinHostPort(host, port)
		slog.Info("starting web UI", "listen", s.listenAddr)
		lns = append(lns, ln)
	}

	if s.socketPath != "" {
		// systemd socket activation first (Linux; inert elsewhere). An
		// inherited fd means systemd bound the socket before we started and
		// keeps it across our restarts, so borrowers queue instead of
		// getting ECONNREFUSED while the daemon is down. An activation
		// *error* is fatal, not a fallback: it means the fd exists but
		// violates an invariant (mode wider than 0600, wrong socket type),
		// and self-binding would both mask the unit misconfiguration and
		// fail anyway, since systemd owns the path.
		aln, actual, err := activatedAPIListener()
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("local API socket (systemd activation): %w", err)
		}
		if aln != nil {
			if actual != s.socketPath {
				// The socket unit's ListenStream=, not api.unix.path, decides
				// where the socket lives under activation. Report the truth
				// so status and clients looking at the config aren't misled.
				slog.Warn("systemd-activated API socket path differs from api.unix.path; the socket unit wins", "activated", actual, "configured", s.socketPath)
				s.socketPath = actual
			}
			slog.Info("serving local API socket from systemd activation", "path", actual)
			// socketBound stays false: systemd owns the node, and our
			// Shutdown must not unlink a socket it will keep using across
			// our restarts.
			lns = append(lns, aln)
		} else {
			ln, err := uds.Listen(s.socketPath)
			if err != nil {
				closeAll()
				if errors.Is(err, uds.ErrAlreadyListening) {
					return nil, fmt.Errorf("another dotvault is already serving the local API socket at %s", s.socketPath)
				}
				return nil, fmt.Errorf("local API socket: %w", err)
			}
			slog.Info("starting local API socket", "path", s.socketPath)
			// Record that *this* Server owns the socket node. Shutdown
			// consults this before unlinking — see socketBound.
			s.startMu.Lock()
			s.socketBound = true
			s.startMu.Unlock()
			lns = append(lns, ln)
		}
	}

	if len(lns) == 0 {
		return nil, fmt.Errorf("no listener configured")
	}
	return lns, nil
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
	// Shutdown closes the listeners, and net.UnixListener unlinks the socket
	// on close; Cleanup is the backstop for the paths that don't reach it
	// (a Shutdown that timed out, or a partially-bound Start). A leftover
	// node is not fatal — the next start detects it as stale — but leaving
	// one behind means the next start has to prove nobody is serving it.
	//
	// Gated on socketBound: a Server that never bound the socket must not
	// touch the node, because the reason it didn't bind is usually that
	// another live daemon owns it.
	s.startMu.Lock()
	bound := s.socketBound
	srv := s.server
	s.startMu.Unlock()
	if bound {
		defer uds.Cleanup(s.socketPath)
	}
	if srv != nil {
		return srv.Shutdown(ctx)
	}
	return nil
}

// activatedAPIListener claims the systemd-activated "api" socket, when one
// exists. An injectable var (matching openBrowser and friends) so tests can
// exercise the activated branch of listen() without a real systemd
// environment — the activation snapshot is process-global and once-guarded,
// which makes it unfakeable in-process.
var activatedAPIListener = func() (net.Listener, string, error) {
	return uds.ActivatedListener("api")
}

// reauthGateHolder wraps the gate so atomic.Value always stores the same
// concrete type (a bare interface value would panic on a type change).
type reauthGateHolder struct {
	gate interface{ NeedsReauth() bool }
}

// SetReauthGate wires the daemon's token lifecycle manager so /api/v1/token
// can decline to hand out a token the daemon already knows is dead. Safe to
// call while requests are in flight; the daemon calls it once, after the
// lifecycle manager is constructed.
func (s *Server) SetReauthGate(g interface{ NeedsReauth() bool }) {
	s.reauthGate.Store(reauthGateHolder{gate: g})
}

// needsReauth reports whether the daemon's token is known to be awaiting
// re-authentication. False when no gate is wired (a hand-constructed Server
// in tests, or the window before the daemon wires one), which preserves the
// pre-gate behaviour of trusting the in-memory token.
func (s *Server) needsReauth() bool {
	h, ok := s.reauthGate.Load().(reauthGateHolder)
	return ok && h.gate != nil && h.gate.NeedsReauth()
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
		p == "/api/v1/sync",
		p == "/api/v1/remote/browse",
		p == "/api/v1/remote/notify",
		p == "/api/v1/remote/clipboard":
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
	return s.loopbackHostname(host)
}

// loopbackHostname applies the loopback-identity allowlist to a bare
// hostname (no port, IPv6 brackets already unwrapped). Shared by the Host
// check above and the remote-browse Origin check, so both enforce the same
// notion of "names this daemon's loopback listener".
func (s *Server) loopbackHostname(host string) bool {
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
	// A socket-only daemon has no browsable address. Return "" rather than a
	// well-formed-looking "http:///" so callers (the daemon's browser-open on
	// startup and on re-auth) can tell there is nowhere to point a browser.
	if s.listenAddr == "" {
		return ""
	}
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

// getRules returns a copy of the current rules slice, safe for concurrent
// use against the daemon's runtime config refresh.
func (s *Server) getRules() []config.Rule {
	s.rulesMu.RLock()
	defer s.rulesMu.RUnlock()
	out := make([]config.Rule, len(s.rules))
	copy(out, s.rules)
	return out
}

// getSyncCfg returns the current sync section under the same lock as rules.
func (s *Server) getSyncCfg() config.SyncConfig {
	s.rulesMu.RLock()
	defer s.rulesMu.RUnlock()
	return s.syncCfg
}

// UpdateDynamicConfig swaps the rule and sync sections the web server serves.
// Called by the daemon's config-refresh loop when the remote overlay (or an
// edited local config) changes them at runtime, so the dashboard, the rules
// API, and the Effective Configuration download all reflect the live state.
func (s *Server) UpdateDynamicConfig(rules []config.Rule, syncCfg config.SyncConfig) {
	s.rulesMu.Lock()
	defer s.rulesMu.Unlock()
	s.rules = append([]config.Rule(nil), rules...)
	s.syncCfg = syncCfg
}

// UpdateEnrolments swaps the web enrolment runner for a changed enrolments
// map at runtime. It refuses (returning false) while an enrolment is
// mid-run, because InitEnrolments replaces the runner wholesale and would
// orphan the running engine's progress — the caller retries on its next
// refresh tick. The check-then-swap is not atomic with a concurrent start,
// but the refresh cadence makes that window academic and the consequence is
// a re-runnable enrolment, not corruption.
func (s *Server) UpdateEnrolments(ctx context.Context, enrolments map[string]config.Enrolment) bool {
	if runner := s.getEnrolRunner(); runner != nil && runner.AnyRunning() {
		return false
	}
	s.InitEnrolments(ctx, enrolments)
	return true
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
		// Drop any previous runner too: a runtime update that removes every
		// enrolment must not leave the old runner's states visible on
		// /api/v1/status and the enrolment page.
		s.enrolRunner = nil
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
