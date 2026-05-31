package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/goodtune/dotvault/internal/agent"
	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/enrol"
	"github.com/goodtune/dotvault/internal/loginsuppress"
	"github.com/goodtune/dotvault/internal/observability"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/regfile"
	"github.com/goodtune/dotvault/internal/sdnotify"
	"github.com/goodtune/dotvault/internal/sync"
	"github.com/goodtune/dotvault/internal/tokenwatch"
	"github.com/goodtune/dotvault/internal/tray"
	"github.com/goodtune/dotvault/internal/vault"
	"github.com/goodtune/dotvault/internal/web"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// version is injected at build time via -ldflags "-X main.version=...".
// Release tags are v-prefixed (v0.19.0) for Go-module consumption, but this
// value is the v-stripped semantic version (0.19.0): GoReleaser's {{.Version}}
// strips it and the Makefile strips it via sed, so it stays consistent across
// local and release builds. Every consumer (the version command, /api/v1/status,
// the OTel service.version attribute, the tray tooltip) re-emits it verbatim and
// must not assume or add a leading v.
var version = "dev"

var (
	flagConfig       string
	flagLogLevel     string
	flagLogFormat    string
	flagDryRun       bool
	flagRegOutput    string
	flagRegASCII     bool
	flagRegRegedit   bool
	flagImportOutput string
)

func main() {
	gui := isGUIBinary(os.Args[0])

	rootCmd := &cobra.Command{
		Use:   "dotvault",
		Short: "Vault-to-file secret synchronisation daemon",
		Long: `dotvault synchronises Vault KVv2 secrets into local config files.

Run with no subcommand prints this help. Use "dotvault run" to start the
long-lived daemon, "dotvault login-check" to validate (and optionally
renew) the cached token on an interactive login, "dotvault login" to
force a fresh login flow, or "dotvault enrol" to drive a credential
enrolment flow from the terminal.`,
		// Cobra's default RunE for a command with no Run/RunE prints help
		// when called bare, which is what we want — explicitly running the
		// daemon now requires `dotvault run`. The GUI-subsystem variant
		// (dotvaultw.exe) is wired below to default to the daemon instead,
		// because it's launched by double-click and has no console to show
		// help on.
		SilenceUsage: true,
	}
	if gui {
		rootCmd.RunE = runDaemon
	}

	rootCmd.PersistentFlags().StringVar(&flagConfig, "config", "", "override system config path")
	rootCmd.PersistentFlags().StringVar(&flagLogLevel, "log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&flagLogFormat, "log-format", "auto", "log format (auto, text, json); auto picks text on TTY, json otherwise")
	rootCmd.PersistentFlags().BoolVar(&flagDryRun, "dry-run", false, "show what would change without writing")

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run daemon in foreground",
		RunE:  runDaemon,
	}
	// --once on the daemon means "do one sync and exit" — keep it as a
	// subcommand-scoped flag so it doesn't pollute the global flag list.
	runCmd.Flags().Bool("once", false, "run one sync cycle and exit")

	rootCmd.AddCommand(
		runCmd,
		&cobra.Command{
			Use:   "sync",
			Short: "Run one sync cycle and exit",
			RunE:  runSync,
		},
		&cobra.Command{
			Use:   "login",
			Short: "Run the configured Vault login flow (always fresh)",
			Long: `Run the configured Vault login flow, ignoring any cached token.
Equivalent to "vault login -address <vault.address> -method <vault.auth_method>"
but driven by dotvault's loaded configuration (YAML or Group Policy).`,
			RunE: runLogin,
		},
		newLoginCheckCmd(),
		&cobra.Command{
			Use:   "status",
			Short: "Show auth and sync status",
			RunE:  runStatus,
		},
		newEnrolCmd(),
		newVersionCmd(),
		newRegExportCmd(),
		newRegImportCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func setupLogging() {
	var level slog.Level
	switch flagLogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	// --log-format forces a specific handler regardless of TTY state.
	// "auto" preserves the historical behaviour (text on TTY, JSON
	// otherwise) so existing systemd units and shell wrappers keep
	// working unchanged. Unknown values exit non-zero rather than
	// silently falling back to auto, so a typo in a system unit or
	// shell wrapper surfaces immediately instead of producing
	// surprising log output.
	useJSON := false
	switch strings.ToLower(flagLogFormat) {
	case "json":
		useJSON = true
	case "text":
		useJSON = false
	case "auto", "":
		useJSON = !isStderrTerminal()
	default:
		fmt.Fprintf(os.Stderr, "dotvault: invalid --log-format %q (want auto, text, or json)\n", flagLogFormat)
		os.Exit(2)
	}

	var handler slog.Handler
	if useJSON {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
}

// newVersionCmd builds the `dotvault version` command. The default form
// prints the version string; pass --json for a machine-readable form
// the OTel collector (and other tooling) can use to pin resource
// attributes deterministically.
func newVersionCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			if jsonOut {
				// Explicit struct so JSON field order is fixed
				// (version, service, go_version, os, arch) rather
				// than the alphabetical order encoding/json
				// applies to maps — easier to grep and copy/paste
				// for OTel resource attribute pipelines.
				type versionInfo struct {
					Version   string `json:"version"`
					Service   string `json:"service"`
					GoVersion string `json:"go_version"`
					OS        string `json:"os"`
					Arch      string `json:"arch"`
				}
				_ = json.NewEncoder(os.Stdout).Encode(versionInfo{
					Version:   version,
					Service:   "dotvault",
					GoVersion: runtime.Version(),
					OS:        runtime.GOOS,
					Arch:      runtime.GOARCH,
				})
				return
			}
			fmt.Println(version)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit version metadata as JSON")
	return cmd
}

func loadConfig() (*config.Config, error) {
	path := flagConfig
	if path == "" {
		path = paths.SystemConfigPath()
	}
	return config.LoadSystem(path)
}

func runDaemon(cmd *cobra.Command, args []string) error {
	setupLogging()

	once, _ := cmd.Flags().GetBool("once")
	if once {
		return runSync(cmd, args)
	}

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the systemd watchdog loop as early as possible. The loop
	// is a no-op outside systemd and when WATCHDOG_USEC/NOTIFY_SOCKET
	// are unset, so calling it unconditionally is safe. We start it
	// before Vault auth / initial sync because a slow authentication
	// or first sync would otherwise miss the watchdog window
	// (WatchdogSec=120s by default) and systemd would restart the
	// process mid-startup. sd_notify(READY=1) is still delayed until
	// after auth + initial sync further down.
	go sdnotify.WatchdogLoop(ctx)

	obsProvider := initObservability(ctx, cfg.Observability)
	defer shutdownObservability(obsProvider)
	// Zero out the bearer-token map now that the SDK has
	// consumed it. cfg lives for the daemon's full lifetime;
	// keeping Headers in the heap-resident Config struct gives a
	// future log statement, JSON encoder, or debug handler a
	// path to exfiltrate the credential. The OTel SDK keeps its
	// own copy internally.
	cfg.Observability.Headers = nil

	// Handle signals. SIGHUP triggers an immediate ~/.vault-token re-read
	// via the LifecycleManager so a fresh token written by `dotvault
	// login` is picked up within seconds, without waiting for the
	// 5-minute tick. This is the manual counterpart to the in-process
	// inotify watcher (internal/tokenwatch) wired in further down, which
	// performs the same re-read automatically on token-file changes.
	// Full config reload on SIGHUP is still not implemented.
	//
	// lmPtr bridges the asynchronous signal goroutine (set up here, before
	// any Vault work) and the LifecycleManager (constructed only after
	// auth completes further down). A SIGHUP arriving before lm exists is
	// metered and logged as a debug no-op rather than dropped silently.
	var lmPtr atomic.Pointer[auth.LifecycleManager]
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				slog.Info("received shutdown signal", "signal", sig)
				cancel()
			case syscall.SIGHUP:
				observability.RecordSIGHUP(ctx)
				if lm := lmPtr.Load(); lm != nil {
					slog.Info("received SIGHUP, re-reading vault token file")
					lm.Reload()
				} else {
					slog.Debug("received SIGHUP before lifecycle manager is ready; ignoring")
				}
			}
		}
	}()

	username, err := paths.Username()
	if err != nil {
		return fmt.Errorf("resolve username: %w", err)
	}

	vc, err := vault.NewClient(vault.Config{
		Address:       cfg.Vault.Address,
		CACert:        cfg.Vault.CACert,
		TLSSkipVerify: cfg.Vault.TLSSkipVerify,
	})
	if err != nil {
		return fmt.Errorf("create vault client: %w", err)
	}

	tokenPath := paths.VaultTokenPath()

	// Try to reuse an existing token before starting any auth flow.
	authenticated := false
	if token := auth.ResolveToken(tokenPath); token != "" {
		vc.SetToken(token)
		if _, err := vc.LookupSelf(ctx); err == nil {
			slog.Info("reusing existing vault token")
			authenticated = true
		} else {
			slog.Warn("existing token invalid, proceeding to fresh auth", "error", err)
			vc.SetToken("")
		}
	}

	// Create sync engine (safe before authentication — no Vault calls until RunLoop).
	statePath := filepath.Join(paths.CacheDir(), "state.json")
	engine := sync.NewEngine(cfg, vc, username, statePath)
	engine.DryRun = flagDryRun

	// Build the SSH agent backend if enabled. Construction is side-effect-free
	// (no Vault calls — vault-ca ephemeral keys are generated in memory), so
	// it is safe before authentication and lets the web server surface agent
	// status. The transport listener itself is started only after the first
	// successful Vault auth, below.
	var agentSvc *agent.Service
	if cfg.Agent.Enabled {
		agentSvc, err = agent.NewService(cfg.Agent, vc, cfg.Vault.KVMount, cfg.Vault.UserPrefix, username, nil)
		if err != nil {
			return fmt.Errorf("ssh agent: %w", err)
		}
	}

	// Start web UI if enabled. We start it before authentication so it can
	// serve the OIDC browser-based login flow.
	var webServer *web.Server
	if cfg.Web.Enabled {
		webCfg := web.ServerConfig{
			WebCfg:        cfg.Web,
			VaultCfg:      cfg.Vault,
			SyncCfg:       cfg.Sync,
			ObsCfg:        cfg.Observability,
			AgentCfg:      cfg.Agent,
			Rules:         cfg.Rules,
			Vault:         vc,
			Engine:        engine,
			Username:      username,
			TokenFilePath: tokenPath,
			Version:       version,
		}
		if agentSvc != nil {
			webCfg.Agent = agentSvc.Backend
		}
		webServer, err = web.NewServer(webCfg)
		if err != nil {
			slog.Error("failed to create web server", "error", err)
		} else {
			go func() {
				if err := webServer.Start(); err != nil {
					slog.Error("web server error", "error", err)
				}
			}()
			defer func() {
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer shutdownCancel()
				webServer.Shutdown(shutdownCtx)
			}()

			// Wait for the server to start listening before proceeding.
			// This ensures WaitForAuth cannot block if the server failed to bind.
			if err := webServer.WaitReady(); err != nil {
				return fmt.Errorf("web server failed to start: %w", err)
			}
		}
	}

	// Authenticate if needed.
	if !authenticated {
		if webServer != nil {
			// All auth methods go through the web UI when enabled.
			url := webServer.URL()
			slog.Info("opening browser for authentication", "url", url)
			if err := browser.OpenURL(url); err != nil {
				slog.Warn("failed to open browser, please visit URL manually", "url", url, "error", err)
			}
			if err := webServer.WaitForAuth(ctx); err != nil {
				return fmt.Errorf("web-based authentication: %w", err)
			}
		} else if !isInteractive() {
			// Headless: no web UI to drive auth and no terminal to prompt
			// on. Don't crash and don't spam the logs trying to read from
			// a closed stdin — stay up so an external interactive facility
			// (e.g. a login profile that runs `dotvault sync`) can write
			// the token, and a daemon restart will pick it up.
			slog.Warn("no vault token available and no interactive facility (web UI unavailable, stdin is not a terminal); daemon will idle until shutdown")
			<-ctx.Done()
			return nil
		} else {
			// Traditional auth flow (OIDC with ephemeral listener, LDAP
			// prompt, or token file).
			mgr := &auth.Manager{
				VaultClient:   vc,
				TokenFilePath: tokenPath,
				AuthMethod:    cfg.Vault.AuthMethod,
				AuthMount:     cfg.Vault.AuthMount,
				AuthRole:      cfg.Vault.AuthRole,
				Username:      username,
			}
			if err := mgr.Authenticate(ctx); err != nil {
				return fmt.Errorf("authenticate: %w", err)
			}
		}
	}

	// Start token lifecycle manager. Wire the token-file path so that on
	// detecting an invalid token the manager can pick up a fresh value
	// written by an external facility (`dotvault login`) before forcing a
	// full re-auth. In web mode register a callback that clears the
	// in-memory token, invalidating any browser session sitting on a
	// stale "logged-in" view.
	lm := auth.NewLifecycleManager(vc, 5*time.Minute, cfg.Vault.DisableTokenRenewal)
	lm.SetTokenFilePath(tokenPath)
	if webServer != nil {
		lm.SetOnReauth(webServer.ForceReauth)
	}
	lmPtr.Store(lm)
	lifecycleErrCh := lm.Start(ctx)

	// Start the SSH agent listener now that we hold a Vault token. The gate is
	// wired before the listener accepts connections so a Sign issued during a
	// token refresh blocks briefly on the lifecycle manager instead of failing.
	// Run supervises the listener (restart-on-terminate) until ctx is
	// cancelled; the backend persists across token refreshes without a restart.
	if agentSvc != nil {
		agentSvc.Backend.SetReauthGate(lm)
		go agentSvc.Run(ctx)
		slog.Info("ssh agent enabled", "endpoint", agentSvc.Endpoint())
	}

	// Watch the token file for replacement and nudge the lifecycle
	// manager to re-read it immediately. This is the in-process
	// analogue of the old systemd `.path` unit (which SIGHUP'd the
	// daemon on every ~/.vault-token change) and is complementary to
	// the still-present SIGHUP handler. On Linux it uses inotify on the
	// token file's parent directory; on other platforms it is a no-op
	// that blocks until shutdown. Creation and update events trigger a
	// reload; deletes are ignored so the daemon keeps using its current
	// token until a new one is written.
	go func() {
		onTokenChange := func() {
			slog.Debug("vault token file changed, re-reading")
			lm.Reload()
		}
		if err := tokenwatch.Watch(ctx, tokenPath, onTokenChange); err != nil && ctx.Err() == nil {
			slog.Warn("token-file watcher stopped", "error", err)
		}
	}()

	// Start refresh manager for any enrolment whose engine rotates its own
	// credentials (currently JFrog). Failures are logged and retried on the
	// next tick — never fatal to the daemon.
	rm := enrol.NewRefreshManager(
		vc,
		cfg.Vault.KVMount,
		cfg.Vault.UserPrefix+username+"/",
		cfg.Enrolments,
		5*time.Minute,
	)
	rm.Start(ctx)

	// Start watch manager for enrolments that mirror an upstream Vault
	// secret (currently the copy engine). Polls at the sync interval and,
	// where Vault Enterprise events are available, reacts to source-write
	// events within seconds. Distinct from RefreshManager because the two
	// concerns (token rotation vs. data mirroring) are orthogonal.
	wm := enrol.NewWatchManager(
		vc,
		cfg.Vault.KVMount,
		cfg.Vault.UserPrefix+username+"/",
		username,
		cfg.Enrolments,
		cfg.Sync.Interval,
	)
	wm.Start(ctx)
	go func() {
		const reauthCooldown = 10 * time.Minute
		var lastReauthOpen time.Time

		for err := range lifecycleErrCh {
			slog.Warn("token lifecycle error, re-authentication may be needed", "error", err)
			if webServer != nil {
				if lastReauthOpen.IsZero() || time.Since(lastReauthOpen) >= reauthCooldown {
					lastReauthOpen = time.Now()
					url := webServer.URL()
					slog.Info("opening browser for re-authentication", "url", url)
					if err := browser.OpenURL(url); err != nil {
						slog.Warn("failed to open browser for re-auth", "url", url, "error", err)
					}
				}
			}
		}
	}()

	if webServer != nil {
		// Web mode: let the frontend drive enrolments.
		webServer.InitEnrolments(ctx, cfg.Enrolments)

		waitDone := make(chan struct{})
		go func() {
			webServer.WaitForEnrolments()
			close(waitDone)
		}()

		select {
		case <-waitDone:
		case <-ctx.Done():
			slog.Info("stopping enrolment wait due to shutdown")
		}
	} else if !isInteractive() {
		// Headless CLI mode: no web UI, no terminal. Skip the enrolment
		// wizard entirely — engines that prompt would either fail or hang
		// without a TTY. The RefreshManager started above continues to
		// rotate already-enrolled credentials, but enrolment/config
		// changes are not reloaded in this path and require a daemon
		// restart to take effect.
		if len(cfg.Enrolments) > 0 {
			slog.Info("skipping enrolment wizard: stdin is not a terminal and web UI is not running")
		}
	} else {
		// CLI mode: terminal-based wizard.
		enrolIO := enrol.IO{
			Out:      os.Stderr,
			Browser:  browser.OpenURL,
			Log:      slog.Default(),
			Username: username,
			PromptSecret: func(label string) (string, error) {
				fd := int(os.Stdin.Fd())
				if !term.IsTerminal(fd) {
					return "", fmt.Errorf("cannot prompt for passphrase: stdin is not a terminal (use web UI or set passphrase to unsafe)")
				}
				fmt.Fprintf(os.Stderr, "%s ", label)
				pass, err := term.ReadPassword(fd)
				fmt.Fprintln(os.Stderr) // newline after hidden input
				if err != nil {
					return "", err
				}
				return string(pass), nil
			},
		}
		enrolMgr := enrol.NewManager(enrol.ManagerConfig{
			Enrolments: cfg.Enrolments,
			KVMount:    cfg.Vault.KVMount,
			UserPrefix: cfg.Vault.UserPrefix + username + "/",
		}, vc, enrolIO)
		if _, err := enrolMgr.CheckAll(ctx); err != nil {
			slog.Warn("enrolment check failed", "error", err)
		}

		// Background goroutine: reload config on each tick and re-check enrolments.
		configPath := flagConfig
		if configPath == "" {
			configPath = paths.SystemConfigPath()
		}
		go func() {
			ticker := time.NewTicker(cfg.Sync.Interval)
			defer ticker.Stop()
			lastEnrolments := cfg.Enrolments
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					reloaded, err := config.LoadSystem(configPath)
					if err != nil {
						observability.RecordConfigReload(ctx, "error")
						slog.Warn("config reload failed", "error", err)
						continue
					}
					if !reflect.DeepEqual(reloaded.Enrolments, lastEnrolments) {
						observability.RecordConfigReload(ctx, "applied")
						slog.Info("enrolments config changed, re-checking")
						enrolMgr.UpdateConfig(reloaded.Enrolments)
						rm.UpdateConfig(reloaded.Enrolments)
						wm.UpdateConfig(reloaded.Enrolments)
						lastEnrolments = reloaded.Enrolments
					} else {
						observability.RecordConfigReload(ctx, "no_change")
					}
					if ok, err := enrolMgr.CheckAll(ctx); err != nil {
						slog.Warn("enrolment check failed", "error", err)
					} else if ok {
						engine.TriggerSync()
					}
				}
			}
		}()
	}

	slog.Info("starting dotvault daemon", "version", version, "user", username)

	// The sync engine drives the initial RunOnce internally; the
	// AfterInitialSync hook below fires the daemon's readiness
	// signals (web-server /readyz gate, sd_notify(READY=1))
	// exactly once, synchronously, between the initial cycle and
	// the long-running loop. Partial first-cycle failures still
	// count as "ready": the daemon has made its best attempt and
	// future cycles will retry; we don't want a single transient
	// error to wedge readiness forever.
	afterInitial := func() {
		// The engine already gates on ctx.Err() before calling
		// the hook, but a future refactor that invokes it via
		// another path could bypass that guard. Re-check here so
		// we never sequence READY=1 → STOPPING=1 in the same
		// systemd start-up window — that confuses unit-state
		// accounting and any After=dotvault.service ordering.
		if ctx.Err() != nil {
			return
		}
		if webServer != nil {
			webServer.MarkInitialSyncComplete()
		}
		// sd_notify(READY=1) is sent here, after auth and the
		// initial sync, so anything depending on dotvault.service
		// blocks until secrets are actually on disk. The
		// watchdog ticker was started earlier (right after ctx)
		// so a long startup doesn't miss the watchdog window.
		// Both calls are no-ops on non-Linux and when
		// NOTIFY_SOCKET is unset; a non-nil return from Ready()
		// means a genuine socket write failure (warn loudly so
		// the systemd "start-limit-hit" log has a breadcrumb).
		if err := sdnotify.Ready(); err != nil {
			slog.Warn("sd_notify READY=1 failed; systemd unit may time out", "error", err)
		}
	}

	// Run the sync engine on a goroutine and the tray (Windows) or a
	// blocking ctx-wait (everything else) on the main goroutine. The tray
	// must own the main goroutine because the Win32 message pump requires
	// runtime.LockOSThread on the same OS thread that creates the window.
	// If the sync loop exits unexpectedly we cancel the context to wake
	// tray.Run up and let the daemon shut down cleanly.
	loopErrCh := make(chan error, 1)
	go func() {
		loopErrCh <- engine.RunLoop(ctx, sync.AfterInitialSync(afterInitial))
		cancel()
	}()

	trayCfg := tray.Config{
		Tooltip: fmt.Sprintf("dotvault %s", version),
		OnExit: func() {
			slog.Info("exit requested from tray")
			cancel()
		},
	}
	if webServer != nil {
		trayCfg.WebURL = webServer.URL()
	}
	if err := tray.Run(ctx, trayCfg); err != nil {
		// A failed tray (e.g. RegisterClassEx, CreateWindow, or
		// Shell_NotifyIcon refused on a session that has no shell) must
		// not take the daemon down with it. Log and fall back to a plain
		// ctx wait so the sync engine keeps running headlessly until
		// signal/lifecycle cancels it.
		slog.Warn("tray exited with error; daemon continues running headlessly", "error", err)
		if ctx.Err() == nil {
			<-ctx.Done()
		}
	}

	// Tray returned because the user picked Exit or ctx was cancelled
	// elsewhere (signal handler, lifecycle manager, headless fallback).
	// Stop the sync loop and propagate its result. Notify systemd we're
	// stopping so the unit state reflects the shutdown sequence rather
	// than appearing to crash.
	_ = sdnotify.Stopping()
	cancel()
	return <-loopErrCh
}

func runSync(cmd *cobra.Command, args []string) error {
	setupLogging()

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx := context.Background()

	// Cron-style one-shot invocations still need to push their metrics
	// out before exit. The deferred Shutdown invokes ForceFlush
	// internally, so the last batch makes it out before the process
	// exits.
	obsProvider := initObservability(ctx, cfg.Observability)
	defer shutdownObservability(obsProvider)
	// Zero out the bearer-token map post-Init for the same
	// reason as the daemon path — keep credentials out of the
	// heap-resident Config struct.
	cfg.Observability.Headers = nil

	username, vc, err := authenticate(ctx, cfg)
	if err != nil {
		return err
	}

	statePath := filepath.Join(paths.CacheDir(), "state.json")
	engine := sync.NewEngine(cfg, vc, username, statePath)
	engine.DryRun = flagDryRun

	slog.Info("running single sync cycle", "user", username)
	return engine.RunOnce(ctx)
}

func runStatus(cmd *cobra.Command, args []string) error {
	setupLogging()

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx := context.Background()

	// Try to connect to Vault
	vc, err := vault.NewClient(vault.Config{
		Address:       cfg.Vault.Address,
		CACert:        cfg.Vault.CACert,
		TLSSkipVerify: cfg.Vault.TLSSkipVerify,
	})
	if err != nil {
		fmt.Printf("Vault connection: ERROR (%v)\n", err)
		return nil
	}

	token := auth.ResolveToken(paths.VaultTokenPath())
	if token == "" {
		fmt.Println("Auth: not authenticated (no token)")
	} else {
		vc.SetToken(token)
		secret, err := vc.LookupSelf(ctx)
		if err != nil {
			fmt.Printf("Auth: token invalid (%v)\n", err)
		} else {
			ttl, _ := secret.Data["ttl"]
			fmt.Printf("Auth: authenticated (TTL: %v)\n", ttl)
		}
	}

	// Show sync state
	statePath := filepath.Join(paths.CacheDir(), "state.json")
	store := sync.NewStateStore(statePath)
	store.Load()

	fmt.Println("\nSync Rules:")
	for _, rule := range cfg.Rules {
		rs := store.Get(rule.Name)
		if rs.VaultVersion == 0 {
			fmt.Printf("  %-20s never synced\n", rule.Name)
		} else {
			fmt.Printf("  %-20s v%d synced %s\n", rule.Name, rs.VaultVersion, rs.LastSynced.Format("2006-01-02 15:04:05"))
		}
	}

	printAgentStatus(ctx, cfg)

	return nil
}

// printAgentStatus renders the SSH agent section of `dotvault status`. The
// agent is only relevant when configured: if `agent.enabled` is false there is
// nothing to show and we never touch the endpoint. When enabled, status acts as
// an agent *client* — it dials the running daemon's socket / pipe and lists the
// identities being served (the `ssh-add -l` equivalent), so the output reflects
// what the daemon actually offers, including a minted certificate's true
// remaining validity. status never creates the endpoint; a failure to connect
// is therefore unexpected (the daemon isn't running, or hasn't authenticated
// far enough to start the listener) and is reported as such.
func printAgentStatus(ctx context.Context, cfg *config.Config) {
	if !cfg.Agent.Enabled {
		return
	}
	endpoint := agent.ResolveEndpoint(cfg.Agent)
	fmt.Println("\nSSH Agent:")
	fmt.Printf("  endpoint: %s\n", endpoint)

	ids, err := agent.QueryListening(ctx, endpoint)
	if err != nil {
		fmt.Printf("  unreachable: %v\n", err)
		fmt.Println("  (agent is enabled but the daemon is not serving this endpoint — is `dotvault run` active?)")
		return
	}
	if len(ids) == 0 {
		fmt.Println("  (no identities loaded)")
		return
	}
	for _, id := range ids {
		line := "  " + id.Fingerprint
		if id.Comment != "" {
			line += " " + id.Comment
		}
		if id.IsCert {
			if id.ExpiresAt != "" {
				line += fmt.Sprintf(" (cert, expires %s)", id.ExpiresAt)
			} else {
				line += " (cert)"
			}
		}
		fmt.Println(line)
	}
}

// runLogin implements `dotvault login` — always forces a fresh login via
// the configured method, ignoring any cached token. This mirrors
// `vault login -address <vault.address> -method <vault.auth_method>` but
// is driven from dotvault's loaded configuration (YAML or GPO) so the
// user doesn't have to re-specify the same parameters on the CLI.
func runLogin(cmd *cobra.Command, args []string) error {
	setupLogging()

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	username, err := paths.Username()
	if err != nil {
		return fmt.Errorf("resolve username: %w", err)
	}

	vc, err := vault.NewClient(vault.Config{
		Address:       cfg.Vault.Address,
		CACert:        cfg.Vault.CACert,
		TLSSkipVerify: cfg.Vault.TLSSkipVerify,
	})
	if err != nil {
		return fmt.Errorf("create vault client: %w", err)
	}

	mgr := &auth.Manager{
		VaultClient:   vc,
		TokenFilePath: paths.VaultTokenPath(),
		AuthMethod:    cfg.Vault.AuthMethod,
		AuthMount:     cfg.Vault.AuthMount,
		AuthRole:      cfg.Vault.AuthRole,
		Username:      username,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := mgr.Login(ctx); err != nil {
		// Ctrl-C should exit quietly — the user knows they cancelled.
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("login: %w", err)
	}
	return nil
}

// newLoginCheckCmd defines the `login-check` subcommand. The body of
// the work lives in runLoginCheck; this builder exists so the command
// can carry its own --quiet flag without polluting the top-level flag
// namespace shared by every other subcommand.
func newLoginCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login-check",
		Short: "Validate cached token on interactive login, renew or re-login as needed",
		Long: `Intended to be wired into shell rc / login-profile scripts via a thin
wrapper that gates on interactivity, TTY, and daemon state. This binary
trusts those preconditions and does not re-check them.

Behaviour:
  - A suppression marker at
    ${XDG_STATE_HOME:-$HOME/.local/state}/dotvault/login-check-suppress
    (overridable with DOTVAULT_SUPPRESS_MARKER) is checked first. If
    the marker's mtime is within DOTVAULT_SUPPRESS_HOURS (default 6),
    the command exits silently. A future mtime is treated as stale so
    clock skew or backup restores cannot lock suppression on.
  - Otherwise: if the cached token is valid and still within the first
    half of its creation TTL, exit clean. Past halfway, attempt
    renewal; if renewal fails but the token is still valid, warn with
    the absolute expiry time. If no valid token, print a short
    explanation of why an authentication prompt is about to appear
    (yellow on a colour-capable TTY, plain text otherwise) and then
    run the configured fresh-auth flow. Pass --quiet to suppress that
    explanation when the caller has its own context display.
  - On every exit past the suppression check the marker is refreshed,
    so a declined login, a failed login, an internal error, or Ctrl+C
    all silence the next shell in the window. Ctrl+C exits immediately
    without requiring an additional Enter.

Exits 0 on suppressed, success, decline, cancellation, or expected
authentication failure. Exits 1 on invalid DOTVAULT_SUPPRESS_HOURS or
genuine internal errors.`,
		RunE: runLoginCheck,
	}
	cmd.Flags().Bool("quiet", false, "suppress the explanation printed before triggering an interactive login")
	return cmd
}

// runLoginCheck implements `dotvault login-check`, intended to be wired
// into shell rc / login-profile scripts via a thin wrapper that handles
// environment gating (interactive shell, TTYs, daemon active). The
// binary trusts those preconditions and never re-checks them — see the
// loginsuppress package and the login-check Long help for the full
// contract.
func runLoginCheck(cmd *cobra.Command, args []string) error {
	quiet, _ := cmd.Flags().GetBool("quiet")

	// Catch SIGINT before any other work so a Ctrl+C arriving during
	// setup (env parse, marker stat, term.GetState) cannot fall through
	// to Go's default handler and bypass the terminal-restore +
	// marker-refresh contract. The handler goroutine is started later,
	// once it has marker path / saved terminal state to act on; signals
	// arriving before then sit in the buffered channel and are picked
	// up the moment the goroutine starts. We register only SIGINT
	// because the contract is exclusively about user-initiated
	// cancellation — SIGTERM from a session/process manager should
	// follow Go's default (terminate with non-zero status) rather than
	// silently extending suppression as if the check succeeded.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT)
	defer signal.Stop(sigCh)

	window, err := loginsuppress.Window()
	if err != nil {
		// Invalid DOTVAULT_SUPPRESS_HOURS: surface the problem loudly so
		// the user fixes it. Bypass cobra's error printing so the message
		// reads exactly as specified, and skip marker refresh — leaving
		// the marker untouched means the next shell will also raise the
		// error rather than masking it.
		fmt.Fprintln(os.Stderr, "dotvault: "+err.Error())
		os.Exit(1)
	}

	markerPath := loginsuppress.Path()
	if loginsuppress.IsFresh(markerPath, window, time.Now()) {
		// Suppressed: another invocation within the window already
		// handled (or attempted) the check. Exit silently without
		// touching the marker — refreshing here would extend
		// suppression indefinitely under tight shell-fanout loops.
		// setupLogging() is deliberately deferred until past this point
		// so the suppressed fast path performs zero side effects (no
		// slog handler swap, no future startup-line leakage into shell
		// scrollback).
		return nil
	}

	setupLogging()

	// From here on every exit path refreshes the marker so the next
	// shell startup is silent. The signal handler below explicitly
	// refreshes too (defers do not run after os.Exit).
	defer func() {
		if rerr := loginsuppress.Refresh(markerPath); rerr != nil {
			slog.Warn("failed to refresh login-check suppression marker", "error", rerr, "path", markerPath)
		}
	}()

	// Capture the terminal state now so the SIGINT handler can restore
	// it even if mgr.Login is mid-prompt (term.ReadPassword puts the
	// terminal into a no-echo mode that bash cannot read out of cleanly
	// on its own). If stdin isn't a TTY, GetState returns an error and
	// we simply leave savedTermState nil.
	fd := int(os.Stdin.Fd())
	var savedTermState *term.State
	if st, gerr := term.GetState(fd); gerr == nil {
		savedTermState = st
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Now start the handler goroutine. It also calls cancel() — os.Exit
	// usually wins the race, but if an in-flight Vault call happens to
	// unwind first it will see context.Canceled and the
	// loginCheckCancelled() backstops below can suppress its error
	// message before exit. The password prompt inside the LDAP flow
	// blocks in a read syscall that does not observe context
	// cancellation, so the only reliable way to honour the
	// "Ctrl+C exits immediately, no extra Enter" contract is to
	// short-circuit to os.Exit from this goroutine.
	go func() {
		select {
		case <-sigCh:
			cancel()
			if savedTermState != nil {
				_ = term.Restore(fd, savedTermState)
				fmt.Fprintln(os.Stderr)
			}
			_ = loginsuppress.Refresh(markerPath)
			os.Exit(0)
		case <-ctx.Done():
		}
	}()

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	vc, err := vault.NewClient(vault.Config{
		Address:       cfg.Vault.Address,
		CACert:        cfg.Vault.CACert,
		TLSSkipVerify: cfg.Vault.TLSSkipVerify,
	})
	if err != nil {
		return fmt.Errorf("create vault client: %w", err)
	}

	tokenPath := paths.VaultTokenPath()
	token := auth.ResolveToken(tokenPath)
	// loginReason captures why we're about to drop the user into an
	// interactive login prompt — printed (yellow on a colour-capable
	// TTY) before the prompt unless --quiet is set, so a shell-startup
	// invocation doesn't surface a context-free password prompt.
	// Default covers the "no cached token" path; the branches below
	// overwrite it for the expired / revoked cases.
	loginReason := "no cached Vault token was found"
	if token != "" {
		vc.SetToken(token)
		secret, lookupErr := vc.LookupSelf(ctx)
		if lookupErr == nil {
			// Token valid. Decide whether to renew based on how much of
			// the original TTL has been consumed.
			handled, err := handleValidToken(ctx, vc, secret)
			if err != nil {
				// Renewal failed but token still valid — already warned
				// inside handleValidToken; exit 0 anyway.
				return nil
			}
			if handled {
				return nil
			}
			loginReason = "the cached Vault token has expired"
		} else if vault.IsForbidden(lookupErr) {
			// 403: the cached token is revoked or otherwise invalid.
			// Clear it and fall through to the interactive login flow.
			vc.SetToken("")
			loginReason = "the cached Vault token is no longer valid"
		} else {
			// Backstop for context.Canceled: the SIGINT handler usually
			// wins the race and os.Exits before this point, but if
			// LookupSelf happens to unwind first we don't want a
			// cancellation message in the shell scrollback.
			if loginCheckCancelled(ctx, lookupErr) {
				return nil
			}
			// Transient Vault/TLS/network error. A shell startup hook
			// should not invent an interactive login prompt every time
			// the user opens a terminal while their VPN is reconnecting
			// — warn and exit clean, leaving the cached token in place
			// for the next shell invocation to retry.
			fmt.Fprintf(os.Stderr, "vault token check failed (will retry on next login): %v\n", lookupErr)
			return nil
		}
	}

	// No valid token: preflight Vault connectivity before falling through
	// to the configured login flow. Without this, an LDAP login would
	// prompt for the user's password and only then discover that the
	// network/TLS/Vault layer is broken — login-check is supposed to be
	// quiet on a flaky boot, not interrogate the user mid-coffee.
	// `Sys().Health` is unauthenticated and exposed on every Vault
	// install, so it's the cheapest discriminator between "Vault is
	// reachable, our token is just gone" and "Vault itself is
	// unreachable".
	healthCtx, healthCancel := context.WithTimeout(ctx, 5*time.Second)
	_, healthErr := vc.ServerHealth(healthCtx)
	healthCancel()
	if healthErr != nil {
		// Backstop for context.Canceled propagating from the outer
		// context (cancelled by the SIGINT handler). os.Exit usually
		// wins the race, but if the health probe unwinds first we
		// suppress the warning to keep shell scrollback clean.
		if loginCheckCancelled(ctx, healthErr) {
			return nil
		}
		fmt.Fprintf(os.Stderr, "vault unreachable (will retry on next login): %v\n", healthErr)
		return nil
	}

	username, err := paths.Username()
	if err != nil {
		return fmt.Errorf("resolve username: %w", err)
	}
	mgr := &auth.Manager{
		VaultClient:   vc,
		TokenFilePath: tokenPath,
		AuthMethod:    cfg.Vault.AuthMethod,
		AuthMount:     cfg.Vault.AuthMount,
		AuthRole:      cfg.Vault.AuthRole,
		Username:      username,
	}
	if !quiet {
		printLoginNotice(os.Stderr, loginReason)
	}
	if err := mgr.Login(ctx); err != nil {
		// Backstop for context.Canceled. The SIGINT handler normally
		// reaches os.Exit before mgr.Login returns, so this branch
		// only fires if a Vault-side cancellation unwinds first;
		// either way we exit silently.
		if loginCheckCancelled(ctx, err) {
			return nil
		}
		// Login was attempted and failed for an expected reason (user
		// declined, wrong password, auth method refused). Exit 0 so
		// shell startup proceeds normally; the marker (refreshed via
		// defer above) silences subsequent shells in the window.
		hours := int(window / time.Hour)
		fmt.Fprintf(os.Stderr,
			"dotvault: login-check declined or failed (%v); suppressed for %dh (rm %s to retry)\n",
			err, hours, markerPath)
		return nil
	}
	return nil
}

// handleValidToken inspects a successful LookupSelf response and decides
// whether to renew the token.
//
// Returns (handled=true, err=nil) when the token is fresh enough to leave
// alone, is non-expiring (no TTL field, or ttl<=0 without an
// expire_time), or was renewed successfully.
//
// Returns (handled=false, err=nil) when the token has actually expired
// (ttl<=0 with a concrete expire_time) — the caller falls through to the
// configured login flow.
//
// Returns (handled=true, err=non-nil) when renewal was attempted and
// failed but the cached token is still valid; the function has already
// warned with the absolute expiry time and the caller should exit clean.
func handleValidToken(ctx context.Context, vc *vault.Client, secret *vaultapi.Secret) (bool, error) {
	ttlSec, ok := readSecondsField(secret.Data, "ttl")
	if !ok {
		// No TTL field at all — non-expiring (e.g. root). Nothing to do.
		return true, nil
	}
	ttl := time.Duration(ttlSec) * time.Second
	if ttl <= 0 {
		// Vault commonly returns ttl=0 for non-expiring tokens (root,
		// service tokens minted without a TTL). A concrete expire_time
		// alongside ttl=0 means the token has actually expired —
		// surface that to the caller so login-check drops to the
		// configured login flow. Mirrors the lifecycle manager's
		// handling of the same shape.
		if secret.Data["expire_time"] == nil {
			return true, nil
		}
		return false, nil
	}
	creationTTLSec, _ := readSecondsField(secret.Data, "creation_ttl")
	creationTTL := time.Duration(creationTTLSec) * time.Second

	renewableRaw, _ := secret.Data["renewable"]
	renewable, _ := renewableRaw.(bool)

	// If we have a creation TTL, compare remaining TTL against half of
	// it. Otherwise fall back to "remaining ttl > 15m means fresh", which
	// matches the daemon's renewal heuristic for tokens with unknown
	// creation TTL.
	threshold := creationTTL / 2
	if creationTTL == 0 {
		threshold = 15 * time.Minute
	}

	if ttl > threshold {
		// Still in the fresh half — nothing to do.
		return true, nil
	}

	if !renewable {
		fmt.Fprintf(os.Stderr, "vault token is past halfway (%s remaining) and not renewable; expires %s\n",
			ttl.Truncate(time.Second), absoluteExpiry(ttl))
		return true, nil
	}

	renew := func(ctx context.Context) error {
		_, err := vc.RenewSelf(ctx, 0)
		return err
	}
	if err := renewTokenWithProgress(ctx, renew, os.Stderr); err != nil {
		// Backstop for context.Canceled (the SIGINT handler cancels
		// the outer context before os.Exit, but the race usually goes
		// to os.Exit). If RenewSelf does happen to unwind first, exit
		// silently and leave the cached token alone — it's still valid,
		// just not yet renewed this session.
		if loginCheckCancelled(ctx, err) {
			return true, err
		}
		fmt.Fprintf(os.Stderr, "token is still valid but nearing expiry: %s remaining, expires %s\n",
			ttl.Truncate(time.Second), absoluteExpiry(ttl))
		return true, err
	}
	return true, nil
}

// renewProgressTick is the interval between progress dots emitted while a
// token renewal is in flight. Small enough that a slow renewal feels
// responsive, large enough that the dots read as a deliberate "working…"
// animation rather than a stutter.
const renewProgressTick = 400 * time.Millisecond

// renewTokenWithProgress runs renew while keeping the user informed that
// something is happening. login-check frequently runs at shell startup,
// and a token renewal can block for a noticeable beat against a slow or
// distant Vault — with no output the terminal looks hung (the user
// reported exactly this). We print a prefix, emit a dot every
// renewProgressTick while the renewal is in flight, and finish the line
// with the outcome, all on a single line: a successful renewal reads as
//
//	Vault token needs extending... renewed.
//
// The dot animation is gated on w being the real stderr TTY; piped output
// and test buffers get the prefix, a static ellipsis, and the outcome with
// no interstitial ticking so captured logs stay on one tidy line.
//
// On failure the line ends with " failed: <err>" and the error is
// returned for the caller to add its own follow-up detail. On Ctrl+C the
// select observes ctx cancellation directly and returns ctx.Err() at once
// — without writing an outcome and without waiting for renew to unwind —
// so the dots stop immediately and the SIGINT handler is left to own the
// terminating newline and the exit rather than racing a second write onto
// the dangling line.
//
// renew is injected (rather than taking the Vault client directly) so the
// presentation stays decoupled from Vault plumbing and is unit-testable
// with a fake. It must honour ctx. The done channel is buffered so the
// renew goroutine's send never blocks: if this function has already
// returned on cancellation, the goroutine still runs until renew unwinds
// (promptly, since renew honours ctx) and then exits cleanly rather than
// blocking forever on an unread channel.
func renewTokenWithProgress(ctx context.Context, renew func(context.Context) error, w io.Writer) error {
	fmt.Fprint(w, "Vault token needs extending")

	done := make(chan error, 1)
	go func() { done <- renew(ctx) }()

	var err error
	if w == os.Stderr && term.IsTerminal(int(os.Stderr.Fd())) {
		// Anchor the ellipsis with an immediate dot so even an
		// instantaneous renewal reads coherently, then tick for as long
		// as the renewal is in flight.
		fmt.Fprint(w, ".")
		ticker := time.NewTicker(renewProgressTick)
		defer ticker.Stop()
		for waiting := true; waiting; {
			select {
			case err = <-done:
				waiting = false
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				fmt.Fprint(w, ".")
			}
		}
	} else {
		fmt.Fprint(w, "...")
		select {
		case err = <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if err != nil {
		if loginCheckCancelled(ctx, err) {
			return err
		}
		fmt.Fprintf(w, " failed: %v\n", err)
		return err
	}
	fmt.Fprintln(w, " renewed.")
	return nil
}

// loginCheckCancelled reports whether err is a context-cancellation.
// The login-check SIGINT handler primarily exits via os.Exit(0), but it
// also cancel()s the outer context — this helper is a backstop at every
// in-flight Vault call site for the rare race where the call unwinds
// before os.Exit lands, suppressing the would-be warning so shell
// startup scrollback stays clean.
func loginCheckCancelled(ctx context.Context, err error) bool {
	if errors.Is(ctx.Err(), context.Canceled) {
		return true
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	return false
}

// readSecondsField proxies vault.ReadSecondsField, kept as an
// unexported package-local alias so the login-check call sites
// stay readable.
func readSecondsField(data map[string]any, key string) (int64, bool) {
	return vault.ReadSecondsField(data, key)
}

func absoluteExpiry(ttl time.Duration) string {
	return time.Now().Add(ttl).Format(time.RFC3339)
}

func authenticate(ctx context.Context, cfg *config.Config) (string, *vault.Client, error) {
	username, err := paths.Username()
	if err != nil {
		return "", nil, fmt.Errorf("resolve username: %w", err)
	}

	vc, err := vault.NewClient(vault.Config{
		Address:       cfg.Vault.Address,
		CACert:        cfg.Vault.CACert,
		TLSSkipVerify: cfg.Vault.TLSSkipVerify,
	})
	if err != nil {
		return "", nil, fmt.Errorf("create vault client: %w", err)
	}

	mgr := &auth.Manager{
		VaultClient:   vc,
		TokenFilePath: paths.VaultTokenPath(),
		AuthMethod:    cfg.Vault.AuthMethod,
		AuthMount:     cfg.Vault.AuthMount,
		AuthRole:      cfg.Vault.AuthRole,
		Username:      username,
	}

	if err := mgr.Authenticate(ctx); err != nil {
		return "", nil, fmt.Errorf("authenticate: %w", err)
	}

	return username, vc, nil
}

// newRegExportCmd defines the `reg-export` subcommand which mirrors
// regedit's `/e` direction: pull a .reg representation of the dotvault
// policy out of the registry world and into a user-facing form. The
// default form is YAML; --regedit re-emits the canonicalised .reg.
func newRegExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reg-export [config.reg]",
		Short: "Export a Windows .reg file as YAML (default) or canonical .reg",
		Long: `Read a Windows Registry .reg file representing dotvault policy under
HKLM\SOFTWARE\Policies\goodtune\dotvault and emit its contents in the requested
form. The default output is the equivalent dotvault YAML configuration;
pass --regedit to re-emit the .reg in its canonical Windows Registry
Editor v5 form (--ascii alongside --regedit selects the plain-text
variant).

The input .reg may be either UTF-16LE with BOM (the canonical
regedit.exe format) or plain text/UTF-8; the encoding is detected
automatically.

The input may be supplied as a positional argument or via stdin (when
the argument is "-" or omitted). YAML output is fully validated
through the standard config loader before being returned, so malformed
registry exports surface as clear errors rather than silently
producing partial configs.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runRegExport,
	}
	cmd.Flags().StringVarP(&flagRegOutput, "output", "o", "", "write to file instead of stdout")
	cmd.Flags().BoolVar(&flagRegRegedit, "regedit", false, "emit canonical .reg instead of YAML")
	cmd.Flags().BoolVar(&flagRegASCII, "ascii", false, "with --regedit, emit unencoded plain text instead of UTF-16LE")

	// Hide the inherited --config flag from this subcommand's help.
	// reg-export takes a .reg input via positional path or stdin and
	// has no use for --config (which selects a YAML file for the other
	// subcommands). Showing it would be a UX footgun. We restore the
	// original Hidden state after rendering so other subcommands' help
	// continues to advertise --config normally.
	defaultHelp := cmd.HelpFunc()
	cmd.SetHelpFunc(func(c *cobra.Command, args []string) {
		if cfg := c.InheritedFlags().Lookup("config"); cfg != nil {
			wasHidden := cfg.Hidden
			cfg.Hidden = true
			defer func() { cfg.Hidden = wasHidden }()
		}
		defaultHelp(c, args)
	})
	return cmd
}

func runRegExport(cmd *cobra.Command, args []string) error {
	setupLogging()

	// reg-export reads a .reg file (positional path or stdin) — the
	// inherited --config flag does not apply here. Reject the
	// combination explicitly rather than silently ignoring it, so a
	// user expecting --config to select the input gets clear feedback.
	if flagConfig != "" {
		return fmt.Errorf("--config does not apply to reg-export; pass the .reg path as a positional argument or stdin")
	}

	// --ascii is only meaningful in the .reg pass-through path; YAML
	// output has no UTF-16LE encoding to opt out of. Reject the
	// combination explicitly so a user who expected ASCII .reg doesn't
	// silently get YAML instead.
	if flagRegASCII && !flagRegRegedit {
		return fmt.Errorf("--ascii is only valid with --regedit")
	}

	var input []byte
	var err error
	switch {
	case len(args) == 0 || args[0] == "-":
		input, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
	default:
		input, err = os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("read input: %w", err)
		}
	}

	cfg, err := regfile.Parse(input)
	if err != nil {
		return fmt.Errorf("parse reg file: %w", err)
	}

	var data []byte
	if flagRegRegedit {
		// Pass-through .reg: parse then re-render. Round-tripping through
		// the parser catches malformed input and normalises wrapping.
		if flagRegASCII {
			text, err := regfile.GenerateText(cfg)
			if err != nil {
				return fmt.Errorf("render reg file: %w", err)
			}
			data = []byte(text)
		} else {
			out, err := regfile.Generate(cfg)
			if err != nil {
				return fmt.Errorf("render reg file: %w", err)
			}
			data = out
		}
	} else {
		yamlData, err := regfile.MarshalYAML(cfg)
		if err != nil {
			return fmt.Errorf("render yaml: %w", err)
		}
		// Validate the YAML through the same loader path the daemon uses
		// at startup, so reg-export surfaces config-level errors (missing
		// rules, bad formats, non-loopback web.listen) rather than emitting
		// YAML the daemon would later reject. We round-trip through the
		// loader by writing to a temp file, since config.Load is the
		// single entry point that runs (*Config).validate.
		if err := validateYAML(yamlData); err != nil {
			return fmt.Errorf("exported config is not valid: %w", err)
		}
		data = yamlData
	}

	if flagRegOutput == "" || flagRegOutput == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	// Match the 0600 convention used by other dotvault-managed files: the
	// output can include enrolment settings or other potentially sensitive
	// material that should not be world-readable.
	return os.WriteFile(flagRegOutput, data, 0600)
}

// newRegImportCmd defines the `reg-import` subcommand which mirrors
// regedit's `/s` direction: take a hand-edited YAML config and cast it
// into the .reg form a Windows admin would import into the registry
// (e.g. via Group Policy Preferences or `regedit.exe /s`).
func newRegImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reg-import [config.yaml]",
		Short: "Convert a YAML config into a Windows .reg file",
		Long: `Convert a dotvault YAML configuration file into a Windows Registry
.reg file targeting HKLM\SOFTWARE\Policies\goodtune\dotvault.

The input config path may be supplied as a positional argument or via the
inherited --config flag; the positional argument takes precedence when
both are given. If neither is supplied the platform-specific system
config path is used, matching the other dotvault subcommands.

The resulting file can be applied with regedit.exe /s, deployed via Group
Policy Preferences, or imported manually. By default the output is encoded
as UTF-16LE with BOM, matching the canonical format produced by regedit.exe.
Pass --ascii for a plain-text variant suitable for diffing or piping
through other tools.

The YAML file is fully validated before conversion; conversion errors out
on any problem the daemon would normally reject at load time.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runRegImport,
	}
	cmd.Flags().StringVarP(&flagImportOutput, "output", "o", "", "write to file instead of stdout")
	cmd.Flags().BoolVar(&flagRegASCII, "ascii", false, "emit unencoded plain text instead of UTF-16LE")
	return cmd
}

func runRegImport(cmd *cobra.Command, args []string) error {
	setupLogging()

	path := flagConfig
	if len(args) == 1 {
		path = args[0]
	}
	if path == "" {
		path = paths.SystemConfigPath()
	}

	// reg-import deliberately reads the YAML file, not the registry, so we
	// use config.Load rather than config.LoadSystem (the latter would
	// short-circuit to the registry on Windows when GPO keys are present).
	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	var data []byte
	if flagRegASCII {
		text, err := regfile.GenerateText(cfg)
		if err != nil {
			return fmt.Errorf("render reg file: %w", err)
		}
		data = []byte(text)
	} else {
		out, err := regfile.Generate(cfg)
		if err != nil {
			return fmt.Errorf("render reg file: %w", err)
		}
		data = out
	}

	if flagImportOutput == "" || flagImportOutput == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	// Match the 0600 convention used by other dotvault-managed files: the
	// rendered .reg can include enrolment settings or other potentially
	// sensitive material that should not be world-readable.
	return os.WriteFile(flagImportOutput, data, 0600)
}

// validateYAML feeds rendered YAML through config.Load so that reg-export
// surfaces validation failures (missing rules, bad formats, non-loopback
// web.listen, etc.) before writing or printing the output. A temp file
// is used because config.Load is the single entry point that runs
// (*Config).validate; the indirection avoids duplicating validation
// logic here.
func validateYAML(data []byte) error {
	tmp, err := os.CreateTemp("", "dotvault-validate-*.yaml")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if _, err := config.Load(tmpPath); err != nil {
		return err
	}
	return nil
}

// isStderrTerminal reports whether stderr is connected to a TTY, used to
// pick the slog text vs JSON handler at startup.
func isStderrTerminal() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// printLoginNotice tells the user why dotvault is about to interrupt
// them with an authentication prompt. A profile-script-triggered
// login-check would otherwise present a context-free password prompt
// to a user who didn't ask for one — printing the reason first gives
// them a chance to either consent or Ctrl-C out.
//
// Yellow on a colour-capable TTY, plain text otherwise (so log
// captures, piped output, and dumb terminals stay readable). Honours
// NO_COLOR. Enables ENABLE_VIRTUAL_TERMINAL_PROCESSING on Windows for
// the duration so the ANSI sequence renders rather than printing as
// literal text on conhost; matches the convention used by the enrol
// picker (cmd/dotvault/enrol.go).
//
// Writes to w (passed in so tests can capture output). Colour is gated
// on the writer being os.Stderr — anything else (a *bytes.Buffer in
// tests, stderr piped into a logger) gets plain text regardless of
// the host terminal's capability.
func printLoginNotice(w io.Writer, reason string) {
	msg := fmt.Sprintf("dotvault: %s — starting Vault login flow...", reason)
	if w != os.Stderr || !stderrSupportsColour() {
		fmt.Fprintln(w, msg)
		return
	}
	restore := enableVTOutput(os.Stderr)
	defer restore()
	fmt.Fprintf(w, "\x1b[33m%s\x1b[0m\n", msg)
}

// stderrSupportsColour reports whether the current stderr is safe to
// emit ANSI colour to: a real TTY with NO_COLOR unset (per
// https://no-color.org). Used by printLoginNotice; takes no arguments
// because the only meaningful question is about os.Stderr specifically.
func stderrSupportsColour() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// isInteractive reports whether stdin is connected to a TTY, i.e. whether
// the daemon can prompt the user for credentials, MFA passcodes, etc.
func isInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// initObservability builds an observability.Provider from the loaded
// configuration, scoped by a short timeout so a misconfigured or
// unreachable collector can't stall daemon startup. Always returns a
// non-nil provider — on Init failure it returns the no-op variant so
// the caller can defer Shutdown unconditionally. Shared between
// runDaemon and runSync because divergence between the two call
// sites had been a real source of regressions.
func initObservability(ctx context.Context, cfg config.ObservabilityConfig) *observability.Provider {
	initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	provider, err := observability.Init(initCtx, observability.Config{
		Enabled:        cfg.Enabled,
		Endpoint:       cfg.Endpoint,
		Protocol:       cfg.Protocol,
		Insecure:       cfg.Insecure,
		Headers:        cfg.Headers,
		ExportInterval: cfg.ExportInterval,
		ServiceVersion: version,
	})
	if err != nil {
		// Telemetry must never take the daemon down. Log loudly and
		// continue with a no-op provider so instrument call sites
		// stay safe.
		slog.Error("failed to initialise observability, continuing without metrics", "error", err)
		return &observability.Provider{}
	}
	return provider
}

// shutdownObservability flushes and tears down the MeterProvider
// behind p with a bounded timeout. Paired with initObservability so
// runDaemon and runSync share the same shutdown contract.
func shutdownObservability(p *observability.Provider) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Shutdown(ctx); err != nil {
		slog.Warn("observability shutdown error", "error", err)
	}
}

// isGUIBinary reports whether the running executable is the GUI-subsystem
// Windows variant (dotvaultw.exe). The two Windows binaries are built from
// the same source with a different PE subsystem flag; the GUI build is
// launched by double-click / Start Menu shortcut and must default to the
// daemon because there's no console to show help on. Both `/` and `\` are
// treated as path separators so the check behaves identically when run
// from a Linux-hosted test suite and on Windows itself.
func isGUIBinary(arg0 string) bool {
	name := arg0
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.ToLower(name)
	name = strings.TrimSuffix(name, ".exe")
	return name == "dotvaultw"
}
