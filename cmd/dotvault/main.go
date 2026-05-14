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
	"syscall"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/enrol"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/regfile"
	"github.com/goodtune/dotvault/internal/sync"
	"github.com/goodtune/dotvault/internal/tray"
	"github.com/goodtune/dotvault/internal/vault"
	"github.com/goodtune/dotvault/internal/web"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var version = "dev"

var (
	flagConfig       string
	flagLogLevel     string
	flagDryRun       bool
	flagRegOutput    string
	flagRegASCII     bool
	flagRegRegedit   bool
	flagImportOutput string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "dotvault",
		Short: "Vault-to-file secret synchronisation daemon",
		Long: `dotvault synchronises Vault KVv2 secrets into local config files.

Run with no subcommand prints this help. Use "dotvault run" to start the
long-lived daemon, "dotvault login-check" to validate (and optionally
renew) the cached token on an interactive login, or "dotvault login" to
force a fresh login flow.`,
		// Cobra's default RunE for a command with no Run/RunE prints help
		// when called bare, which is what we want — explicitly running the
		// daemon now requires `dotvault run`.
		SilenceUsage: true,
	}

	rootCmd.PersistentFlags().StringVar(&flagConfig, "config", "", "override system config path")
	rootCmd.PersistentFlags().StringVar(&flagLogLevel, "log-level", "info", "log level (debug, info, warn, error)")
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
		&cobra.Command{
			Use:   "login-check",
			Short: "Validate cached token on interactive login, renew or re-login as needed",
			Long: `Intended to be wired into shell rc / login-profile scripts.

If stdout is not a terminal the command exits silently with status 0 so
non-interactive environments (cron, system services, scp) never see a
prompt.

When run on an interactive terminal:
  - If the cached token is valid and still within the first half of its
    creation TTL, exit clean.
  - If the cached token is valid but past the halfway point, attempt
    renewal. If renewal succeeds, exit clean. If renewal fails but the
    token is still valid, warn with the absolute expiry time and exit 0.
  - If the cached token is missing or invalid, run the configured login
    flow. Ctrl-C exits without fanfare so the user can dismiss the prompt
    on a fresh terminal session.`,
			RunE: runLoginCheck,
		},
		&cobra.Command{
			Use:   "status",
			Short: "Show auth and sync status",
			RunE:  runStatus,
		},
		&cobra.Command{
			Use:   "version",
			Short: "Print version",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Println(version)
			},
		},
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

	var handler slog.Handler
	if isStderrTerminal() {
		handler = slog.NewTextHandler(os.Stderr, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
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

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				slog.Info("received shutdown signal", "signal", sig)
				cancel()
			case syscall.SIGHUP:
				// TODO: Implement config reload on SIGHUP. This is deferred
				// to a future release. For now, restart the daemon to pick
				// up config changes.
				slog.Warn("received SIGHUP but config reload is not yet implemented; restart the daemon to apply config changes")
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

	// Start web UI if enabled. We start it before authentication so it can
	// serve the OIDC browser-based login flow.
	var webServer *web.Server
	if cfg.Web.Enabled {
		webServer, err = web.NewServer(web.ServerConfig{
			WebCfg:        cfg.Web,
			VaultCfg:      cfg.Vault,
			SyncCfg:       cfg.Sync,
			Rules:         cfg.Rules,
			Vault:         vc,
			Engine:        engine,
			Username:      username,
			TokenFilePath: tokenPath,
			Version:       version,
		})
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
	lifecycleErrCh := lm.Start(ctx)

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
						slog.Warn("config reload failed", "error", err)
						continue
					}
					if !reflect.DeepEqual(reloaded.Enrolments, lastEnrolments) {
						slog.Info("enrolments config changed, re-checking")
						enrolMgr.UpdateConfig(reloaded.Enrolments)
						rm.UpdateConfig(reloaded.Enrolments)
						wm.UpdateConfig(reloaded.Enrolments)
						lastEnrolments = reloaded.Enrolments
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

	// Run the sync engine on a goroutine and the tray (Windows) or a
	// blocking ctx-wait (everything else) on the main goroutine. The tray
	// must own the main goroutine because the Win32 message pump requires
	// runtime.LockOSThread on the same OS thread that creates the window.
	// If the sync loop exits unexpectedly we cancel the context to wake
	// tray.Run up and let the daemon shut down cleanly.
	loopErrCh := make(chan error, 1)
	go func() {
		loopErrCh <- engine.RunLoop(ctx)
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
	// Stop the sync loop and propagate its result.
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

	return nil
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

// runLoginCheck implements `dotvault login-check`, intended to be called
// from a user's interactive-shell login profile. The semantics are
// described in the command's Long help text.
func runLoginCheck(cmd *cobra.Command, args []string) error {
	// Only attach the slog default in interactive mode — non-interactive
	// callers should be completely silent. We still log to stderr (text
	// handler) in the interactive path so renewal/failure messages reach
	// the operator.
	if !isStdoutTerminal() {
		// No tty: nothing for us to do. Exit clean rather than blocking
		// or emitting JSON-shaped logs into the shell startup output.
		return nil
	}
	setupLogging()

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

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	tokenPath := paths.VaultTokenPath()
	token := auth.ResolveToken(tokenPath)
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
		} else if vault.IsForbidden(lookupErr) {
			// 403: the cached token is revoked or otherwise invalid.
			// Clear it and fall through to the interactive login flow.
			vc.SetToken("")
		} else {
			// Ctrl-C during LookupSelf surfaces as a wrapped
			// context.Canceled here — exit silently to honour the
			// command's documented "Ctrl-C without fanfare" contract.
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
		// Ctrl-C during the health probe inherits cancellation from the
		// outer signal context. Suppress the warning in that case so the
		// shell scrollback stays clean.
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
	if err := mgr.Login(ctx); err != nil {
		// Ctrl-C: silent exit. The user dismissed the prompt knowingly.
		if loginCheckCancelled(ctx, err) {
			return nil
		}
		return fmt.Errorf("login: %w", err)
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

	if _, err := vc.RenewSelf(ctx, 0); err != nil {
		// Ctrl-C during renewal: exit silently (the command's documented
		// contract), leaving the cached token in place — it's still
		// valid, just not yet renewed this session.
		if loginCheckCancelled(ctx, err) {
			return true, err
		}
		fmt.Fprintf(os.Stderr, "vault token renewal failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "token is still valid but nearing expiry: %s remaining, expires %s\n",
			ttl.Truncate(time.Second), absoluteExpiry(ttl))
		return true, err
	}
	fmt.Fprintln(os.Stderr, "vault token renewed")
	return true, nil
}

// loginCheckCancelled reports whether err is a context-cancellation
// (i.e. the user pressed Ctrl-C). Used at every login-check error site
// to honour the command's "Ctrl-C exits without fanfare" contract — a
// cancelled lookup, health probe, or renewal must not leave warnings
// in the shell's startup scrollback.
func loginCheckCancelled(ctx context.Context, err error) bool {
	if errors.Is(ctx.Err(), context.Canceled) {
		return true
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	return false
}

func readSecondsField(data map[string]any, key string) (int64, bool) {
	v, ok := data[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case json.Number:
		s, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return s, true
	case float64:
		return int64(n), true
	case int:
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
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

// isStdoutTerminal reports whether stdout is connected to a TTY. Used by
// `dotvault login-check` to silently no-op when invoked from a
// non-interactive shell (cron, sshd ForceCommand, scp, etc.).
func isStdoutTerminal() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// isInteractive reports whether stdin is connected to a TTY, i.e. whether
// the daemon can prompt the user for credentials, MFA passcodes, etc.
func isInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}
