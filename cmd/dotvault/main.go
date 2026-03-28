package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/sync"
	"github.com/goodtune/dotvault/internal/vault"
	"github.com/goodtune/dotvault/internal/web"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
)

var version = "dev"

var (
	flagConfig   string
	flagLogLevel string
	flagDryRun   bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "dotvault",
		Short: "Vault-to-file secret synchronisation daemon",
		RunE:  runDaemon,
	}

	rootCmd.PersistentFlags().StringVar(&flagConfig, "config", "", "override system config path")
	rootCmd.PersistentFlags().StringVar(&flagLogLevel, "log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().BoolVar(&flagDryRun, "dry-run", false, "show what would change without writing")

	rootCmd.AddCommand(
		&cobra.Command{
			Use:   "run",
			Short: "Run daemon in foreground",
			RunE:  runDaemon,
		},
		&cobra.Command{
			Use:   "sync",
			Short: "Run one sync cycle and exit",
			RunE:  runSync,
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
	)

	// --once as alias for sync
	rootCmd.PersistentFlags().Bool("once", false, "run one sync cycle and exit")

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
	if isTerminal() {
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
	return config.Load(path)
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
			Rules:         cfg.Rules,
			Vault:         vc,
			Engine:        engine,
			Username:      username,
			TokenFilePath: tokenPath,
		})
		if err != nil {
			slog.Error("failed to create web server", "error", err)
		} else {
			go func() {
				if err := webServer.Start(); err != nil {
					slog.Error("web server error", "error", err)
				}
			}()
			defer webServer.Shutdown(ctx)

			// Wait for the server to start listening before proceeding.
			// This ensures WaitForAuth cannot block if the server failed to bind.
			if err := webServer.WaitReady(); err != nil {
				return fmt.Errorf("web server failed to start: %w", err)
			}
		}
	}

	// Authenticate if needed.
	if !authenticated {
		if webServer != nil && cfg.Vault.AuthMethod == "oidc" {
			// Web-based OIDC: open the browser to the web server's auth
			// start page, which redirects through the Vault OIDC flow and
			// back to the web server's callback to complete authentication.
			url := webServer.AuthStartURL()
			slog.Info("opening browser for OIDC authentication", "url", url)
			if err := browser.OpenURL(url); err != nil {
				slog.Warn("failed to open browser, please visit URL manually", "url", url, "error", err)
			}
			if err := webServer.WaitForAuth(ctx); err != nil {
				return fmt.Errorf("web-based authentication: %w", err)
			}
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

	// Start token lifecycle manager.
	lm := auth.NewLifecycleManager(vc, 5*time.Minute)
	lifecycleErrCh := lm.Start(ctx)
	go func() {
		reauthOpened := false
		for err := range lifecycleErrCh {
			slog.Warn("token lifecycle error, re-authentication may be needed", "error", err)
			if webServer != nil && cfg.Vault.AuthMethod == "oidc" && !reauthOpened {
				reauthOpened = true
				url := webServer.AuthStartURL()
				slog.Info("opening browser for re-authentication", "url", url)
				if err := browser.OpenURL(url); err != nil {
					slog.Warn("failed to open browser for re-auth", "url", url, "error", err)
				}
			}
		}
	}()

	slog.Info("starting dotvault daemon", "version", version, "user", username)
	return engine.RunLoop(ctx)
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

func isTerminal() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
