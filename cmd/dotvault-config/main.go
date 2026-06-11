// Command dotvault-config is the remote-configuration service for dotvault
// clients: it composes layered partial-config documents (global → os →
// groups → user) from a storage backend and serves them over HTTP for the
// daemon's remote_config overlay. See docs/services/dotvault-config.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/goodtune/dotvault/internal/configsvc"
)

// version is injected at build time via -ldflags "-X main.version=...".
// Same contract as the dotvault binary: the value is the v-stripped
// semantic version.
var version = "dev"

var (
	flagConfig    string
	flagLogLevel  string
	flagLogFormat string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "dotvault-config",
		Short: "Remote configuration service for dotvault",
		Long: `dotvault-config composes layered partial configuration documents
(global → os → groups → user) and serves them to dotvault daemons over HTTP.

Use "dotvault-config serve" to run the service, "dotvault-config seed" to
publish a directory of layer YAMLs into the storage backend, and
"dotvault-config compose" to debug a composition offline.`,
		SilenceUsage: true,
	}

	rootCmd.PersistentFlags().StringVar(&flagConfig, "config", "", "path to the service configuration file")
	rootCmd.PersistentFlags().StringVar(&flagLogLevel, "log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&flagLogFormat, "log-format", "auto", "log format (auto, text, json); auto picks text on TTY, json otherwise")

	rootCmd.AddCommand(
		newServeCmd(),
		newSeedCmd(),
		newComposeCmd(),
		newVersionCmd(),
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

	useJSON := false
	switch strings.ToLower(flagLogFormat) {
	case "json":
		useJSON = true
	case "text":
		useJSON = false
	case "auto", "":
		useJSON = !term.IsTerminal(int(os.Stderr.Fd()))
	default:
		fmt.Fprintf(os.Stderr, "dotvault-config: invalid --log-format %q (want auto, text, or json)\n", flagLogFormat)
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

func loadConfig() (*configsvc.Config, error) {
	if flagConfig == "" {
		return nil, fmt.Errorf("--config is required")
	}
	return configsvc.LoadConfig(flagConfig)
}

func newServeCmd() *cobra.Command {
	var seedDir string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the configuration service",
		Long: `Run the HTTP service: GET /v1/config composes the partial configuration
document for the identity asserted in the X-Dotvault-OS / X-Dotvault-User
headers, with ETag/If-None-Match revalidation; /healthz and /readyz serve
liveness and storage-gated readiness probes. TLS is terminated by the
operator's ingress unless tls.cert_file / tls.key_file are configured.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			setupLogging()
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			st, err := cfg.OpenStore(ctx)
			if err != nil {
				return err
			}
			defer st.Close()

			if seedDir != "" {
				summary, err := configsvc.Seed(ctx, st, seedDir)
				if err != nil {
					return fmt.Errorf("seed %s: %w", seedDir, err)
				}
				slog.Info("seeded store", "dir", seedDir,
					"layers", len(summary.Layers), "users", len(summary.Users))
			}

			resolver, err := cfg.OpenResolver(st)
			if err != nil {
				return err
			}

			server := &http.Server{
				Addr:              cfg.Listen,
				Handler:           configsvc.NewServer(st, resolver).Handler(),
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      30 * time.Second,
				IdleTimeout:       2 * time.Minute,
			}

			errCh := make(chan error, 1)
			go func() {
				slog.Info("dotvault-config listening", "addr", cfg.Listen,
					"tls", cfg.TLS.Enabled(), "store", cfg.Store.Driver,
					"groups", cfg.Groups.Source, "version", version)
				if cfg.TLS.Enabled() {
					errCh <- server.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
				} else {
					errCh <- server.ListenAndServe()
				}
			}()

			select {
			case err := <-errCh:
				return err
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := server.Shutdown(shutdownCtx); err != nil {
					return err
				}
				if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
					return err
				}
				slog.Info("dotvault-config stopped")
				return nil
			}
		},
	}
	cmd.Flags().StringVar(&seedDir, "seed", "", "seed the store from a layer directory before serving (dev convenience)")
	return cmd
}

func newSeedCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "seed",
		Short: "Publish a directory of layer YAMLs into the store",
		Long: `Walk a layer directory (global.yaml, os/*.yaml, group/*.yaml, user/*.yaml,
and an optional groups.yaml with static membership), validate every document,
and write the result to the configured storage backend. Nothing is written
unless everything validates, so a CI job publishing a git-managed layer tree
on merge can never half-apply an invalid tree.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			setupLogging()
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			st, err := cfg.OpenStore(cmd.Context())
			if err != nil {
				return err
			}
			defer st.Close()

			summary, err := configsvc.Seed(cmd.Context(), st, dir)
			if err != nil {
				return err
			}
			for _, key := range summary.Layers {
				fmt.Printf("layer %s\n", key)
			}
			for _, user := range summary.Users {
				fmt.Printf("groups %s\n", user)
			}
			fmt.Printf("seeded %d layers, %d group memberships\n", len(summary.Layers), len(summary.Users))
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "layer directory to publish")
	cmd.MarkFlagRequired("dir")
	return cmd
}

func newComposeCmd() *cobra.Command {
	var (
		osName    string
		user      string
		groupList []string
	)
	cmd := &cobra.Command{
		Use:   "compose",
		Short: "Compose a document offline for debugging",
		Long: `Compose the document a client identity would receive, printing the YAML to
stdout and the ETag to stderr. Group membership comes from the configured
resolver unless --groups overrides it.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			setupLogging()
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			st, err := cfg.OpenStore(cmd.Context())
			if err != nil {
				return err
			}
			defer st.Close()

			memberOf := groupList
			if !cmd.Flags().Changed("groups") {
				resolver, err := cfg.OpenResolver(st)
				if err != nil {
					return err
				}
				memberOf, err = resolver.Groups(cmd.Context(), user)
				if err != nil {
					return fmt.Errorf("resolve groups for %q: %w", user, err)
				}
			}

			keys := configsvc.LayerKeys(osName, user, memberOf)
			composer := &configsvc.Composer{Store: st}
			doc, etag, err := composer.Compose(cmd.Context(), keys)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "layers: %s\netag: %s\n", strings.Join(keys, " "), etag)
			os.Stdout.Write(doc)
			return nil
		},
	}
	cmd.Flags().StringVar(&osName, "os", runtime.GOOS, "X-Dotvault-OS dimension")
	cmd.Flags().StringVar(&user, "user", "", "X-Dotvault-User dimension")
	cmd.Flags().StringSliceVar(&groupList, "groups", nil, "override group membership (skips the resolver)")
	cmd.MarkFlagRequired("user")
	return cmd
}

func newVersionCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			if jsonOut {
				type versionInfo struct {
					Version   string `json:"version"`
					Service   string `json:"service"`
					GoVersion string `json:"go_version"`
					OS        string `json:"os"`
					Arch      string `json:"arch"`
				}
				_ = json.NewEncoder(os.Stdout).Encode(versionInfo{
					Version:   version,
					Service:   "dotvault-config",
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
