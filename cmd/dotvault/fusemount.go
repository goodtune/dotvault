package main

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
	"github.com/goodtune/dotvault/internal/vaultfs"
)

// resolveFUSEMountpoint returns the directory the daemon should mount the
// filesystem on, or "" when it should mount none.
//
// Enabling the filesystem on Windows warns and mounts nothing rather than
// failing the daemon, exactly as resolveAPISocket treats the local API socket:
// a fleet shares one config across platforms, and a Windows host that has no
// use for the setting should not refuse to start because of it. There is no
// Windows equivalent planned — the closest thing, WinFsp, is a DLL reached
// through cgo, and dotvault ships CGO_ENABLED=0 static binaries.
func resolveFUSEMountpoint(cfg *config.Config) string {
	if cfg.FUSE.Enabled && runtime.GOOS == "windows" {
		// config.FUSEMountpoint already returns "" here — this only surfaces
		// *why* to an operator who set the flag and expects a mount.
		slog.Warn("fuse.enabled is set but the filesystem is not supported on windows; ignoring")
		return ""
	}
	path, err := cfg.FUSEMountpoint()
	if err != nil {
		slog.Warn("could not resolve fuse.mountpoint; filesystem disabled", "error", err)
		return ""
	}
	return path
}

// startFUSE mounts the filesystem in the background and returns its service,
// or nil when none is configured or it could not be built.
//
// A failure to mount is never fatal to the daemon. The filesystem is a
// convenience surface over secrets that are already being synced to real files
// by the sync engine, so a host without /dev/fuse (a container, a locked-down
// runner) should still sync, serve its API socket and run its SSH agent. The
// failure is logged once and recorded in the service's status; see
// vaultfs.Service.Run for why it is not retried.
//
// Called after the first successful Vault auth, like the SSH agent listener:
// the mount answers reads by calling Vault, so mounting before there is a
// token would publish a directory that returns errors to anything that looked
// at it — including, on a desktop, whatever indexes the user's home directory.
func startFUSE(ctx context.Context, cfg *config.Config, vc *vault.Client, username string) *vaultfs.Service {
	mountpoint := resolveFUSEMountpoint(cfg)
	if mountpoint == "" {
		return nil
	}

	store, err := vaultfs.NewStore(vc, cfg.Vault.KVMount, cfg.Vault.UserPrefix, username)
	if err != nil {
		slog.Warn("filesystem not mounted", "error", err)
		return nil
	}
	svc, err := vaultfs.NewService(store, vaultfs.Options{
		Mountpoint: mountpoint,
		ReadWrite:  cfg.FUSE.ReadWrite,
		CacheTTL:   cfg.FUSE.CacheTTL,
	})
	if err != nil {
		slog.Warn("filesystem not mounted", "mountpoint", mountpoint, "error", err)
		return nil
	}

	go func() {
		if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("filesystem not mounted", "mountpoint", mountpoint, "error", err)
		}
	}()
	return svc
}

// printFUSEStatus renders the filesystem section of `dotvault status`.
//
// Unlike the SSH agent section, status does not ask the daemon: it asks the
// kernel whether anything is mounted at the configured path. That is the right
// question for a command whose most likely use is "the directory looks empty,
// what is going on" — an answer sourced from the daemon would report nothing
// at all when the daemon is down, which is exactly when it is being asked.
func printFUSEStatus(cfg *config.Config) {
	if !cfg.FUSE.Enabled {
		return
	}
	fmt.Println("\nFilesystem:")

	if runtime.GOOS == "windows" {
		fmt.Println("  unsupported: this platform has no FUSE implementation, so nothing is mounted")
		return
	}

	mountpoint, err := cfg.FUSEMountpoint()
	if err != nil {
		fmt.Printf("  mountpoint:  (unresolvable: %v)\n", err)
		return
	}
	fmt.Printf("  mountpoint:  %s\n", mountpoint)
	fmt.Printf("  mode:        %s\n", vaultfs.AccessMode(cfg.FUSE.ReadWrite))
	fmt.Printf("  cache ttl:   %s\n", cfg.FUSE.CacheTTL)
	if cfg.FUSE.UserOverlayPath != "" {
		// Without this, an administrator looking at a machine whose policy
		// says the filesystem is off has nothing but a startup WARN — long
		// since scrolled past — to explain why one is mounted.
		fmt.Printf("  preferences: %s\n", cfg.FUSE.UserOverlayPath)
	}

	mounted, err := vaultfs.IsMounted(mountpoint)
	switch {
	case err != nil:
		fmt.Printf("  state:       unknown (%v)\n", err)
	case mounted:
		fmt.Println("  state:       mounted")
	default:
		fmt.Println("  state:       not mounted")
		fmt.Println("  (the filesystem is enabled but nothing is mounted — is `dotvault run` active?)")
	}
}
