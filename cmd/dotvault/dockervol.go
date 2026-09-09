package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/dockervol"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/vault"
	"github.com/goodtune/dotvault/internal/vaultfs"
)

// dockerStatePath is where the volume plugin persists its volume definitions
// (names and options only — never secret data), beside the sync engine's
// state.json.
func dockerStatePath() string {
	return filepath.Join(paths.CacheDir(), "docker-volumes.json")
}

// resolveDockerPlugin returns the socket the daemon should serve the volume
// plugin on and the directory volumes are materialised under, or two empty
// strings when it should serve none.
//
// Enabling the plugin off Linux warns and serves nothing rather than failing
// the daemon, exactly as resolveAPISocket and resolveFUSEMountpoint treat
// their sections: a fleet shares one config across platforms. It is
// Linux-only in a stronger sense than those two — Docker Desktop and Podman
// machine on macOS run the engine in a VM, where a host-side socket is
// unreachable, so there is nothing a macOS build could usefully bind.
func resolveDockerPlugin(cfg *config.Config) (socket, volumeDir string) {
	if cfg.Docker.Enabled && runtime.GOOS != "linux" {
		// config.DockerSocketPath already returns "" here — this only
		// surfaces *why* to an operator who set the flag and expects a socket.
		slog.Warn("docker.enabled is set but the volume plugin is served on linux only; ignoring")
		return "", ""
	}
	socket, err := cfg.DockerSocketPath()
	if err != nil {
		slog.Warn("could not resolve docker.socket; volume plugin disabled", "error", err)
		return "", ""
	}
	if socket == "" {
		return "", ""
	}
	volumeDir, err = cfg.DockerVolumeDir()
	if err != nil {
		slog.Warn("could not resolve docker.volume_dir; volume plugin disabled", "error", err)
		return "", ""
	}
	return socket, volumeDir
}

// startDockerVolumes serves the volume plugin in the background and returns
// its driver, or nil when none is configured or it could not be built.
//
// Started before authentication, like the agent and HTTP listeners: the
// engine may ask about volumes (`docker volume ls`, `create`) at any time,
// and those answers need no token. Only a Mount that has to populate a
// volume does, and the driver refuses that one with a message naming the
// cause until a token arrives — a clearer answer than the engine's "plugin
// not found" for a socket that does not exist yet. The refresh policy's own
// Vault work (edition probe, event subscription) waits for a token itself.
//
// A failure to serve is never fatal to the daemon; it is logged once, the
// same way a failed FUSE mount is. socket and volumeDir come from
// resolveDockerPlugin, resolved once by the caller because the keep list
// for systemd activation is built from the same answer — and a plugin that
// was kept but cannot be built drains its activated fd here, so an engine
// never hangs on a socket nothing will serve.
func startDockerVolumes(ctx context.Context, cfg *config.Config, socket, volumeDir string, vc *vault.Client, username string) *dockervol.Driver {
	if socket == "" {
		return nil
	}
	store, err := vaultfs.NewStore(vc, cfg.Vault.KVMount, cfg.Vault.UserPrefix, username)
	if err != nil {
		slog.Warn("docker volume plugin not started", "error", err)
		dockervol.DrainActivated()
		return nil
	}
	// The default lives on the per-user runtime tmpfs so a rendered secret
	// never touches persistent disk. Say so when that is not where the
	// volumes are going: an unset XDG_RUNTIME_DIR falls back to the cache
	// dir silently, and an explicit docker.volume_dir may be anywhere.
	if rt := os.Getenv("XDG_RUNTIME_DIR"); rt == "" || !strings.HasPrefix(volumeDir, filepath.Clean(rt)+string(filepath.Separator)) {
		slog.Warn("docker volumes will be materialised outside the runtime directory; secrets held by a container are written to persistent disk", "volume_dir", volumeDir)
	}
	driver, err := dockervol.New(dockervol.Options{
		SocketPath: socket,
		VolumeDir:  volumeDir,
		StatePath:  dockerStatePath(),
		DefaultTTL: cfg.Docker.CacheTTL,
		UserPrefix: vaultfs.UserRoot(cfg.Vault.UserPrefix, username),
		HasToken:   func() bool { return vc.Token() != "" },
	}, store, vc)
	if err != nil {
		slog.Warn("docker volume plugin not started", "error", err)
		dockervol.DrainActivated()
		return nil
	}
	go func() {
		if err := driver.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("docker volume plugin stopped", "socket", socket, "error", err)
		}
	}()
	return driver
}

// printDockerStatus renders the volume plugin section of `dotvault status`.
//
// Like the SSH agent section, status acts as a client of the running daemon:
// it asks the plugin socket for its volume list, so the output reflects what
// the driver is actually serving. It never creates the socket. The
// registration hint is printed because the socket is deliberately not where
// an engine looks on its own (see paths.DefaultDockerSocket).
func printDockerStatus(ctx context.Context, cfg *config.Config) {
	if !cfg.Docker.Enabled {
		return
	}
	fmt.Println("\nDocker Volumes:")
	if runtime.GOOS != "linux" {
		fmt.Println("  unsupported: the volume plugin is served on linux only")
		return
	}
	socket, volumeDir := resolveDockerPlugin(cfg)
	if socket == "" {
		fmt.Println("  socket:     (unresolvable; see the warning above)")
		return
	}
	fmt.Printf("  socket:     %s\n", socket)
	fmt.Printf("  volume dir: %s\n", volumeDir)
	// Printed as the spec file's path and contents rather than as a shell
	// command: the socket path is operator data and would need quoting to
	// be safe to paste, and a data line has nothing to quote. ~/.local/lib
	// rather than ~/.config: released rootless dockerds (v27, v28) scan
	// only the former — see docs/guide/docker-volumes.md.
	fmt.Printf("  spec file:  ~/.local/lib/docker/plugins/%s.spec\n", dockervol.DriverName)
	fmt.Printf("  spec body:  unix://%s\n", socket)

	vols, err := dockervol.QueryListening(ctx, socket)
	if err != nil {
		fmt.Printf("  unreachable: %v\n", err)
		fmt.Println("  (the plugin is enabled but the daemon is not serving this socket — is `dotvault run` active?)")
		return
	}
	if len(vols) == 0 {
		fmt.Println("  (no volumes defined — `docker volume create -d dotvault -o secrets=gh myvol`)")
		return
	}
	for _, v := range vols {
		line := fmt.Sprintf("  %-20s mounts=%v secrets=%v refresh=%v", v.Name,
			v.Status[dockervol.StatusMounts], v.Status[dockervol.StatusSecrets], v.Status[dockervol.StatusRefresh])
		if e, ok := v.Status[dockervol.StatusLastError]; ok {
			line += fmt.Sprintf(" error=%v", e)
		}
		if e, ok := v.Status[dockervol.StatusEventsError]; ok {
			line += fmt.Sprintf(" events_error=%v", e)
		}
		fmt.Println(line)
	}
}
