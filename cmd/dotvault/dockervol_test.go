package main

import (
	"runtime"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

func TestResolveDockerPluginDisabled(t *testing.T) {
	cfg := &config.Config{}
	if socket, dir := resolveDockerPlugin(cfg); socket != "" || dir != "" {
		t.Errorf("resolveDockerPlugin() = %q, %q, want empty when the section is disabled", socket, dir)
	}
}

func TestResolveDockerPluginEnabled(t *testing.T) {
	cfg := &config.Config{Docker: config.DockerConfig{Enabled: true, Socket: "/run/x/docker.sock", VolumeDir: "/run/x/volumes"}}
	socket, dir := resolveDockerPlugin(cfg)
	if runtime.GOOS != "linux" {
		// Enabling it elsewhere warns and serves nothing rather than
		// failing the daemon: one config is shared across a mixed fleet,
		// and no other platform has an engine a host socket can reach.
		if socket != "" || dir != "" {
			t.Errorf("resolveDockerPlugin() = %q, %q on %s, want empty", socket, dir, runtime.GOOS)
		}
		return
	}
	if socket != "/run/x/docker.sock" || dir != "/run/x/volumes" {
		t.Errorf("resolveDockerPlugin() = %q, %q", socket, dir)
	}
}

func TestResolveDockerPluginExpandsHome(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("no plugin surface off linux")
	}
	cfg := &config.Config{Docker: config.DockerConfig{Enabled: true, Socket: "~/docker.sock", VolumeDir: "~/volumes"}}
	socket, dir := resolveDockerPlugin(cfg)
	if socket == "" || strings.HasPrefix(socket, "~") || dir == "" || strings.HasPrefix(dir, "~") {
		t.Errorf("resolveDockerPlugin() = %q, %q, want ~ expanded", socket, dir)
	}
}

// startDockerVolumes must never take the daemon down. A store it cannot
// build (no username here) resolves to "no plugin" rather than an error the
// caller is obliged to handle.
func TestStartDockerVolumesIsNeverFatal(t *testing.T) {
	cfg := &config.Config{
		Vault:  config.VaultConfig{KVMount: "kv", UserPrefix: "users/"},
		Docker: config.DockerConfig{Enabled: true, Socket: "/nonexistent/docker.sock", VolumeDir: "/nonexistent/volumes"},
	}
	if driver := startDockerVolumes(t.Context(), cfg, nil, ""); driver != nil {
		t.Error("startDockerVolumes returned a driver for an unbuildable store")
	}
}
