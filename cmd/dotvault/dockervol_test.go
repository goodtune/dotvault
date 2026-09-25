package main

import (
	"os"
	"path/filepath"
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
	socket, dir := resolveDockerPlugin(cfg)
	if driver := startDockerVolumes(t.Context(), cfg, socket, dir, nil, ""); driver != nil {
		t.Error("startDockerVolumes returned a driver for an unbuildable store")
	}
}

func TestActivationKeepList(t *testing.T) {
	for _, tc := range []struct {
		name        string
		agent       bool
		api, docker string
		want        []string
	}{
		{"nothing enabled", false, "", "", nil},
		{"api only", false, "/run/api.sock", "", []string{"api"}},
		{"agent only", true, "", "", []string{"agent"}},
		{"docker only", false, "", "/run/docker.sock", []string{"docker"}},
		{"all three", true, "/run/api.sock", "/run/docker.sock", []string{"api", "agent", "docker"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Agent: config.AgentConfig{Enabled: tc.agent}}
			got := activationKeepList(cfg, tc.api, tc.docker)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("activationKeepList = %v, want %v", got, tc.want)
			}
		})
	}
}

// The spec-file annotation in `dotvault status` has to tell five states
// apart: absent (the packaged tmpfiles drop-in has not run and nobody wrote
// one), agreeing with the resolved socket, naming a different one (what a
// customised docker.socket looks like from here), empty, and not a regular
// file. The guide's two troubleshooting symptoms map onto the first and
// third, so collapsing any pair would make the line useless — and the last
// two exist because status output is something users paste into issues.
func TestDockerSpecState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	spec := filepath.Join(home, ".local", "lib", "docker", "plugins", "dotvault.spec")
	if err := os.MkdirAll(filepath.Dir(spec), 0o755); err != nil {
		t.Fatal(err)
	}

	const socket = "/run/user/1000/dotvault/docker.sock"

	if got := dockerSpecState(spec, socket); !strings.Contains(got, "missing") {
		t.Errorf("no spec file: state = %q, want a missing notice", got)
	}

	// tmpfiles' `f` writes no trailing newline, `echo` writes one, and moby
	// TrimSpace's the body — both must read as agreeing.
	for _, body := range []string{"unix://" + socket, "unix://" + socket + "\n"} {
		writeSpec(t, spec, body)
		if got := dockerSpecState(spec, socket); !strings.Contains(got, "present") || strings.Contains(got, "names") {
			t.Errorf("spec %q: state = %q, want a plain present notice", body, got)
		}
	}

	writeSpec(t, spec, "unix:///run/user/1000/elsewhere.sock")
	if got := dockerSpecState(spec, socket); !strings.Contains(got, "names") || !strings.Contains(got, "elsewhere.sock") {
		t.Errorf("diverging spec: state = %q, want the other socket named", got)
	}

	// A truncated or half-written file must not render as `names ""`.
	for _, body := range []string{"", "  \n\t "} {
		writeSpec(t, spec, body)
		got := dockerSpecState(spec, socket)
		if !strings.Contains(got, "empty") || strings.Contains(got, "names") {
			t.Errorf("empty spec %q: state = %q, want an empty notice", body, got)
		}
	}
}

// The read must not follow a symlink: tmpfiles opens its target O_NOFOLLOW,
// and status output is pasted into issues, so a spec path pointed at the token
// file must not print it.
func TestDockerSpecStateRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privilege on windows")
	}
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	writeSpec(t, secret, "hvs.super-secret-token")
	spec := filepath.Join(dir, "dotvault.spec")
	if err := os.Symlink(secret, spec); err != nil {
		t.Fatal(err)
	}
	got := dockerSpecState(spec, "/run/user/1000/dotvault/docker.sock")
	if strings.Contains(got, "secret") || strings.Contains(got, "hvs.") {
		t.Fatalf("symlinked spec: state = %q, must not disclose the target's contents", got)
	}
	if !strings.Contains(got, "not a regular file") {
		t.Errorf("symlinked spec: state = %q, want a not-a-regular-file notice", got)
	}
}

// A file that is not a spec must not be able to push terminal escapes through
// the status output, nor an unbounded amount of text.
func TestDockerSpecStateQuotesAndCapsContents(t *testing.T) {
	dir := t.TempDir()
	spec := filepath.Join(dir, "dotvault.spec")
	const beyondCap = "PAST-THE-CAP"
	writeSpec(t, spec, "\x1b[2Junix://evil"+strings.Repeat("A", 32*1024)+beyondCap)

	got := dockerSpecState(spec, "/run/user/1000/dotvault/docker.sock")
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("state = %q, want the escape rendered inert by %%q", got)
	}
	if strings.Contains(got, beyondCap) {
		t.Errorf("state reached past the %d-byte read cap", maxSpecRead)
	}
}

func writeSpec(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
