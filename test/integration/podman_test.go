package integration

// A rootless Podman engine drives dotvault's Docker volume plugin over the
// real socket, with a dev-mode Vault behind it. The unit tests in
// internal/dockervol post JSON at the handler and prove the driver does what
// the protocol says; this proves an engine agrees. It is the only place the
// protocol is exercised by a container engine.
//
// Unlike its siblings it does not use the compose stack: it starts its own
// Vault under the same podman (the compose Vault assumes a rootful docker,
// which is the arrangement the guide tells operators to think twice about),
// gives the daemon its own HOME so a developer's live cache and token file
// are untouched, and registers the plugin through CONTAINERS_CONF_OVERRIDE
// rather than ~/.config/containers/containers.conf. It pulls images and runs
// containers, so it is opt-in: set DOTVAULT_PODMAN_E2E=1 (`make podman-e2e`,
// or the podman-e2e CI job).
//
// The secret values seeded here are throwaway fixtures the test invents, and
// on failure it prints them freely (container output, the daemon's debug log)
// because that is what makes a CI failure diagnosable. Do not copy that habit
// into a test that touches a real Vault.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/vault"
)

const (
	podmanVaultImage  = "docker.io/hashicorp/vault:1.21"
	podmanAlpineImage = "docker.io/library/alpine:3.22"
	// Not 8200: a developer's compose stack may hold it.
	podmanVaultAddr  = "http://127.0.0.1:18200"
	podmanVaultToken = "e2e-root-token"
)

func skipIfNoPodmanE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("DOTVAULT_PODMAN_E2E") == "" {
		t.Skip("set DOTVAULT_PODMAN_E2E=1 to run the Podman end-to-end test (pulls images, runs containers)")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the volume plugin is served on linux only")
	}
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman not found in PATH")
	}
	out, err := exec.Command("podman", "info", "--format", "{{.Host.Security.Rootless}}").CombinedOutput()
	if err != nil {
		t.Skipf("podman info failed: %v\n%s", err, out)
	}
	t.Logf("podman rootless=%s", strings.TrimSpace(string(out)))
}

// podmanEnv is the environment every podman invocation gets: the process
// environment plus the plugin registration override.
type podmanEnv struct {
	t        *testing.T
	override string
}

func (p podmanEnv) cmd(args ...string) *exec.Cmd {
	c := exec.Command("podman", args...)
	c.Env = append(os.Environ(), "CONTAINERS_CONF_OVERRIDE="+p.override)
	return c
}

// run executes podman and fails the test on a non-zero exit.
func (p podmanEnv) run(args ...string) string {
	p.t.Helper()
	out, err := p.cmd(args...).CombinedOutput()
	if err != nil {
		p.t.Fatalf("podman %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// try executes podman and returns its combined output and error.
func (p podmanEnv) try(args ...string) (string, error) {
	out, err := p.cmd(args...).CombinedOutput()
	return string(out), err
}

func waitFor(t *testing.T, timeout time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// buildDotvault returns the binary under test: DOTVAULT_BIN if set, else a
// fresh CGO_ENABLED=0 build into the test's temp dir.
func buildDotvault(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("DOTVAULT_BIN"); bin != "" {
		abs, err := filepath.Abs(bin)
		if err != nil {
			t.Fatal(err)
		}
		return abs
	}
	bin := filepath.Join(t.TempDir(), "dotvault")
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd/dotvault")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// oauthToken reads the oauth_token field of a rendered gh.json document.
func oauthToken(t *testing.T, doc string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("gh.json is not a JSON object: %v\n%s", err, doc)
	}
	s, _ := m["oauth_token"].(string)
	return s
}

func TestPodmanDrivesVolumePlugin(t *testing.T) {
	skipIfNoPodmanE2E(t)
	ctx := context.Background()
	bin := buildDotvault(t)
	work := t.TempDir()
	daemonHome := filepath.Join(work, "home")
	runDir := filepath.Join(work, "run")
	socket := filepath.Join(runDir, "docker.sock")
	volumeDir := filepath.Join(runDir, "volumes")
	for _, d := range []string{daemonHome, runDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	username, err := paths.Username()
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", os.Getpid())
	vaultCtr := "dotvault-e2e-vault-" + suffix
	holderCtr := "dotvault-e2e-holder-" + suffix

	// Podman with the plugin registration. Written now so every podman call,
	// cleanup included, sees it; the socket does not need to exist until a
	// volume names the driver.
	override := filepath.Join(work, "containers.conf")
	conf := fmt.Sprintf("[engine.volume_plugins]\ndotvault = %q\n", socket)
	if err := os.WriteFile(override, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	pm := podmanEnv{t: t, override: override}
	t.Cleanup(func() {
		pm.try("rm", "-f", holderCtr)
		pm.try("volume", "rm", "-f", "app", "shared", "fields")
		pm.try("rm", "-f", vaultCtr)
	})

	t.Log("starting Vault (dev mode) under podman")
	// --network host so the dev listener is plain loopback with no rootless
	// port forwarding in the way; SKIP_SETCAP because the image's entrypoint
	// would otherwise try to grant IPC_LOCK, which a dev server does not need.
	pm.run("run", "-d", "--rm", "--name", vaultCtr, "--network", "host",
		"-e", "SKIP_SETCAP=true",
		"-e", "VAULT_DEV_ROOT_TOKEN_ID="+podmanVaultToken,
		"-e", "VAULT_DEV_LISTEN_ADDRESS="+strings.TrimPrefix(podmanVaultAddr, "http://"),
		podmanVaultImage)
	waitFor(t, 60*time.Second, "Vault to answer", func() bool {
		resp, err := http.Get(podmanVaultAddr + "/v1/sys/health")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})

	t.Logf("seeding secrets under users/%s", username)
	vc, err := vault.NewClient(vault.Config{Address: podmanVaultAddr, Token: podmanVaultToken})
	if err != nil {
		t.Fatal(err)
	}
	// The dev server mounts KVv2 at secret/ already.
	seed := func(key string, data map[string]any) {
		t.Helper()
		if err := vc.WriteKVv2(ctx, "secret", "users/"+username+"/"+key, data); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
	}
	seed("gh", map[string]any{"oauth_token": "gho_first", "user": "e2e"})
	seed("db/prod", map[string]any{"password": "pw-prod"})
	seed("raw", map[string]any{"key": "no trailing newline"})

	t.Log("starting dotvault run")
	config := filepath.Join(work, "config.yaml")
	cfg := fmt.Sprintf(`vault:
  address: %q
  auth_method: token
  kv_mount: secret
  user_prefix: users/
sync:
  interval: 15m
rules:
  - name: marker
    target:
      path: %q
      format: text
      template: "dotvault podman e2e for {{ username }}\n"
docker:
  enabled: true
  socket: %q
  volume_dir: %q
  cache_ttl: 2s
`, podmanVaultAddr, filepath.Join(work, "marker.txt"), socket, volumeDir)
	if err := os.WriteFile(config, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	// Every dotvault invocation gets the same isolated environment: its own
	// HOME (cache dir, token file), the config, and the root token via the env
	// var the `token` auth method reads.
	dv := func(args ...string) *exec.Cmd {
		c := exec.Command(bin, append([]string{"--config", config}, args...)...)
		c.Env = append(os.Environ(), "HOME="+daemonHome, "DOTVAULT_TOKEN="+podmanVaultToken)
		return c
	}
	logPath := filepath.Join(work, "daemon.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	daemon := dv("run", "--log-format", "json", "--log-level", "debug")
	daemon.Stdout, daemon.Stderr = logFile, logFile
	if err := daemon.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	t.Cleanup(func() {
		daemon.Process.Kill()
		daemon.Wait()
		logFile.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logPath)
			t.Logf("daemon log:\n%s", b)
		}
	})
	waitFor(t, 30*time.Second, "the plugin socket", func() bool {
		fi, err := os.Stat(socket)
		return err == nil && fi.Mode()&os.ModeSocket != 0
	})
	status := func() string {
		out, err := dv("status").CombinedOutput()
		if err != nil {
			t.Fatalf("dotvault status: %v\n%s", err, out)
		}
		return string(out)
	}

	t.Log("1. create a volume and read it from a container")
	pm.run("volume", "create", "-d", "dotvault", "-o", "secrets=gh,db/", "app")
	if got := strings.TrimSpace(pm.run("volume", "inspect", "app", "--format", "{{.Driver}}")); got != "dotvault" {
		t.Fatalf("volume driver = %q, want dotvault", got)
	}
	out := pm.run("run", "--rm", "-v", "app:/run/secrets/dotvault:ro", podmanAlpineImage,
		"sh", "-c", "cat /run/secrets/dotvault/gh.json && echo --- && ls /run/secrets/dotvault /run/secrets/dotvault/db")
	t.Log(out)
	doc, listing, _ := strings.Cut(out, "\n---\n")
	if got := oauthToken(t, doc); got != "gho_first" {
		t.Fatalf("gh.json oauth_token = %q, want gho_first", got)
	}
	if !regexp.MustCompile(`(?m)^prod\.json$`).MatchString(listing) {
		t.Fatalf("db/prod.json missing from the folder selection:\n%s", listing)
	}
	if strings.Contains(listing, "raw.json") {
		t.Fatalf("raw.json present although not selected:\n%s", listing)
	}

	t.Log("2. a rewrite in Vault reaches a container that holds the volume")
	pm.run("run", "-d", "--name", holderCtr, "-v", "app:/run/secrets/dotvault:ro", podmanAlpineImage, "sleep", "600")
	holderToken := func() string {
		out, err := pm.try("exec", holderCtr, "cat", "/run/secrets/dotvault/gh.json")
		if err != nil {
			return ""
		}
		return oauthToken(t, out)
	}
	if got := holderToken(); got != "gho_first" {
		t.Fatalf("holder sees oauth_token %q, want gho_first", got)
	}
	seed("gh", map[string]any{"oauth_token": "gho_second", "user": "e2e"})
	// The holder's view is the bind-mounted directory the daemon rewrites into
	// in place; nothing here remounts it, so seeing the new value proves the
	// Community ttl refresh under a held volume.
	waitFor(t, 20*time.Second, "the holder to see the rewritten secret (cache_ttl 2s)", func() bool {
		return holderToken() == "gho_second"
	})

	t.Log("3. dotvault status reports the volume the engine mounted")
	// refresh=poll is what a Community Vault settles on once the daemon's
	// edition probe has answered; until then the line says probing.
	appLine := regexp.MustCompile(`(?m)^  app +mounts=1 secrets=2 refresh=poll`)
	waitFor(t, 20*time.Second, "status to report app with mounts=1 secrets=2 refresh=poll", func() bool {
		return appLine.MatchString(status())
	})
	if s := status(); strings.Contains(s, "Docker Volumes:") {
		t.Log(s[strings.Index(s, "Docker Volumes:"):])
	}

	t.Log("4. the last unmount deletes the directory; volume rm forgets it")
	if _, err := os.Stat(filepath.Join(volumeDir, "app")); err != nil {
		t.Fatalf("volume directory missing while mounted: %v", err)
	}
	pm.run("rm", "-f", holderCtr)
	waitFor(t, 10*time.Second, "the volume directory to be removed after the last unmount", func() bool {
		_, err := os.Lstat(filepath.Join(volumeDir, "app"))
		return os.IsNotExist(err)
	})

	t.Log("5. mode=0444 admits a non-root container user; the default 0400 refuses")
	pm.run("volume", "create", "-d", "dotvault", "-o", "secrets=gh", "-o", "mode=0444", "shared")
	out = pm.run("run", "--rm", "--user", "65534:65534", "-v", "shared:/s:ro", podmanAlpineImage, "cat", "/s/gh.json")
	if got := oauthToken(t, out); got != "gho_second" {
		t.Fatalf("non-root user read %q from a mode=0444 volume, want gho_second", got)
	}
	// Assert on the refusal's cause, not just a non-zero exit: any other
	// failure (a missing image, a bad mount) would otherwise pass for free.
	out, err = pm.try("run", "--rm", "--user", "65534:65534", "-v", "app:/s:ro", podmanAlpineImage, "cat", "/s/gh.json")
	if err == nil {
		t.Fatalf("non-root user read a default-mode (0400) volume:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "permission denied") {
		t.Fatalf("expected a permission error for the 0400 volume, got: %v\n%s", err, out)
	}

	t.Log("6. layout=fields is byte-for-byte; an unknown option is an error")
	pm.run("volume", "create", "-d", "dotvault", "-o", "secrets=raw", "-o", "layout=fields", "fields")
	out = pm.run("run", "--rm", "-v", "fields:/s:ro", podmanAlpineImage, "cat", "/s/raw/key")
	if out != "no trailing newline" {
		t.Fatalf("fields layout wrote %q, want the value with no added newline", out)
	}
	out, err = pm.try("volume", "create", "-d", "dotvault", "-o", "secret=gh", "bad")
	if err == nil {
		t.Fatalf("a volume with an unknown option was created:\n%s", out)
	}
	if !strings.Contains(out, `unknown option "secret"`) {
		t.Fatalf("unknown-option error not surfaced through the engine: %v\n%s", err, out)
	}
	t.Logf("unknown option refused: %s", strings.TrimSpace(out))

	t.Log("removing volumes")
	pm.run("volume", "rm", "app", "shared", "fields")
	for _, name := range strings.Fields(pm.run("volume", "ls", "-q")) {
		if name == "app" || name == "shared" || name == "fields" {
			t.Fatalf("volume %s still listed after rm", name)
		}
	}
	if s := status(); !strings.Contains(s, "no volumes defined") {
		t.Fatalf("status still lists volumes after rm:\n%s", s)
	}
}
