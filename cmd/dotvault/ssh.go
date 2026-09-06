package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/config"
)

// newSSHCmd defines the `dotvault ssh` parent command: add/list/remove are
// thin clients of the daemon's own web API (Task 13's /api/v1/ssh/remotes
// endpoints) rather than a second writer of ssh.yaml.
//
// The CLI never touches ssh.yaml directly: the SSH identity lives in the
// daemon's agent backend, so only a running daemon can perform the verifying
// login `ssh add` requires, and routing every mutation through the one
// Registry the web UI also uses removes the CLI-versus-daemon lost-update
// race outright.
func newSSHCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh",
		Short: "Manage daemon-maintained SSH remote forwards",
		Long: `Manage the SSH remote forwards the running dotvault daemon maintains.

These commands are thin clients of the daemon's own web API — nothing here
edits ssh.yaml directly. A running, authenticated daemon is required:
"dotvault ssh add" in particular performs a live SSH dial, credential check,
and host-key verification through the daemon's agent identity before
anything is persisted.

The daemon is reached over its per-user local API socket when api.enabled is
set (Unix only), or otherwise over its loopback web listener when web.enabled
is set. On Windows only the web listener exists today, so web.enabled must be
set there. "ssh list" degrades gracefully when neither is reachable (it falls
back to reading ssh.yaml directly); "ssh add" and "ssh remove" cannot — a
mutation always requires the daemon.

If a request happens to arrive over the very forward it is about to change —
"ssh remove" run against a host reached only through the forward being
removed, or a config edit that restarts it — the change still commits, but
the connection carrying the request is dropped mid-response as that forward's
old connection is torn down. Re-run over a different path (directly, or a
different managed forward) to confirm the result.`,
	}
	cmd.AddCommand(newSSHAddCmd(), newSSHEditCmd(), newSSHListCmd(), newSSHRemoveCmd())
	return cmd
}

// sshLoadConfig resolves the local config the ssh subcommands run against.
// Indirected to the package var (rather than calling loadConfigLocalOnly
// directly) purely so tests can supply a config in-process without
// contending with a real system-wide dotvault install on the test host —
// the same --config-refusal gate loadConfigLocalOnly enforces in production
// (see resolveConfigSource) otherwise makes every ssh subcommand test depend
// on the test host having no system config at all, exactly the class of
// environment-specific flakiness main_test.go already special-cases for
// (see its skip when paths.SystemConfigPath() exists).
var sshLoadConfig = loadConfigLocalOnly

// daemonHTTPTimeout bounds every request `dotvault ssh` makes to the daemon.
// Looser than a typical local IPC call because `ssh add` triggers a live SSH
// dial, authentication, and host-key check on the daemon side — a real
// network round trip to a possibly slow or unreachable host, not just a
// local JSON read.
const daemonHTTPTimeout = 30 * time.Second

// daemonClient returns an HTTP client addressed at the running daemon's API.
//
// Transport preference mirrors the forward's own target: the per-user API
// socket when api.enabled (owner-only, and present on a headless host with no
// web UI), else the loopback web listener. On Windows only the latter exists
// today, so `dotvault ssh` there requires web.enabled — stated in the error so
// the user is not left guessing.
//
// The CLI is deliberately a thin client rather than a second writer of
// ssh.yaml: the SSH identity lives in the daemon's agent backend, so only the
// daemon can perform the verifying login that `add` requires, and a single
// writer removes the lost-update race outright.
func daemonClient(cfg *config.Config) (*http.Client, string, error) {
	sock, err := cfg.APISocketPath()
	if err != nil {
		return nil, "", fmt.Errorf("resolve api.unix.path: %w", err)
	}
	if sock != "" {
		client, _, perr := auth.PeerSocketClient(sock)
		if perr != nil {
			return nil, "", fmt.Errorf("cannot reach the dotvault daemon at its local API socket %s: %w", sock, perr)
		}
		client.Timeout = daemonHTTPTimeout
		// The unix dialer ignores the URL host, but "localhost" is on the
		// web server's DNS-rebinding Host allowlist (see internal/web).
		return client, "http://localhost", nil
	}

	if cfg.Web.Enabled && cfg.Web.Listen != "" {
		return &http.Client{Timeout: daemonHTTPTimeout}, "http://" + cfg.Web.Listen, nil
	}

	if runtime.GOOS == "windows" {
		return nil, "", fmt.Errorf("dotvault ssh needs a reachable daemon API: enable web.enabled (the local API socket is not supported on Windows yet)")
	}
	return nil, "", fmt.Errorf("dotvault ssh needs a reachable daemon API: enable api.enabled or web.enabled in the dotvault config")
}

// sshCSRFToken fetches a one-time CSRF token from the daemon, required on
// every mutating request (see internal/web/csrf.go): the SSH remote CRUD
// endpoints are ordinary CSRF-protected mutations, not one of the
// Origin-checked peer-action exemptions, because both consumers here (this
// CLI and the browser) can run the issue-then-spend handshake.
func sshCSRFToken(ctx context.Context, client *http.Client, base string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/csrf", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not reach the dotvault daemon: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("dotvault daemon: csrf token request returned status %d", resp.StatusCode)
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return "", fmt.Errorf("dotvault daemon: decode csrf response: %w", err)
	}
	return body.Token, nil
}

// sshDo issues one request against the daemon's API. reqBody, when non-nil,
// is JSON-marshalled as the request body; mutating methods (anything but GET)
// fetch and attach a fresh CSRF token first. It returns the raw status code
// and response body so callers can branch on the daemon's documented statuses
// (201 created, 400 validation, 404 unknown host, 409 confirmation required,
// 503 not configured) rather than treating any of them as a Go error — only a
// transport failure (the daemon unreachable at all) is returned as err.
func sshDo(ctx context.Context, client *http.Client, base, method, path string, reqBody any) (status int, body []byte, err error) {
	var reader io.Reader
	if reqBody != nil {
		b, merr := json.Marshal(reqBody)
		if merr != nil {
			return 0, nil, merr
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, base+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		token, terr := sshCSRFToken(ctx, client, base)
		if terr != nil {
			return 0, nil, terr
		}
		req.Header.Set("X-CSRF-Token", token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("could not reach the dotvault daemon: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("dotvault daemon: read response: %w", err)
	}
	return resp.StatusCode, data, nil
}

// sshAPIErrorMessage extracts the daemon's {"error": "..."} envelope from an
// error response body, falling back to a generic status line when the body
// doesn't parse (or carries no message).
func sshAPIErrorMessage(status int, body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &e); err == nil && e.Error != "" {
		return e.Error
	}
	return fmt.Sprintf("request failed with status %d", status)
}
