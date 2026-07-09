package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/browser"
	"github.com/spf13/cobra"

	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/web"
)

// browsePostTimeout bounds the browse POST to a peer socket. Slightly more
// generous than the token-borrow timeout because the peer opens the browser
// synchronously inside the request (xdg-open / `open` / ShellExecute has to
// return before the 200 does).
const browsePostTimeout = 10 * time.Second

// browseBodyLimit caps how much of the peer's response we read — the body is
// a tiny JSON envelope either way.
const browseBodyLimit = 1 << 16 // 64 KiB

// newBrowseCmd defines `dotvault browse <url>` — a $BROWSER-shaped wrapper
// over the remote-browse endpoint. It prefers handing the URL to the peer
// dotvault named by vault.token_socket (the same SSH-forwarded socket the
// token borrow uses, so an already-wired headless host needs no new config),
// and falls back to opening the URL locally when no peer is reachable.
func newBrowseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "browse <url>",
		Short: "Open a URL in a browser, preferring the peer over vault.token_socket",
		Long: `Open a URL in a browser.

When vault.token_socket names a reachable peer dotvault (typically an SSH
RemoteForward from a workstation running the web UI), the URL is posted to
the peer's /api/v1/remote/browse endpoint so the browser opens on the machine
that actually has one. When the peer is not configured or not reachable, the
URL is opened in this host's default browser instead.

Suitable as a BROWSER environment variable target:

  export BROWSER="dotvault browse"`,
		Args: cobra.ExactArgs(1),
		RunE: runBrowse,
	}
}

func runBrowse(cmd *cobra.Command, args []string) error {
	setupLogging()

	// Validate up front with the same allowlist the peer endpoint enforces:
	// neither the remote nor the local opener should ever see a non-http(s)
	// URL, and a local error message beats a round-tripped 400.
	target, err := web.ValidateBrowseURL(args[0])
	if err != nil {
		return err
	}

	// Config is only needed to locate the peer socket. Local-only load (no
	// remote-config fetch): the vault section is local-only, and $BROWSER
	// invocations sit on an interactive latency budget like login-check.
	// A load failure downgrades to the local browser rather than failing —
	// `dotvault browse` should still open URLs on a host with a broken or
	// absent config.
	socket := ""
	if cfg, _, err := loadConfigLocalOnly(); err != nil {
		slog.Warn("could not load config; opening locally", "error", err)
	} else {
		socket = cfg.Vault.TokenSocket
	}

	if socket != "" {
		err := postBrowseToSocket(cmd.Context(), socket, target)
		if err == nil {
			return nil
		}
		slog.Debug("peer browse unavailable; opening locally", "socket", socket, "error", err)
	}

	if err := browser.OpenURL(target); err != nil {
		return fmt.Errorf("open browser locally: %w", err)
	}
	return nil
}

// postBrowseToSocket posts the URL to a peer dotvault's remote-browse
// endpoint over a Unix-domain socket — the programmatic equivalent of
//
//	curl --unix-socket <socketPath> http://localhost/api/v1/remote/browse -d url=<target>
//
// Unlike auth.FetchTokenFromSocket this reports failures: the caller falls
// back to the local browser on any error, but wants the reason for the debug
// log.
func postBrowseToSocket(ctx context.Context, socketPath, target string) error {
	expanded, err := paths.ExpandHome(socketPath)
	if err != nil {
		return fmt.Errorf("expand socket path: %w", err)
	}
	// A missing socket file is the common "peer not connected" case — skip
	// the dial so we don't pay a timeout on it.
	if _, err := os.Stat(expanded); err != nil {
		return fmt.Errorf("peer socket not present: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", expanded)
			},
		},
	}

	ctx, cancel := context.WithTimeout(ctx, browsePostTimeout)
	defer cancel()

	form := url.Values{"url": {target}}
	// The unix dialer ignores the URL host, but "localhost" is on the peer
	// web server's DNS-rebinding Host allowlist.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://localhost/api/v1/remote/browse", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, browseBodyLimit)).Decode(&body)
		if body.Error != "" {
			return fmt.Errorf("peer returned %d: %s", resp.StatusCode, body.Error)
		}
		return fmt.Errorf("peer returned %d", resp.StatusCode)
	}
	return nil
}
