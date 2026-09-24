package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/pkg/browser"
	"github.com/spf13/cobra"

	"github.com/goodtune/dotvault/internal/peer"
	"github.com/goodtune/dotvault/internal/web"
)

// openLocalBrowser is the local fallback opener. Indirected so tests can
// assert the fallback ordering without popping a real browser (same pattern
// as internal/auth's openBrowser).
var openLocalBrowser = browser.OpenURL

// newBrowseCmd defines `dotvault browse <url>` — a $BROWSER-shaped wrapper
// over the remote-browse endpoint. It prefers handing the URL to every live
// peer dotvault matching vault.token_socket (the same SSH-forwarded sockets the
// token borrow uses, so an already-wired headless host needs no new config),
// and falls back to opening the URL locally when no peer accepted it.
func newBrowseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "browse <url>",
		Short: "Open a URL in a browser, preferring the peers over vault.token_socket",
		Long: `Open a URL in a browser.

vault.token_socket is a list of socket patterns (by default ~/.ssh/dotvault.sock
and ~/.ssh/dotvault.*.sock, the paths a workstation's SSH RemoteForward binds).
The URL is posted to the /api/v1/remote/browse endpoint of every live peer
socket, so the page opens on each workstation forwarding here and the user finds
it wherever they are sitting. Only when no peer accepted it is the URL opened in
this host's default browser instead.

Suitable as a BROWSER environment variable target:

  export BROWSER="dotvault browse"

Note that some tools (notably Python-based ones such as az) exec a multi-word
BROWSER value as a single program name; for those, point BROWSER at a
one-line wrapper script that runs: dotvault browse "$1"`,
		Args: cobra.ExactArgs(1),
		RunE: runBrowse,
	}
}

func runBrowse(cmd *cobra.Command, args []string) error {
	setupLogging()

	// Validate up front with the same allowlist the peer endpoint enforces:
	// neither the remote nor the local opener should ever see a non-http(s)
	// URL, and a local error message beats a round-tripped 400.
	u, err := web.ValidateBrowseURL(args[0])
	if err != nil {
		return err
	}
	target := u.String()

	// Config is only needed to locate the peer socket. Local-only load (no
	// remote-config fetch): the vault section is local-only, and $BROWSER
	// invocations sit on an interactive latency budget like login-check.
	// A load failure downgrades to the local browser rather than failing —
	// `dotvault browse` should still open URLs on a host with a broken or
	// absent config.
	var pool *peer.Pool
	if cfg, _, err := loadConfigLocalOnly(); err != nil {
		slog.Warn("could not load config; opening locally", "error", err)
	} else {
		pool = newPeerPool(cfg.PeerActionSockets())
	}

	if pool != nil {
		err := postBrowseToPeers(cmd.Context(), pool, target)
		if err == nil {
			return nil
		}
		slog.Debug("peer browse unavailable; opening locally", "error", err)
	}

	if err := openLocalBrowser(target); err != nil {
		return fmt.Errorf("open browser locally: %w", err)
	}
	return nil
}

// postBrowseToPeers posts the URL to every active peer dotvault's remote-browse
// endpoint, via the pool's broadcast. Any peer accepting it is success; the
// caller falls back to the local browser on any error.
func postBrowseToPeers(ctx context.Context, pool *peer.Pool, target string) error {
	return pool.Broadcast(ctx, "/api/v1/remote/browse", url.Values{"url": {target}})
}
