package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/goodtune/dotvault/internal/clipboard"
	"github.com/goodtune/dotvault/internal/peer"
)

// setLocalClipboard is the local fallback writer. Indirected so tests can
// assert the fallback ordering without touching a real clipboard (mirrors
// openLocalBrowser / sendLocalNotification).
var setLocalClipboard = clipboard.Set

// newClipboardCmd defines `dotvault clipboard [text]` — the third peer action
// alongside `dotvault browse` and `dotvault notify`. It prefers posting to
// every live peer dotvault matching vault.token_socket (the same forwarded
// sockets the token borrow uses), and falls back to this host's clipboard when
// no peer accepted it.
func newClipboardCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clipboard [text]",
		Short: "Put text on the clipboard, preferring the peers in vault.token_socket",
		Long: `Put text on the system clipboard.

The text is posted to the /api/v1/remote/clipboard endpoint of every live peer
socket matching vault.token_socket (by default ~/.ssh/dotvault.sock and
~/.ssh/dotvault.*.sock), so it lands on the clipboard of each workstation
forwarding here. With several connected that means ALL of their clipboards, so
stage a one-time value rather than a long-lived secret. Only when no peer
accepted it is the text placed on this host's clipboard instead.

With no positional argument (or with "-"), the text is read from stdin; a
single trailing newline is stripped so shell piping does not paste a stray
newline into whatever field the value lands in. Prefer stdin for secrets — a
positional argument is visible to other local processes in the process
listing:

  jq -r .token creds.json | dotvault clipboard

Together with dotvault browse and notify, this closes the loop for
authenticating to a service from a headless host: open the login page in the
workstation's browser, and put the one-time token or device code on the
workstation's clipboard, ready to paste.

The text is capped at 64 KiB and must be valid UTF-8 with no NUL bytes; it is
otherwise written verbatim.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runClipboard,
	}
}

func runClipboard(cmd *cobra.Command, args []string) error {
	setupLogging()

	text, err := clipboardText(cmd, args)
	if err != nil {
		return err
	}
	// Validate up front with the same rules the peer endpoint enforces, so
	// bad input fails locally with a clear message instead of a round-tripped
	// 400 (and neither the peer nor the local writer is touched).
	if err := clipboard.ValidateText(text); err != nil {
		return err
	}

	// Config is only needed to locate the peer socket. Local-only load, same
	// rationale as `dotvault browse`: a load failure downgrades to the local
	// clipboard rather than failing.
	var pool *peer.Pool
	if cfg, _, err := loadConfigLocalOnly(); err != nil {
		slog.Warn("could not load config; using the local clipboard", "error", err)
	} else {
		pool = newPeerPool(cfg.PeerActionSockets())
	}

	if pool != nil {
		err := postClipboardToPeers(cmd.Context(), pool, text)
		if err == nil {
			return nil
		}
		// Scrub the text from the logged error: a peer's non-200 body is
		// echoed into peer.StatusError.Message, so a hostile or buggy peer
		// could otherwise reflect the secret into this host's logs. The
		// broadcast joins every peer's failure, so one error may carry several
		// such bodies — all the more reason to scrub rather than trust.
		slog.Debug("peer clipboard unavailable; using the local clipboard",
			"error", strings.ReplaceAll(err.Error(), text, "<text>"))
	}

	if err := setLocalClipboard(text); err != nil {
		return fmt.Errorf("set clipboard locally: %w", err)
	}
	return nil
}

// clipboardText resolves the text: the positional argument when given (and
// not "-"), else stdin. Stdin is read against the validation cap so an
// over-limit input errors rather than being silently truncated (a truncated
// credential is corrupt), and exactly one trailing newline (\n or \r\n) is
// stripped — the near-universal artefact of `echo`/pipeline usage, and never
// load-bearing in a value meant to be pasted.
func clipboardText(cmd *cobra.Command, args []string) (string, error) {
	if len(args) == 1 && args[0] != "-" {
		return args[0], nil
	}
	// Read up to the cap + 3: a maximal legitimate input is MaxTextLen bytes
	// plus a trailing "\r\n", and one extra byte lets the over-limit check
	// distinguish "too big" from "exactly at the limit". The length check runs
	// AFTER newline stripping so `printf '%s\n' <64KiB-value>` is accepted —
	// the stripped newline was never going to be part of the text.
	data, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), clipboard.MaxTextLen+3))
	if err != nil {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	text := string(data)
	// "\r\n" before "\n" so a lone trailing "\r" (no "\n") is preserved —
	// only a genuine trailing newline is stripped.
	if strings.HasSuffix(text, "\r\n") {
		text = text[:len(text)-2]
	} else {
		text = strings.TrimSuffix(text, "\n")
	}
	if len(text) > clipboard.MaxTextLen {
		return "", fmt.Errorf("stdin exceeds the %d-byte clipboard limit", clipboard.MaxTextLen)
	}
	return text, nil
}

// postClipboardToPeers posts the text to every active peer dotvault's
// remote-clipboard endpoint, via the pool's broadcast. Any peer accepting it is
// success; the caller falls back to the local clipboard on any error.
func postClipboardToPeers(ctx context.Context, pool *peer.Pool, text string) error {
	return pool.Broadcast(ctx, "/api/v1/remote/clipboard", url.Values{"text": {text}})
}
