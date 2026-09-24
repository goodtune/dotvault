package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/goodtune/dotvault/internal/notify"
	"github.com/goodtune/dotvault/internal/peer"
)

// sendLocalNotification is the local fallback notifier. Indirected so tests
// can assert the fallback ordering without raising a real notification
// (mirrors openLocalBrowser).
var sendLocalNotification = notify.Send

// newNotifyCmd defines `dotvault notify <level> <title> [description]` — the
// notification sibling of `dotvault browse`. It prefers posting to every live
// peer dotvault matching vault.token_socket (the same forwarded sockets the
// token borrow and remote browse use), and falls back to raising the
// notification locally when no peer accepted it.
func newNotifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notify <level> <title> [description]",
		Short: "Raise a desktop notification, preferring the peers in vault.token_socket",
		Long: fmt.Sprintf(`Raise a native desktop notification (a Windows toast, a macOS
Notification Center panel, or a Linux D-Bus notification).

The notification is posted to the /api/v1/remote/notify endpoint of every live
peer socket matching vault.token_socket (by default ~/.ssh/dotvault.sock and
~/.ssh/dotvault.*.sock), so it appears on each workstation forwarding here and a
human sees it wherever they are actually looking. Only when no peer accepted it
is the notification raised on this host instead.

The level is one of: %s. It drives the notification's urgency (error and
attention are delivered as audible alerts) and, where the platform supports a
named icon, the icon shown.

Pass --action-url to attach an http/https link the user is taken to when they
click the notification. This is clickable on Windows (the toast opens the URL);
on macOS and Linux, where a one-shot notification cannot register a click
handler, the URL is appended to the body so it stays visible.

  dotvault notify info "Sync complete" "all rules applied"
  dotvault notify error "Backup failed" "see the logs" --action-url https://ci.example/build/42`, strings.Join(notify.Levels(), ", ")),
		Args: cobra.RangeArgs(2, 3),
		RunE: runNotify,
	}
	cmd.Flags().String("action-url", "", "http/https URL to open when the notification is clicked (Windows) or shown in the body (macOS/Linux)")
	return cmd
}

func runNotify(cmd *cobra.Command, args []string) error {
	setupLogging()

	level, title := args[0], args[1]
	body := ""
	if len(args) == 3 {
		body = args[2]
	}
	actionURL, _ := cmd.Flags().GetString("action-url")

	// Validate up front with the same rules the peer endpoint enforces, so a
	// bad level, empty title, or malformed action URL fails locally with a
	// clear message instead of a round-tripped 400 (and neither the peer nor
	// the local notifier is touched).
	msg, err := notify.NewMessage(level, title, body, actionURL)
	if err != nil {
		return err
	}

	// Config is only needed to locate the peer socket. Local-only load, same
	// rationale as `dotvault browse`: a load failure downgrades to a local
	// notification rather than failing.
	var pool *peer.Pool
	if cfg, _, err := loadConfigLocalOnly(); err != nil {
		slog.Warn("could not load config; notifying locally", "error", err)
	} else {
		pool = newPeerPool(cfg.PeerActionSockets())
	}

	if pool != nil {
		err := postNotifyToPeers(cmd.Context(), pool, msg)
		if err == nil {
			return nil
		}
		slog.Debug("peer notify unavailable; notifying locally", "error", err)
	}

	if err := sendLocalNotification(msg); err != nil {
		return fmt.Errorf("deliver notification locally: %w", err)
	}
	return nil
}

// postNotifyToPeers posts a notification to every active peer dotvault's
// remote-notify endpoint, via the pool's broadcast. Any peer accepting it is
// success; the caller falls back to a local notification on any error.
func postNotifyToPeers(ctx context.Context, pool *peer.Pool, msg notify.Message) error {
	form := url.Values{
		"level": {string(msg.Level)},
		"title": {msg.Title},
		"body":  {msg.Body},
	}
	if msg.ActionURL != "" {
		form.Set("action_url", msg.ActionURL)
	}
	return pool.Broadcast(ctx, "/api/v1/remote/notify", form)
}
