package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/notify"
)

// sendLocalNotification is the local fallback notifier. Indirected so tests
// can assert the fallback ordering without raising a real notification
// (mirrors openLocalBrowser).
var sendLocalNotification = notify.Send

// newNotifyCmd defines `dotvault notify <level> <title> [description]` — the
// notification sibling of `dotvault browse`. It prefers posting to the peer
// dotvault named by vault.token_socket (the same forwarded socket the token
// borrow and remote browse use), and falls back to raising the notification
// locally when no peer is reachable.
func newNotifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notify <level> <title> [description]",
		Short: "Raise a desktop notification, preferring the peer over vault.token_socket",
		Long: fmt.Sprintf(`Raise a native desktop notification (a Windows toast, a macOS
Notification Center panel, or a Linux D-Bus notification).

When vault.token_socket names a reachable peer dotvault (typically an SSH
RemoteForward from a workstation running the web UI), the notification is
posted to the peer's /api/v1/remote/notify endpoint so it appears on the
machine a human is actually looking at. When the peer is not configured or not
reachable, the notification is raised on this host instead.

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
	socket := ""
	if cfg, _, err := loadConfigLocalOnly(); err != nil {
		slog.Warn("could not load config; notifying locally", "error", err)
	} else {
		socket = cfg.Vault.TokenSocket
	}

	if socket != "" {
		err := postNotifyToSocket(cmd.Context(), socket, msg)
		if err == nil {
			return nil
		}
		slog.Debug("peer notify unavailable; notifying locally", "socket", socket, "error", err)
	}

	if err := sendLocalNotification(msg); err != nil {
		return fmt.Errorf("deliver notification locally: %w", err)
	}
	return nil
}

// postNotifyToSocket posts a notification to a peer dotvault's remote-notify
// endpoint over its Unix-domain socket, via the shared auth.PostFormToPeer
// transport. The caller falls back to a local notification on any error.
func postNotifyToSocket(ctx context.Context, socketPath string, msg notify.Message) error {
	form := url.Values{
		"level": {string(msg.Level)},
		"title": {msg.Title},
		"body":  {msg.Body},
	}
	if msg.ActionURL != "" {
		form.Set("action_url", msg.ActionURL)
	}
	return auth.PostFormToPeer(ctx, socketPath, "/api/v1/remote/notify", form)
}
