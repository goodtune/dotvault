package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

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
	return &cobra.Command{
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

  dotvault notify info "Sync complete" "all rules applied"
  dotvault notify error "Backup failed" "see the logs"`, strings.Join(notify.Levels(), ", ")),
		Args: cobra.RangeArgs(2, 3),
		RunE: runNotify,
	}
}

func runNotify(cmd *cobra.Command, args []string) error {
	setupLogging()

	level, title := args[0], args[1]
	body := ""
	if len(args) == 3 {
		body = args[2]
	}

	// Validate up front with the same rules the peer endpoint enforces, so a
	// bad level or empty title fails locally with a clear message instead of
	// a round-tripped 400 (and neither the peer nor the local notifier is
	// touched).
	msg, err := notify.NewMessage(level, title, body)
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
		if err := postNotifyToSocket(cmd.Context(), socket, msg); err == nil {
			return nil
		} else {
			slog.Debug("peer notify unavailable; notifying locally", "socket", socket, "error", err)
		}
	}

	if err := sendLocalNotification(msg); err != nil {
		return fmt.Errorf("deliver notification locally: %w", err)
	}
	return nil
}

// postNotifyToSocket posts a notification to a peer dotvault's remote-notify
// endpoint over its Unix-domain socket, via the shared postFormToPeer
// transport. The caller falls back to a local notification on any error.
func postNotifyToSocket(ctx context.Context, socketPath string, msg notify.Message) error {
	form := url.Values{
		"level": {string(msg.Level)},
		"title": {msg.Title},
		"body":  {msg.Body},
	}
	return postFormToPeer(ctx, socketPath, "/api/v1/remote/notify", form)
}
