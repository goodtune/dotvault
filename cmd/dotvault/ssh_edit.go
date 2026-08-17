package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"

	"github.com/goodtune/dotvault/internal/sshfwd"
)

// sshEditRequest is the JSON body of PATCH /api/v1/ssh/remotes/{host} —
// matches the daemon's sshPatchRequest (internal/web/ssh.go), a private type
// there, so this package keeps its own copy of the wire shape. Pointer
// fields carry the PATCH semantics: nil leaves the daemon's current value
// untouched.
type sshEditRequest struct {
	Enabled      *bool   `json:"enabled,omitempty"`
	RemoteSocket *string `json:"remote_socket,omitempty"`
	Port         *int    `json:"port,omitempty"`
}

func newSSHEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit <host>",
		Short: "Edit a managed SSH remote forward",
		Long: `Edit host's managed SSH remote forward on the running daemon — the CLI
counterpart of the web UI's per-remote edit form.

Only the fields you pass change; everything else keeps its current value.
--port 0 resets the port to the default (22), and --socket "" resets the
remote socket path to the default (~/.ssh/dotvault.sock). Changes go through
the same registry as "ssh add": the daemon persists ssh.yaml and reconciles
the forward immediately, so --enable/--disable take effect without a
restart.`,
		Args: cobra.ExactArgs(1),
		RunE: runSSHEdit,
	}
	cmd.Flags().Int("port", 0, "SSH port (0 resets to the default, 22)")
	cmd.Flags().String("socket", "", `remote Unix socket path to bind ("" resets to the default, ~/.ssh/dotvault.sock)`)
	cmd.Flags().Bool("enable", false, "enable the forward")
	cmd.Flags().Bool("disable", false, "disable the forward without removing it")
	return cmd
}

func runSSHEdit(cmd *cobra.Command, args []string) error {
	setupLogging()
	host := args[0]

	enable, _ := cmd.Flags().GetBool("enable")
	disable, _ := cmd.Flags().GetBool("disable")
	if enable && disable {
		return fmt.Errorf("--enable and --disable are mutually exclusive")
	}

	// Distinguish "flag not given" from a zero value: --port 0 and
	// --socket "" are deliberate resets to the defaults, not values to leave
	// alone. The socket reset maps to the default literal here because the
	// daemon's validation (deliberately) rejects an empty remote_socket
	// rather than defaulting it on PATCH.
	var req sshEditRequest
	if cmd.Flags().Changed("port") {
		port, _ := cmd.Flags().GetInt("port")
		if port < 0 || port > 65535 {
			return fmt.Errorf("--port must be between 0 and 65535")
		}
		req.Port = &port
	}
	if cmd.Flags().Changed("socket") {
		socket, _ := cmd.Flags().GetString("socket")
		if socket == "" {
			socket = sshfwd.DefaultRemoteSocket
		}
		req.RemoteSocket = &socket
	}
	if enable || disable {
		req.Enabled = &enable
	}
	if req.Port == nil && req.RemoteSocket == nil && req.Enabled == nil {
		return fmt.Errorf("nothing to change: pass at least one of --port, --socket, --enable, --disable")
	}

	cfg, _, err := sshLoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	client, base, err := daemonClient(cfg)
	if err != nil {
		return err
	}

	status, body, err := sshDo(cmd.Context(), client, base, http.MethodPatch, "/api/v1/ssh/remotes/"+url.PathEscape(host), req)
	if err != nil {
		return fmt.Errorf("dotvault daemon: %w", err)
	}

	switch status {
	case http.StatusOK:
		// Echo the daemon's resulting entry so the user sees the effective
		// values (defaults applied) rather than just what they passed.
		var got struct {
			Host         string `json:"host"`
			Port         int    `json:"port"`
			RemoteSocket string `json:"remote_socket"`
			Enabled      bool   `json:"enabled"`
		}
		if err := json.Unmarshal(body, &got); err != nil {
			return fmt.Errorf("dotvault daemon: decode response: %w", err)
		}
		state := "enabled"
		if !got.Enabled {
			state = "disabled"
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s: port %d, socket %s, %s\n", got.Host, got.Port, got.RemoteSocket, state)
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("no managed remote configured for %s", host)
	default:
		return fmt.Errorf("dotvault daemon: %s", sshAPIErrorMessage(status, body))
	}
}
