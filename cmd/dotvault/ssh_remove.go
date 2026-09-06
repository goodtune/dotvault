package main

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
)

func newSSHRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <host>",
		Short: "Remove a managed SSH remote forward",
		Long: `Remove host from the running daemon's managed SSH remote forwards.

Idempotent: removing a host that is not configured is not an error — it
prints a message and exits 0, matching Registry.Remove's own idempotent
contract.`,
		Args: cobra.ExactArgs(1),
		RunE: runSSHRemove,
	}
}

func runSSHRemove(cmd *cobra.Command, args []string) error {
	setupLogging()
	host := args[0]

	cfg, _, err := sshLoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	client, base, err := daemonClient(cfg)
	if err != nil {
		return err
	}

	status, body, err := sshDo(cmd.Context(), client, base, http.MethodDelete, "/api/v1/ssh/remotes/"+url.PathEscape(host), nil)
	if err != nil {
		return fmt.Errorf("dotvault daemon: %w", err)
	}

	switch status {
	case http.StatusNoContent:
		// Silent on success, matching this repo's other daemon-mutating CLIs.
		return nil
	case http.StatusNotFound:
		fmt.Fprintf(cmd.OutOrStdout(), "no managed remote configured for %s\n", host)
		return nil
	default:
		return fmt.Errorf("dotvault daemon: %s", sshAPIErrorMessage(status, body))
	}
}
