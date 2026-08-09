package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/sshfwd"
)

// sshListRow is one line of `dotvault ssh list` output, sourced either from
// the daemon's live status (the common path) or, when the daemon cannot be
// reached, from ssh.yaml directly (see runSSHList).
type sshListRow struct {
	Host         string
	Status       string
	RemoteSocket string
	Reconnects   string
	LastError    string
}

func newSSHListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List managed SSH remote forwards",
		Long: `List every configured SSH remote forward and its live state, as reported
by the running daemon.

When the daemon cannot be reached, this falls back to reading ssh.yaml
directly and prints "unavailable" in the STATUS column — reading the config
file is safe without a daemon; writing it is not, which is why every mutating
subcommand (add/remove) always goes through the daemon's API.`,
		Args: cobra.NoArgs,
		RunE: runSSHList,
	}
}

func runSSHList(cmd *cobra.Command, args []string) error {
	setupLogging()

	cfg, _, err := sshLoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	rows, liveErr := sshFetchLiveRows(cmd, cfg)
	if liveErr != nil {
		fallback, ferr := sshFallbackRows()
		if ferr != nil {
			// Both the daemon and the local file are unusable: report the
			// daemon failure, since that's the one a user can typically act
			// on (start the daemon), and note the fallback also failed.
			return fmt.Errorf("dotvault daemon unreachable (%v); local ssh.yaml fallback also failed: %w", liveErr, ferr)
		}
		rows = fallback
	}

	printSSHTable(cmd.OutOrStdout(), rows)
	return nil
}

// sshFetchLiveRows asks the running daemon for its current SSH-forward
// status via GET /api/v1/status (the same unauthenticated endpoint the web
// dashboard polls) and projects its "ssh" block into rows, ordered by host
// (Manager.Status already returns that order; sorted again here defensively
// so the contract does not depend on the daemon's internal ordering).
func sshFetchLiveRows(cmd *cobra.Command, cfg *config.Config) ([]sshListRow, error) {
	client, base, err := daemonClient(cfg)
	if err != nil {
		return nil, err
	}

	status, body, err := sshDo(cmd.Context(), client, base, http.MethodGet, "/api/v1/status", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("dotvault daemon: %s", sshAPIErrorMessage(status, body))
	}

	var envelope struct {
		SSH []sshfwd.RemoteStatus `json:"ssh"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("dotvault daemon: decode status response: %w", err)
	}

	rows := make([]sshListRow, len(envelope.SSH))
	for i, st := range envelope.SSH {
		rows[i] = sshListRow{
			Host:         st.Host,
			Status:       st.State,
			RemoteSocket: st.RemoteSocket,
			Reconnects:   strconv.Itoa(st.Reconnects),
			LastError:    st.LastError,
		}
	}
	sort.Slice(rows, func(i, j int) bool { return strings.ToLower(rows[i].Host) < strings.ToLower(rows[j].Host) })
	return rows, nil
}

// sshFallbackRows reads ssh.yaml directly when the daemon cannot be reached.
// This is read-only and therefore safe without a daemon — every mutation
// still goes exclusively through the daemon's API, so there is no writer to
// race here. Every row reports "unavailable" in the STATUS column: with no
// daemon to ask, nothing is known about the forward's live state.
func sshFallbackRows() ([]sshListRow, error) {
	path, err := paths.SSHConfigPath()
	if err != nil {
		return nil, fmt.Errorf("resolve ssh.yaml path: %w", err)
	}
	f, err := sshfwd.Load(path)
	if err != nil {
		return nil, err
	}

	rows := make([]sshListRow, len(f.Remotes))
	for i, r := range f.Remotes {
		rows[i] = sshListRow{
			Host:         r.Host,
			Status:       "unavailable",
			RemoteSocket: r.RemoteSocket,
			Reconnects:   "-",
			LastError:    "-",
		}
	}
	sort.Slice(rows, func(i, j int) bool { return strings.ToLower(rows[i].Host) < strings.ToLower(rows[j].Host) })
	return rows, nil
}

// printSSHTable renders rows as a simple tab-aligned table.
func printSSHTable(w io.Writer, rows []sshListRow) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tSTATUS\tREMOTE SOCKET\tRECONNECTS\tLAST ERROR")
	for _, r := range rows {
		lastError := r.LastError
		if lastError == "" {
			lastError = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Host, r.Status, r.RemoteSocket, r.Reconnects, lastError)
	}
	tw.Flush()
}
