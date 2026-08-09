package main

import (
	"encoding/json"
	"errors"
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

// errSSHNotConfigured is returned by sshFetchLiveRows when the daemon's
// status response omits the "ssh" key entirely, meaning managed forwards
// are not wired up on this daemon (the SSH agent surface is disabled, or
// no status query was ever registered — see Server.sshStatusSnapshot).
// This is distinct from a registry that is live but empty ([]), which
// must render as an empty table, not a fallback. Distinguishing the two
// requires reading presence, not just length, out of the JSON body.
var errSSHNotConfigured = errors.New("managed SSH forwards are not configured on this daemon")

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
		// The daemon is reachable but doesn't know about managed forwards
		// at all (as opposed to a transport failure) — say so, since the
		// daemon already told us as much by omitting the "ssh" key.
		if errors.Is(liveErr, errSSHNotConfigured) {
			fmt.Fprintln(cmd.OutOrStdout(), "managed SSH forwards are not configured on this daemon; listing ssh.yaml directly")
		}
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

	// SSH is a pointer to a slice, not a plain slice, so a JSON body that
	// omits the key entirely (envelope.SSH == nil) can be told apart from
	// one that includes it as an empty array (envelope.SSH != nil, len 0) —
	// the former means managed forwards aren't configured on this daemon,
	// the latter means they are and there's simply nothing there yet.
	var envelope struct {
		SSH *[]sshfwd.RemoteStatus `json:"ssh"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("dotvault daemon: decode status response: %w", err)
	}
	if envelope.SSH == nil {
		return nil, errSSHNotConfigured
	}

	rows := make([]sshListRow, len(*envelope.SSH))
	for i, st := range *envelope.SSH {
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
