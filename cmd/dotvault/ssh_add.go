package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// sshAddRequest is the JSON body of POST /api/v1/ssh/remotes — matches the
// daemon's sshRemoteRequest (internal/web/ssh.go), a private type there, so
// this package keeps its own copy of the wire shape.
type sshAddRequest struct {
	Host              string `json:"host"`
	Port              int    `json:"port,omitempty"`
	RemoteSocket      string `json:"remote_socket,omitempty"`
	Force             bool   `json:"force,omitempty"`
	AcceptFingerprint string `json:"accept_fingerprint,omitempty"`
}

// sshHostKeyConfirmation is the 409 body a POST returns when a host's key is
// neither pinned nor CA-signed: the caller must echo Fingerprint back via
// AcceptFingerprint to commit.
type sshHostKeyConfirmation struct {
	Host        string `json:"host"`
	Fingerprint string `json:"fingerprint"`
}

func newSSHAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <host>",
		Short: "Register a managed SSH remote forward",
		Long: `Register host with the running daemon so it maintains a persistent SSH
remote forward to it, exposing dotvault's own web API there as a Unix socket.

The daemon performs a live SSH dial, credential check, and host-key
verification before persisting anything. An unpinned host's key is printed
for confirmation: on a terminal you are prompted to accept it; from a script
or non-interactive shell, pass --accept-host-key after verifying the printed
fingerprint out of band.

--port and --socket override the remote's SSH port (default 22) and the Unix
socket path bound on the remote (default ~/.ssh/dotvault.sock) respectively.
--force skips verification entirely and persists the entry as given — the
documented escape for registering a host that is offline right now; it does
not bypass the host-key confirmation gate on a later re-add, only the
verification dial itself.`,
		Args: cobra.ExactArgs(1),
		RunE: runSSHAdd,
	}
	cmd.Flags().Bool("force", false, "skip verification and persist the entry as given (for a host that is offline right now)")
	cmd.Flags().Bool("accept-host-key", false, "accept an unpinned host's key without an interactive prompt (its fingerprint is still printed first)")
	cmd.Flags().String("socket", "", "remote Unix socket path to bind (default ~/.ssh/dotvault.sock)")
	cmd.Flags().Int("port", 0, "SSH port (default 22)")
	return cmd
}

func runSSHAdd(cmd *cobra.Command, args []string) error {
	setupLogging()
	host := args[0]

	force, _ := cmd.Flags().GetBool("force")
	acceptHostKey, _ := cmd.Flags().GetBool("accept-host-key")
	socket, _ := cmd.Flags().GetString("socket")
	port, _ := cmd.Flags().GetInt("port")

	cfg, _, err := sshLoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	client, base, err := daemonClient(cfg)
	if err != nil {
		return err
	}

	req := sshAddRequest{Host: host, Port: port, RemoteSocket: socket, Force: force}
	ctx := cmd.Context()

	status, body, err := sshDo(ctx, client, base, http.MethodPost, "/api/v1/ssh/remotes", req)
	if err != nil {
		return fmt.Errorf("dotvault daemon: %w", err)
	}

	if status == http.StatusConflict {
		var confirm sshHostKeyConfirmation
		if jerr := json.Unmarshal(body, &confirm); jerr != nil {
			return fmt.Errorf("dotvault daemon: decode host-key confirmation: %w", jerr)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "The host key for %s is not yet trusted.\nFingerprint: %s\n", confirm.Host, confirm.Fingerprint)

		if !acceptHostKey {
			if !sshIsInteractive() {
				return fmt.Errorf(
					"refusing to trust %s's host key without confirmation on a non-interactive session: "+
						"verify the fingerprint above out of band, then re-run with --accept-host-key",
					confirm.Host)
			}
			ok, perr := sshConfirmPrompt(cmd, fmt.Sprintf("Trust this host key for %s?", confirm.Host))
			if perr != nil {
				return perr
			}
			if !ok {
				return fmt.Errorf("host key for %s was not accepted; nothing was added", confirm.Host)
			}
		}

		req.AcceptFingerprint = confirm.Fingerprint
		status, body, err = sshDo(ctx, client, base, http.MethodPost, "/api/v1/ssh/remotes", req)
		if err != nil {
			return fmt.Errorf("dotvault daemon: %w", err)
		}
	}

	if status != http.StatusCreated {
		if status == http.StatusConflict {
			// A 409 surviving the one confirmed re-POST means the daemon's
			// view of the key changed again between the two requests (a
			// genuine race, not the ordinary flow) — say so specifically
			// rather than falling through to the generic "request failed
			// with status 409", which names neither the host nor the new
			// fingerprint the user would need to confirm.
			var again sshHostKeyConfirmation
			if jerr := json.Unmarshal(body, &again); jerr == nil && again.Fingerprint != "" {
				return fmt.Errorf(
					"dotvault daemon: host key confirmation required again for %s (fingerprint %s); the daemon's view of the key changed since it was last displayed — re-run ssh add to confirm the new one",
					again.Host, again.Fingerprint)
			}
		}
		return fmt.Errorf("dotvault daemon: %s", sshAPIErrorMessage(status, body))
	}
	// Silent on success, matching this repo's other daemon-mutating CLIs.
	return nil
}

// sshIsInteractive reports whether both stdin and stderr are a TTY a human
// can see and respond to — matching this repo's convention for gating an
// interactive prompt (see enrol.go's picker, which requires the same pair).
// Checking stdin alone would let a redirected-stderr invocation (stdin a
// real terminal, stderr piped to a log file) block forever on a prompt the
// human never sees. A 409 without --accept-host-key on a non-interactive
// session (a script, a CI job, a piped invocation) must be a hard error
// rather than degrading into an invisible prompt — or worse, a silent
// accept.
var sshIsInteractive = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
}

// sshConfirmPrompt asks a yes/no question on stderr (matching the fingerprint
// line above it) and reads the answer from cmd.InOrStdin() (os.Stdin in
// production; a test supplies canned input via cmd.SetIn). Only "y"/"yes"
// (case-insensitive) count as acceptance; anything else, including a bare
// Enter, declines. A read error also declines — surfaced as an error rather
// than treated as an empty answer, so a broken stdin can never be silently
// read as acceptance.
func sshConfirmPrompt(cmd *cobra.Command, question string) (bool, error) {
	fmt.Fprintf(cmd.ErrOrStderr(), "%s [y/N]: ", question)
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}
