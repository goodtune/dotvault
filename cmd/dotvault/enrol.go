package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/enrol"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/vault"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// newEnrolCmd defines the `dotvault enrol` subcommand: a CLI entry
// point that mirrors the web UI's enrolment page.
//
//   - `dotvault enrol` with no args lists the configured enrolments in
//     an interactive picker (arrow keys + Enter).
//   - `dotvault enrol <name>` runs a single enrolment directly,
//     identified by the configured key (the map key under the
//     `enrolments:` section in YAML).
//
// In both forms the command requires a valid cached Vault token; it
// does not initiate fresh authentication. If no token is available it
// exits with a clear pointer to `dotvault login`.
func newEnrolCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enrol [name]",
		Short: "Run an enrolment flow (interactive picker, or single by name)",
		Long: `Run a credential-acquisition enrolment flow from the terminal.

With no argument, opens an interactive picker listing every configured
enrolment alongside its current status (enrolled / not enrolled).
Arrow keys navigate, Enter runs the highlighted enrolment, and q (or
Esc) exits.

With a single positional argument, runs the named enrolment directly
without showing the picker. The name is the configured enrolment key
(the map key under the YAML "enrolments:" section, also the final
path segment in Vault).

A valid cached Vault token is required. If no token is available, the
command exits with a non-zero status pointing at "dotvault login";
this command does not initiate fresh authentication itself.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runEnrol,
	}
}

func runEnrol(cmd *cobra.Command, args []string) error {
	setupLogging()

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if len(cfg.Enrolments) == 0 {
		fmt.Fprintln(os.Stderr, "dotvault: no enrolments configured")
		return nil
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	username, err := paths.Username()
	if err != nil {
		return fmt.Errorf("resolve username: %w", err)
	}

	vc, err := vault.NewClient(vault.Config{
		Address:       cfg.Vault.Address,
		CACert:        cfg.Vault.CACert,
		TLSSkipVerify: cfg.Vault.TLSSkipVerify,
	})
	if err != nil {
		return fmt.Errorf("create vault client: %w", err)
	}

	token := auth.ResolveToken(paths.VaultTokenPath())
	if token == "" {
		fmt.Fprintln(os.Stderr, "dotvault: not authenticated; run `dotvault login` first")
		os.Exit(1)
	}
	vc.SetToken(token)
	if _, err := vc.LookupSelf(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "dotvault: cached vault token is invalid (%v); run `dotvault login` first\n", err)
		os.Exit(1)
	}

	enrolIO := enrol.IO{
		Out:      os.Stderr,
		In:       os.Stdin,
		Browser:  browser.OpenURL,
		Log:      slog.Default(),
		Username: username,
		PromptSecret: func(label string) (string, error) {
			fd := int(os.Stdin.Fd())
			if !term.IsTerminal(fd) {
				return "", fmt.Errorf("cannot prompt for passphrase: stdin is not a terminal")
			}
			fmt.Fprintf(os.Stderr, "%s ", label)
			pass, err := term.ReadPassword(fd)
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return "", err
			}
			return string(pass), nil
		},
	}
	mgr := enrol.NewManager(enrol.ManagerConfig{
		Enrolments: cfg.Enrolments,
		KVMount:    cfg.Vault.KVMount,
		UserPrefix: cfg.Vault.UserPrefix + username + "/",
	}, vc, enrolIO)

	if len(args) == 1 {
		if _, ok := cfg.Enrolments[args[0]]; !ok {
			fmt.Fprintf(os.Stderr, "dotvault: unknown enrolment %q\n", args[0])
			fmt.Fprintln(os.Stderr, "configured enrolments:")
			keys := make([]string, 0, len(cfg.Enrolments))
			for k := range cfg.Enrolments {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(os.Stderr, "  %s\n", k)
			}
			os.Exit(1)
		}
		if err := mgr.RunOne(ctx, args[0]); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		return nil
	}

	// No argument: require a TTY for the interactive picker. A
	// headless caller has no way to drive the selection, and silently
	// printing a list would surprise scripts expecting either a clean
	// run or an explicit error.
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
		fmt.Fprintln(os.Stderr, "dotvault: enrol with no argument requires a terminal")
		fmt.Fprintln(os.Stderr, "pass one of the configured enrolment names to run non-interactively:")
		keys := make([]string, 0, len(cfg.Enrolments))
		for k := range cfg.Enrolments {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(os.Stderr, "  %s\n", k)
		}
		os.Exit(1)
	}

	return runEnrolTUI(ctx, mgr)
}

// runEnrolTUI drives the interactive enrolment picker. The terminal is
// switched to raw mode for keystroke reads, restored around each
// enrolment run (so the engine's terminal-aware I/O works normally),
// and finally restored on exit via defer.
func runEnrolTUI(ctx context.Context, mgr *enrol.Manager) error {
	tty := os.Stderr
	in := os.Stdin

	model := &tuiModel{statuses: mgr.Statuses(ctx)}
	if len(model.statuses) == 0 {
		fmt.Fprintln(tty, "dotvault: no enrolments configured")
		return nil
	}

	for {
		choice, quit, err := tuiSelect(in, tty, model)
		if err != nil {
			return err
		}
		if quit {
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}

		// runOne owns the terminal — engines (browser launches,
		// passphrase prompts, the JFrog/SSH wizard text) expect cooked
		// I/O. The TUI re-renders the refreshed status list after the
		// engine returns so the user can pick another or quit.
		fmt.Fprintln(tty)
		if err := mgr.RunOne(ctx, choice); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			fmt.Fprintf(tty, "\n✗ %s — %v\n", choice, err)
		}
		// Terminal is back in cooked mode (Restore deferred inside
		// tuiSelect ran), so stdin is line-buffered — a "press any
		// key" prompt would actually wait for Enter anyway.
		fmt.Fprint(tty, "\nPress Enter to return to the menu... ")
		buf := make([]byte, 16)
		if _, rerr := in.Read(buf); rerr != nil && !errors.Is(rerr, io.EOF) {
			return rerr
		}
		model.statuses = mgr.Statuses(ctx)
	}
}

// tuiModel is the picker's UI state.
type tuiModel struct {
	statuses []enrol.Status
	cursor   int
}

func (m *tuiModel) up() {
	if m.cursor > 0 {
		m.cursor--
	}
}

func (m *tuiModel) down() {
	if m.cursor < len(m.statuses)-1 {
		m.cursor++
	}
}

// render emits the picker's frame to w using ANSI escape sequences.
// Always starts at the top of the screen and clears each line; this
// is enough for a small fixed list without resorting to a full
// terminal-state library.
//
// All upstream-controlled strings (Engine, EngineName, Error) are
// scrubbed with sanitizeOneLine before interpolation. Vault is a
// trusted backend, but an OSC sequence in a Vault error response
// would otherwise survive into the user's terminal scrollback after
// term.Restore — cheap defense-in-depth.
func (m *tuiModel) render(w io.Writer) {
	var sb strings.Builder
	// Move cursor home + clear screen.
	sb.WriteString("\x1b[H\x1b[2J")
	sb.WriteString("dotvault — enrolments\r\n\r\n")

	nameWidth := len("ENROLMENT")
	engineWidth := len("ENGINE")
	for _, s := range m.statuses {
		if len(s.Key) > nameWidth {
			nameWidth = len(s.Key)
		}
		display := s.EngineName
		if display == "" {
			display = s.Engine
		}
		if len(display) > engineWidth {
			engineWidth = len(display)
		}
	}

	fmt.Fprintf(&sb, "    %-*s  %-*s  %s\r\n", nameWidth, "ENROLMENT", engineWidth, "ENGINE", "STATUS")
	for i, s := range m.statuses {
		marker := "  "
		if i == m.cursor {
			marker = "▶ "
		}
		display := s.EngineName
		if display == "" {
			display = s.Engine
		}
		status := "not enrolled"
		if s.Enrolled {
			status = "enrolled"
		}
		if s.Error != "" {
			status = "error: " + sanitizeOneLine(s.Error)
		}
		line := fmt.Sprintf("%s  %-*s  %-*s  %s",
			marker,
			nameWidth, sanitizeOneLine(s.Key),
			engineWidth, sanitizeOneLine(display),
			status,
		)
		if i == m.cursor {
			// Inverted highlight for the selected row.
			sb.WriteString("\x1b[7m")
			sb.WriteString(line)
			sb.WriteString("\x1b[0m")
		} else {
			sb.WriteString(line)
		}
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n↑/↓ navigate · Enter run · q quit\r\n")
	_, _ = w.Write([]byte(sb.String()))
}

// sanitizeOneLine drops ASCII control characters (including newlines
// and ESC) so adversary-controlled bytes from Vault responses or
// upstream identities cannot inject ANSI escape sequences into the
// rendered TUI line — control chars would either break column
// alignment or, in the case of OSC sequences, persist into the
// terminal's title bar or scrollback after the picker exits.
func sanitizeOneLine(s string) string {
	if !strings.ContainsFunc(s, isControlRune) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isControlRune(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isControlRune(r rune) bool {
	return r < 0x20 || r == 0x7f
}

// tuiSelect runs one cycle of the picker: switch the terminal into
// raw mode, render-and-read until the user picks a row or quits, then
// restore the cooked terminal state. Returns (selectedKey, quit,
// error); when quit is true the caller should return cleanly.
func tuiSelect(in *os.File, tty *os.File, model *tuiModel) (string, bool, error) {
	fd := int(in.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return "", false, fmt.Errorf("enter raw mode: %w", err)
	}
	defer term.Restore(fd, oldState) //nolint:errcheck

	// On Windows, MakeRaw enables VT input but not VT output; without
	// this the ANSI sequences in render() print as literal text on
	// bare cmd.exe. No-op everywhere else.
	restoreVT := enableVTOutput(tty)
	defer restoreVT()

	for {
		model.render(tty)
		key, err := readSingleKey(in)
		if err != nil {
			return "", false, err
		}
		switch key {
		case keyUp:
			model.up()
		case keyDown:
			model.down()
		case keyEnter:
			if len(model.statuses) == 0 {
				return "", true, nil
			}
			return model.statuses[model.cursor].Key, false, nil
		case keyQuit:
			return "", true, nil
		}
	}
}

// keyKind names the input events the TUI cares about. Anything else
// (mouse, function keys, unknown bytes) collapses to keyNone and the
// render loop ignores it.
type keyKind int

const (
	keyNone keyKind = iota
	keyUp
	keyDown
	keyEnter
	keyQuit
)

// readSingleKey reads one keystroke from in (which must already be in
// raw mode) and classifies it. Arrow keys arrive as 3-byte ANSI escape
// sequences; on local pty's all three bytes show up in a single Read,
// but VMIN=1 VTIME=0 (the POSIX raw-mode contract term.MakeRaw applies)
// means a Read returns as soon as one byte is available, so in
// principle a slow link could split the sequence one byte at a time.
// When we see a lone ESC we keep polling+reading via waitForMoreInput
// until either the buffer holds a complete known sequence or a short
// deadline expires — without that an arrow on a high-latency link
// would mis-fire as quit, or worse, hang half-classified at n=2.
// Ctrl-C and EOF also collapse to quit so the caller can exit cleanly
// without a special path.
func readSingleKey(in *os.File) (keyKind, error) {
	buf := make([]byte, 16)
	n, err := in.Read(buf)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return keyQuit, nil
		}
		return keyNone, err
	}
	if n == 0 {
		return keyNone, nil
	}
	if n >= 1 && buf[0] == 0x1b {
		n = drainEscapeTail(in, buf, n, 50*time.Millisecond)
	}
	b := buf[:n]
	switch {
	case n >= 3 && b[0] == 0x1b && b[1] == '[' && b[2] == 'A':
		return keyUp, nil
	case n >= 3 && b[0] == 0x1b && b[1] == '[' && b[2] == 'B':
		return keyDown, nil
	case b[0] == 0x1b && (n == 1 || b[1] != '['):
		// Bare ESC, or ESC followed by a non-CSI byte (the user
		// pressed Esc and then another key within the peek window).
		// Treat as quit. A truncated CSI sequence (ESC '[' with no
		// final byte) deliberately falls through to keyNone — the
		// drain loop already waited the full deadline, so reaching
		// this point means the rest is genuinely never coming and
		// surprising the user with a quit would be worse than a
		// silent no-op they can re-try.
		return keyQuit, nil
	case n == 1 && (b[0] == '\r' || b[0] == '\n'):
		return keyEnter, nil
	case n == 1 && (b[0] == 'q' || b[0] == 'Q'):
		return keyQuit, nil
	case n == 1 && b[0] == 0x03:
		// Ctrl-C: term.MakeRaw disables ISIG on POSIX (and
		// ENABLE_PROCESSED_INPUT on Windows), so Ctrl-C arrives
		// as the literal byte 0x03 rather than firing the parent
		// ctx's SIGINT handler. Translate it to quit so the
		// picker exits cleanly without the user having to type q.
		return keyQuit, nil
	}
	return keyNone, nil
}

// drainEscapeTail keeps polling and reading from in until either buf
// holds a complete recognised ANSI escape sequence (ESC '[' followed
// by a final byte) or the cumulative wait exceeds timeout, then
// returns the new byte count. Called after readSingleKey sees an ESC
// byte at the start of buf.
//
// The loop matters because POSIX raw mode (VMIN=1 VTIME=0) lets a
// single Read return the moment one byte is in the buffer, so on a
// slow link the three bytes of an arrow sequence can arrive in three
// separate reads (ESC, then '[', then 'A'/'B'). A one-shot peek isn't
// enough — we need to keep collecting until we have a classifiable
// sequence or we time out.
//
// We stop early when:
//   - the buffer fills (defensive, never expected in practice);
//   - we already have at least 3 bytes (the recognised arrow length);
//   - the second byte isn't '[' (the sequence isn't a CSI escape, so
//     waiting for more bytes won't help — the input is Esc-then-
//     something the caller will treat as quit).
func drainEscapeTail(in *os.File, buf []byte, have int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for have < 3 && have < len(buf) {
		if have >= 2 && buf[1] != '[' {
			break
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		if !waitForMoreInput(in.Fd(), remaining) {
			break
		}
		m, rerr := in.Read(buf[have:])
		if rerr != nil || m == 0 {
			break
		}
		have += m
	}
	return have
}
