package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"unicode"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/goodtune/dotvault/internal/clipboard"
	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/kvpath"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/vault"
	"github.com/goodtune/dotvault/internal/vaultfs"
)

// kvMaxInput caps what a value read from a file or stdin may weigh. It is the
// same ceiling the FUSE mount applies to a document (vaultfs's
// maxDocumentSize): a secret is small, and an unbounded read of a mistyped
// path (`token=@/dev/zero`) should fail rather than exhaust memory.
const kvMaxInput = 1 << 20

// kvCASAttempts bounds how often `kv patch` re-reads and retries after losing
// a check-and-set race. A patch names fields rather than a whole document, so
// re-applying it to whatever the other writer left is still what the user
// asked for — unlike `put`, where it would silently discard their write.
const kvCASAttempts = 3

// kvBackend is the KV access seam the `kv` subcommands drive: the FUSE
// mount's vaultfs.Store plus its check-and-set write. Reusing the store rather
// than a second adapter keeps "the store, not the command, binds the mount and
// the user's prefix" a single implementation — every path is relative to
// kv/{user_prefix}{username}/, so no argument a user types can name a path
// outside their own subtree.
type kvBackend interface {
	vaultfs.Store
	vaultfs.CASWriter
}

// kvSession is what every `kv` subcommand starts from: the backend and the
// loaded config (for the enrolment-managed guard).
type kvSession struct {
	kv  kvBackend
	cfg *config.Config
}

// openKVSession loads the config and authenticates with a cached token. It is
// a var so tests can substitute an in-memory backend without a Vault.
var openKVSession = func(ctx context.Context) (*kvSession, error) {
	cfg, _, err := loadConfig()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	username, err := paths.Username()
	if err != nil {
		return nil, fmt.Errorf("resolve username: %w", err)
	}
	vc, err := cachedVaultClient(ctx, cfg, username)
	if err != nil {
		return nil, err
	}
	// NewStore validates the username and prefix it composes the root from.
	store, err := vaultfs.NewStore(vc, cfg.Vault.KVMount, cfg.Vault.UserPrefix, username)
	if err != nil {
		return nil, err
	}
	kv, ok := store.(kvBackend)
	if !ok {
		return nil, errors.New("internal error: vault store does not support check-and-set writes")
	}
	return &kvSession{kv: kv, cfg: cfg}, nil
}

// newKVCmd defines `dotvault kv`: a deliberately narrow counterpart of
// `vault kv`. The mount, the user prefix and the address all come from the
// loaded configuration, so there are no switches for them — every path is
// relative to the user's own key space, the same tree the FUSE mount and the
// web UI's secret browser show.
func newKVCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kv",
		Short: "Read and write secrets in your own Vault key space",
		Long: `Read and write the KVv2 secrets in your own key space,
{kv_mount}/{user_prefix}{username}/ — the same tree dotvault syncs from and the
web UI and filesystem mount show.

Unlike "vault kv", there are no switches for the address, mount or path
prefix: they come from dotvault's configuration, and every path is relative to
your own key space. "dotvault kv get gh" reads kv/users/<you>/gh.

A valid cached Vault token is required (the token file, DOTVAULT_TOKEN, or one
borrowed from this host's daemon or a peer socket); these commands never start
an interactive login. Run "dotvault login" first if needed.`,
	}
	cmd.AddCommand(newKVListCmd(), newKVGetCmd(), newKVClipboardCmd(), newKVPutCmd(), newKVPatchCmd(), newKVDeleteCmd())
	return cmd
}

func newKVListCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:     "list [folder]",
		Aliases: []string{"ls"},
		Short:   "List the secrets and folders in a folder",
		Long: `List the entries directly inside a folder of your key space (the root when
omitted). Folders carry a trailing slash, as in "vault kv list".`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rel := ""
			if len(args) == 1 {
				rel = args[0]
			}
			return withKV(cmd, func(ctx context.Context, s *kvSession) error {
				return kvList(ctx, s, cmd.OutOrStdout(), rel, format)
			})
		},
	}
	cmd.Flags().StringVar(&format, "format", "table", "output format: table or json")
	return cmd
}

func newKVGetCmd() *cobra.Command {
	var format, field string
	cmd := &cobra.Command{
		Use:   "get <path>",
		Short: "Print a secret",
		Long: `Print the fields of the secret at <path>.

--field prints one field's value alone, byte for byte (a trailing newline is
added only when stdout is a terminal), so it can feed a file or a command
substitution:

  dotvault kv get --field private_key ssh > key

--format json prints the secret's data as a JSON object — the same bytes the
filesystem mount serves for that secret.

Without --field, every value is printed in plain text, as "vault kv get" does,
with control characters (line breaks included) shown escaped so a multi-line
value stays on its row and a stored value cannot drive the terminal. Use "dotvault kv clipboard" to copy a
value without displaying it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withKV(cmd, func(ctx context.Context, s *kvSession) error {
				return kvGet(ctx, s, cmd.OutOrStdout(), args[0], field, format, isTerminal(cmd.OutOrStdout()))
			})
		},
	}
	cmd.Flags().StringVar(&field, "field", "", "print only this field's value")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table or json")
	return cmd
}

// kvDeliverClipboard is the clipboard sink `kv clipboard` hands a value to.
// Indirected so tests can capture the value without a peer or a real
// clipboard.
var kvDeliverClipboard = deliverClipboard

func newKVClipboardCmd() *cobra.Command {
	var field string
	cmd := &cobra.Command{
		Use:     "clipboard <path>",
		Aliases: []string{"clip", "copy"},
		Short:   "Put one field of a secret on the clipboard, as dotvault clipboard does",
		Long: `Put one field of the secret at <path> on the clipboard — shorthand for

  dotvault kv get --field <name> <path> | dotvault clipboard

without the value passing through a pipe or your terminal. It is delivered
exactly as "dotvault clipboard" delivers text: to the clipboard of every
workstation forwarding a live vault.token_socket peer socket here, and only
when none accepts it, to this host's clipboard. As there, a single trailing
newline is dropped.

--field names the field; it may be omitted when the secret has exactly one.
Nothing is printed on success, and the value is never written to stdout.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withKV(cmd, func(ctx context.Context, s *kvSession) error {
				return kvClipboard(ctx, s, args[0], field)
			})
		},
	}
	cmd.Flags().StringVar(&field, "field", "", "the field to copy (optional when the secret has only one)")
	return cmd
}

const kvDataHelp = `Fields are given as key=value pairs. A value of the form @file reads the
file's contents verbatim (use it for a key or certificate whose final newline
matters), and - reads stdin with one trailing newline dropped. Prefer either
for anything sensitive — a value typed on the command line is visible to
other local processes in the process listing and lands in your shell history:

  echo "$TOKEN" | dotvault kv patch personal/api token=-
  dotvault kv put ssh/deploy private_key=@id_ed25519 public_key=@id_ed25519.pub

A lone - instead of key=value pairs reads a whole JSON object from stdin; it is
also the way to store a value that itself begins with @ or is exactly -.

The global --dry-run reports what would be written without writing it.`

func newKVPutCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "put <path> (<key=value>... | -)",
		Short: "Write a secret, replacing every field it had",
		Long: `Write the secret at <path>, creating it if absent. Like "vault kv put", the
fields given REPLACE the secret's whole contents; any field not named is
removed. Use "dotvault kv patch" to change some fields and keep the rest.

` + kvDataHelp + `

A path configured as an enrolment is refused unless --force is given: the
enrolment engine owns that secret and would overwrite the change.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := parseKVData(args[1:], cmd.InOrStdin())
			if err != nil {
				return err
			}
			return withKV(cmd, func(ctx context.Context, s *kvSession) error {
				return kvPut(ctx, s, cmd.ErrOrStderr(), args[0], data, force, flagDryRun)
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "write even if the path is managed by an enrolment")
	return cmd
}

func newKVPatchCmd() *cobra.Command {
	var force bool
	var remove []string
	cmd := &cobra.Command{
		Use:   "patch <path> [key=value]...",
		Short: "Change some fields of an existing secret, keeping the rest",
		Long: `Merge fields into the existing secret at <path>: the fields given are added or
replaced, --remove deletes a field, and every other field is kept as it was.
The secret must already exist; use "dotvault kv put" to create one.

The write is a check-and-set against the version that was read, so a
concurrent change by another writer is never silently overwritten; the patch
is re-applied to the newer version instead.

` + kvDataHelp + `

A path configured as an enrolment is refused unless --force is given.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var data map[string]any
			if len(args) > 1 {
				var err error
				if data, err = parseKVData(args[1:], cmd.InOrStdin()); err != nil {
					return err
				}
			}
			if len(data) == 0 && len(remove) == 0 {
				return errors.New("nothing to patch: give key=value pairs or --remove")
			}
			return withKV(cmd, func(ctx context.Context, s *kvSession) error {
				return kvPatch(ctx, s, cmd.ErrOrStderr(), args[0], data, remove, force, flagDryRun)
			})
		},
	}
	cmd.Flags().StringArrayVar(&remove, "remove", nil, "delete this field (repeatable)")
	cmd.Flags().BoolVar(&force, "force", false, "write even if the path is managed by an enrolment")
	return cmd
}

func newKVDeleteCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:     "delete <path>",
		Aliases: []string{"rm"},
		Short:   "Delete a secret and all of its versions",
		Long: `Delete the secret at <path> together with every version of it (its metadata,
not just the latest version) — the same delete the web UI performs.

A path configured as an enrolment is refused unless --force is given. Deleting
an enrolment's secret is how to start that enrolment again from scratch; the
enrolment flow will prompt for it.

The global --dry-run reports what would be deleted without deleting it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withKV(cmd, func(ctx context.Context, s *kvSession) error {
				return kvDelete(ctx, s, cmd.ErrOrStderr(), args[0], force, flagDryRun)
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "delete even if the path is managed by an enrolment")
	return cmd
}

// withKV runs fn with an authenticated session under a signal-cancelled
// context. A cached-auth failure is printed as the whole explanation and exits
// non-zero, matching `dotvault enrol`.
func withKV(cmd *cobra.Command, fn func(context.Context, *kvSession) error) error {
	setupLogging()
	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	s, err := openKVSession(ctx)
	if err != nil {
		if errors.Is(err, errCachedAuth) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return err
	}
	return fn(ctx, s)
}

// cleanSecretPath validates a secret path. Unlike a folder, a secret cannot
// be the root of the key space.
func cleanSecretPath(p string) (string, error) {
	// A trailing slash names a folder: kvpath.Clean would trim it and quietly
	// address a same-named secret beside the folder instead.
	if strings.HasSuffix(p, "/") {
		return "", fmt.Errorf("%q names a folder, not a secret", p)
	}
	clean, err := cleanKVArg(p)
	if err != nil {
		return "", err
	}
	if clean == "" {
		return "", errors.New("a secret path is required (the root of your key space is a folder)")
	}
	return clean, nil
}

// cleanKVArg validates a path argument. A backslash is refused rather than
// stored: Vault would take it as part of a name, so `databricks\prod` typed on
// Windows would create an oddly named secret at the root instead of reaching
// databricks/prod, and nothing else in dotvault can carry such a name (the
// enrolment-key grammar forbids it too).
func cleanKVArg(p string) (string, error) {
	if strings.Contains(p, "\\") {
		return "", fmt.Errorf("invalid path %q: use / to separate folders", p)
	}
	clean, err := kvpath.Clean(p)
	if err != nil {
		return "", fmt.Errorf("invalid path %q: %w", p, err)
	}
	return clean, nil
}

// guardManaged refuses a write to a path an enrolment owns. Sync rules'
// sources are deliberately not protected — a rule reading a secret the user
// edits is the point — where an enrolment engine overwriting the edit at its
// next refresh is a silent loss. The definition of "managed" is the web UI's
// (kvpath.EditPolicy), so the two surfaces cannot disagree about it.
func guardManaged(cfg *config.Config, rel string, force bool) error {
	if force || cfg == nil {
		return nil
	}
	keys := make([]string, 0, len(cfg.Enrolments))
	for k := range cfg.Enrolments {
		keys = append(keys, k)
	}
	if kvpath.NewEditPolicy(nil, keys).Managed(rel) {
		return fmt.Errorf("%q is managed by an enrolment, which would overwrite the change; pass --force to write it anyway", rel)
	}
	return nil
}

func kvList(ctx context.Context, s *kvSession, w io.Writer, folder, format string) error {
	if err := checkFormat(format); err != nil {
		return err
	}
	rel, err := cleanKVArg(folder)
	if err != nil {
		return err
	}
	keys, err := s.kv.List(ctx, rel)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("no secrets found under %q", displayRel(rel))
	}
	sort.Strings(keys)
	if format == "json" {
		return writeJSON(w, keys)
	}
	for _, k := range keys {
		fmt.Fprintln(w, escapeControls(k))
	}
	return nil
}

func kvGet(ctx context.Context, s *kvSession, w io.Writer, p, field, format string, tty bool) error {
	if err := checkFormat(format); err != nil {
		return err
	}
	rel, err := cleanSecretPath(p)
	if err != nil {
		return err
	}
	sec, err := s.kv.Read(ctx, rel)
	if err != nil {
		return err
	}
	if sec == nil {
		return fmt.Errorf("no secret at %q", rel)
	}
	if field != "" {
		if format == "json" {
			return errors.New("--field and --format json are mutually exclusive")
		}
		v, ok := sec.Data[field]
		if !ok {
			return fmt.Errorf("secret %q has no field %q", rel, field)
		}
		out, err := fieldText(v)
		if err != nil {
			return err
		}
		if tty && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		_, err = io.WriteString(w, out)
		return err
	}
	if format == "json" {
		doc, err := vaultfs.RenderDocument(&vaultfs.Secret{Data: sec.Data})
		if err != nil {
			return err
		}
		_, err = w.Write(doc.Bytes)
		return err
	}
	keys := make([]string, 0, len(sec.Data))
	for k := range sec.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tw := tabwriter.NewWriter(w, 0, 4, 4, ' ', 0)
	fmt.Fprintln(tw, "Key\tValue")
	fmt.Fprintln(tw, "---\t-----")
	for _, k := range keys {
		v, err := fieldText(sec.Data[k])
		if err != nil {
			return err
		}
		fmt.Fprintf(tw, "%s\t%s\n", escapeControls(k), escapeControls(v))
	}
	return tw.Flush()
}

func kvClipboard(ctx context.Context, s *kvSession, p, field string) error {
	rel, err := cleanSecretPath(p)
	if err != nil {
		return err
	}
	sec, err := s.kv.Read(ctx, rel)
	if err != nil {
		return err
	}
	if sec == nil {
		return fmt.Errorf("no secret at %q", rel)
	}
	if field == "" {
		if len(sec.Data) != 1 {
			keys := make([]string, 0, len(sec.Data))
			for k := range sec.Data {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			return fmt.Errorf("secret %q has %s; choose one with --field (%s)", rel, fieldCount(len(keys)), strings.Join(keys, ", "))
		}
		for k := range sec.Data {
			field = k
		}
	}
	v, ok := sec.Data[field]
	if !ok {
		return fmt.Errorf("secret %q has no field %q", rel, field)
	}
	text, err := fieldText(v)
	if err != nil {
		return err
	}
	// Exactly what `kv get --field … | dotvault clipboard` would deliver:
	// that pipeline drops one trailing newline (see clipboardText), so this
	// does too, and a PEM value pastes the same either way.
	text = trimOneNewline(text)
	// Errors from ValidateText are content-free by contract.
	if err := clipboard.ValidateText(text); err != nil {
		return fmt.Errorf("field %q cannot go on the clipboard: %w", field, err)
	}
	return kvDeliverClipboard(ctx, s.cfg, text)
}

func kvPut(ctx context.Context, s *kvSession, w io.Writer, p string, data map[string]any, force, dryRun bool) error {
	rel, err := cleanSecretPath(p)
	if err != nil {
		return err
	}
	if err := guardManaged(s.cfg, rel, force); err != nil {
		return err
	}
	if dryRun {
		fmt.Fprintf(w, "dotvault: would write %s to %s (dry run)\n", fieldCount(len(data)), rel)
		return nil
	}
	if err := s.kv.Write(ctx, rel, data); err != nil {
		return err
	}
	fmt.Fprintf(w, "dotvault: wrote %s to %s\n", fieldCount(len(data)), rel)
	return nil
}

func kvPatch(ctx context.Context, s *kvSession, w io.Writer, p string, set map[string]any, remove []string, force, dryRun bool) error {
	rel, err := cleanSecretPath(p)
	if err != nil {
		return err
	}
	if err := guardManaged(s.cfg, rel, force); err != nil {
		return err
	}
	removing := make(map[string]bool, len(remove))
	for _, k := range remove {
		if removing[k] {
			return fmt.Errorf("field %q given to --remove more than once", k)
		}
		removing[k] = true
		if _, ok := set[k]; ok {
			return fmt.Errorf("field %q is both set and removed", k)
		}
	}
	for attempt := 1; ; attempt++ {
		sec, err := s.kv.Read(ctx, rel)
		if err != nil {
			return err
		}
		if sec == nil {
			return fmt.Errorf("no secret at %q; use `dotvault kv put` to create it", rel)
		}
		merged := make(map[string]any, len(sec.Data)+len(set))
		for k, v := range sec.Data {
			merged[k] = v
		}
		for k, v := range set {
			merged[k] = v
		}
		for _, k := range remove {
			if _, ok := merged[k]; !ok {
				return fmt.Errorf("secret %q has no field %q to remove", rel, k)
			}
			delete(merged, k)
		}
		if len(merged) == 0 {
			// KVv2 stores no fieldless secret; removing the last field is a
			// delete, which is its own deliberate gesture.
			return fmt.Errorf("removing every field would leave %q empty; use `dotvault kv delete` instead", rel)
		}
		if dryRun {
			fmt.Fprintf(w, "dotvault: would patch %s (%s set, %s removed; dry run)\n", rel, fieldCount(len(set)), fieldCount(len(remove)))
			return nil
		}
		err = s.kv.WriteCAS(ctx, rel, merged, sec.Version)
		if err == nil {
			fmt.Fprintf(w, "dotvault: patched %s (%s set, %s removed)\n", rel, fieldCount(len(set)), fieldCount(len(remove)))
			return nil
		}
		if !errors.Is(err, vault.ErrCASMismatch) || attempt >= kvCASAttempts {
			return err
		}
	}
}

func kvDelete(ctx context.Context, s *kvSession, w io.Writer, p string, force, dryRun bool) error {
	rel, err := cleanSecretPath(p)
	if err != nil {
		return err
	}
	if err := guardManaged(s.cfg, rel, force); err != nil {
		return err
	}
	// Read first: DeleteKVv2 is a no-op on an absent path, and a typo — or a
	// folder name — reported as a successful delete would be a lie.
	sec, err := s.kv.Read(ctx, rel)
	if err != nil {
		return err
	}
	if sec == nil {
		return fmt.Errorf("no secret at %q", rel)
	}
	if dryRun {
		fmt.Fprintf(w, "dotvault: would delete %s and all of its versions (dry run)\n", rel)
		return nil
	}
	if err := s.kv.Delete(ctx, rel); err != nil {
		return err
	}
	fmt.Fprintf(w, "dotvault: deleted %s and all of its versions\n", rel)
	return nil
}

// parseKVData turns the data arguments of put/patch into a field map. Errors
// name fields and files, never values: the values are credentials.
func parseKVData(args []string, stdin io.Reader) (map[string]any, error) {
	if len(args) == 1 && args[0] == "-" {
		b, err := readCapped(stdin, "stdin")
		if err != nil {
			return nil, err
		}
		// The same document grammar the filesystem mount accepts, so a secret
		// read with `get --format json` can be edited and written back.
		return vaultfs.ParseDocument(b)
	}
	data := make(map[string]any, len(args))
	usedStdin := false
	for i, arg := range args {
		key, val, ok := strings.Cut(arg, "=")
		if !ok || key == "" {
			if arg == "-" {
				return nil, errors.New("a lone - (a JSON object on stdin) cannot be combined with key=value pairs")
			}
			return nil, fmt.Errorf("argument %d is not of the form key=value", i+1)
		}
		if _, dup := data[key]; dup {
			return nil, fmt.Errorf("field %q given more than once", key)
		}
		switch {
		case val == "-":
			if usedStdin {
				return nil, errors.New("only one field can be read from stdin")
			}
			usedStdin = true
			b, err := readCapped(stdin, "stdin")
			if err != nil {
				return nil, err
			}
			// One trailing newline is dropped, as `dotvault clipboard` drops
			// it: it is the artefact of `echo` and of PowerShell's pipeline
			// (which appends CRLF), and storing it would corrupt a token.
			// @file stays verbatim — that is the way to store content whose
			// final newline matters, such as a PEM key.
			val = trimOneNewline(string(b))
		case strings.HasPrefix(val, "@"):
			name := val[1:]
			f, err := os.Open(name)
			if err != nil {
				return nil, fmt.Errorf("field %q: %w", key, err)
			}
			b, err := readCapped(f, name)
			f.Close()
			if err != nil {
				return nil, fmt.Errorf("field %q: %w", key, err)
			}
			val = string(b)
		}
		data[key] = val
	}
	return data, nil
}

// trimOneNewline drops exactly one trailing "\r\n" or "\n".
func trimOneNewline(s string) string {
	if strings.HasSuffix(s, "\r\n") {
		return s[:len(s)-2]
	}
	return strings.TrimSuffix(s, "\n")
}

func readCapped(r io.Reader, name string) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, kvMaxInput+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if len(b) > kvMaxInput {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, kvMaxInput)
	}
	return b, nil
}

// fieldText renders one field for output: a string verbatim, anything else
// as compact JSON (the shape it has in the secret).
func fieldText(v any) (string, error) {
	if s, ok := v.(string); ok {
		return s, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		// encoding/json can quote the offending value; don't.
		return "", errors.New("a field value cannot be rendered as JSON")
	}
	return string(b), nil
}

// escapeControls escapes control characters in the human-readable outputs
// (the get table, the list). A multi-line value — a PEM key — would otherwise
// break the table across rows, and key names and values can be written by
// other tooling (a copy enrolment's shared source, say): an ANSI or OSC
// sequence printed raw could retitle the terminal or write its clipboard.
// --field and --format json are exempt — they are for machines, and --field is
// the value byte for byte by contract.
func escapeControls(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return s
	}
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}

func writeJSON(w io.Writer, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func checkFormat(format string) error {
	switch format {
	case "table", "json":
		return nil
	}
	return fmt.Errorf("unknown --format %q (want table or json)", format)
}

func displayRel(rel string) string {
	if rel == "" {
		return "/"
	}
	return rel
}

func fieldCount(n int) string {
	if n == 1 {
		return "1 field"
	}
	return fmt.Sprintf("%d fields", n)
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}
