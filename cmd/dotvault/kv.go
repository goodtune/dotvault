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
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/term"

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

// kvBackend is the KV access seam the `kv` subcommands drive. Every path is
// relative to the user's own root (kv/{user_prefix}{username}/), so — exactly
// as for the FUSE mount's vaultfs.Store — the backend, not the command, owns
// the mount and prefix, and no argument a user types can name a path outside
// their own subtree.
type kvBackend interface {
	List(ctx context.Context, rel string) ([]string, error)
	Read(ctx context.Context, rel string) (*vault.Secret, error)
	Write(ctx context.Context, rel string, data map[string]any) error
	WriteCAS(ctx context.Context, rel string, data map[string]any, cas int) error
	Delete(ctx context.Context, rel string) error
}

// vaultKV adapts a Vault client to kvBackend, binding the mount and the
// user's root.
type vaultKV struct {
	vc    *vault.Client
	mount string
	root  string // "users/<name>/", always slash-terminated
}

func (k *vaultKV) path(rel string) string { return k.root + rel }

func (k *vaultKV) List(ctx context.Context, rel string) ([]string, error) {
	return k.vc.ListKVv2(ctx, k.mount, k.path(rel))
}

func (k *vaultKV) Read(ctx context.Context, rel string) (*vault.Secret, error) {
	return k.vc.ReadKVv2(ctx, k.mount, k.path(rel))
}

func (k *vaultKV) Write(ctx context.Context, rel string, data map[string]any) error {
	return k.vc.WriteKVv2(ctx, k.mount, k.path(rel), data)
}

func (k *vaultKV) WriteCAS(ctx context.Context, rel string, data map[string]any, cas int) error {
	return k.vc.WriteKVv2CAS(ctx, k.mount, k.path(rel), data, cas)
}

func (k *vaultKV) Delete(ctx context.Context, rel string) error {
	return k.vc.DeleteKVv2(ctx, k.mount, k.path(rel))
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
	// The username becomes a path segment; one carrying a slash or ".."
	// would let the composed root name a subtree other than this user's.
	// Same check vaultfs.NewStore applies, for the same reason.
	if err := kvpath.ValidateName(username); err != nil {
		return nil, fmt.Errorf("invalid username %q: %w", username, err)
	}
	vc, err := cachedVaultClient(ctx, cfg, username)
	if err != nil {
		return nil, err
	}
	return &kvSession{
		kv: &vaultKV{
			vc:    vc,
			mount: cfg.Vault.KVMount,
			root:  vaultfs.UserRoot(cfg.Vault.UserPrefix, username),
		},
		cfg: cfg,
	}, nil
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
	cmd.AddCommand(newKVListCmd(), newKVGetCmd(), newKVPutCmd(), newKVPatchCmd(), newKVDeleteCmd())
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
filesystem mount serves for that secret.`,
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

const kvDataHelp = `Fields are given as key=value pairs. A value of the form @file reads the
file's contents, and - reads stdin; both are taken verbatim, trailing newline
included. Prefer either for anything sensitive — a value typed on the command
line is visible to other local processes in the process listing and lands in
your shell history:

  printf %s "$TOKEN" | dotvault kv put personal/api token=-

A lone - instead of key=value pairs reads a whole JSON object from stdin.`

func newKVPutCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "put <path> <key=value>... | put <path> -",
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
enrolment flow will prompt for it.`,
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
	clean, err := kvpath.Clean(p)
	if err != nil {
		return "", fmt.Errorf("invalid path %q: %w", p, err)
	}
	if clean == "" {
		return "", errors.New("a secret path is required (the root of your key space is a folder)")
	}
	return clean, nil
}

// guardManaged refuses a write to a path an enrolment owns. Sync rules'
// sources are deliberately not protected — a rule reading a secret the user
// edits is the point — where an enrolment engine overwriting the edit at its
// next refresh is a silent loss. The same split the web UI's edit policy draws.
func guardManaged(cfg *config.Config, rel string, force bool) error {
	if force || cfg == nil {
		return nil
	}
	if _, ok := cfg.Enrolments[rel]; ok {
		return fmt.Errorf("%q is managed by an enrolment, which would overwrite the change; pass --force to write it anyway", rel)
	}
	return nil
}

func kvList(ctx context.Context, s *kvSession, w io.Writer, folder, format string) error {
	if err := checkFormat(format); err != nil {
		return err
	}
	rel, err := kvpath.Clean(folder)
	if err != nil {
		return fmt.Errorf("invalid path %q: %w", folder, err)
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
		fmt.Fprintln(w, k)
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
		fmt.Fprintf(tw, "%s\t%s\n", k, v)
	}
	return tw.Flush()
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
	for _, k := range remove {
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
			val = string(b)
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
