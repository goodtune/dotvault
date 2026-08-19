package vaultfs

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

// Kind distinguishes the two things a name in the mount can be.
type Kind int

const (
	// KindNone means the name does not exist.
	KindNone Kind = iota
	// KindDir is a KV folder.
	KindDir
	// KindFile is a secret, readable as a JSON document.
	KindFile
)

func (k Kind) String() string {
	switch k {
	case KindDir:
		return "dir"
	case KindFile:
		return "file"
	default:
		return "none"
	}
}

// FileExtension is appended to every secret's filename. A secret at
// kv/users/gary/gh is ~/.dotvault/gh.json, not ~/.dotvault/gh.
//
// The contents are JSON, so the extension is simply true — and it is what
// makes editors, IDEs and `vim` syntax-highlight, fold and lint the file
// instead of treating it as unknown plain text. It also removes the
// secret-versus-folder collision that a bare name creates: a secret named
// `databricks` and a folder named `databricks` are `databricks.json` and
// `databricks`, two distinct filenames, so both stay reachable.
//
// Directories carry no extension: a KV folder is not a JSON document.
const FileExtension = ".json"

// fileDisplayName is the filename a secret appears under.
func fileDisplayName(kvName string) string { return kvName + FileExtension }

// secretKVName maps a filename back to the KV key it names. ok is false when
// the name is not a secret filename at all — a directory, or a bare name with
// no extension, neither of which can address a secret.
//
// Exactly one extension is stripped, so the mapping is a bijection: a secret
// genuinely named "config.json" in Vault appears as "config.json.json" and
// reads back as "config.json".
func secretKVName(display string) (string, bool) {
	stem, ok := strings.CutSuffix(display, FileExtension)
	if !ok || stem == "" {
		return "", false
	}
	return stem, true
}

// kvPathForFile converts a mount-relative path naming a secret into the KV
// path it addresses: only the final segment carries the extension, since
// every segment before it is a directory.
//
// The leaf having no extension is ErrInvalidName rather than "not found":
// callers that mutate (Put, Remove, Create) must refuse a bare name outright,
// so a file created as `newthing` cannot appear as `newthing.json` on the
// next listing — a file that renames itself the moment you look away.
func kvPathForFile(displayPath string) (string, error) {
	p, err := cleanPath(displayPath)
	if err != nil {
		return "", err
	}
	if p == "" {
		return "", ErrInvalidName
	}
	dir, leaf := parentPath(p), leafName(p)
	stem, ok := secretKVName(leaf)
	if !ok {
		return "", ErrInvalidName
	}
	return joinPath(dir, stem), nil
}

// Entry is one child of a directory. Name is the filename as it appears in
// the mount — a secret's name therefore carries FileExtension.
type Entry struct {
	Name string
	Kind Kind
}

// Tree is the filesystem's view of the user's KV subtree: name resolution,
// document rendering, caching, and the read-only guard. It holds no FUSE
// types, so the whole of the filesystem's behaviour can be tested — on any
// platform — by driving a Tree over an in-memory Store.
type Tree struct {
	store Store
	cache *cache

	// readWrite gates every mutating method. The mount is also asked to mount
	// read-only when this is false, but the check lives here as well so the
	// guarantee does not depend on the kernel honouring a mount flag.
	readWrite bool

	// warned records the collision paths already logged, so a directory that
	// shadows a secret produces one warning rather than one per readdir.
	warned sync.Map
}

// NewTree builds a tree over store. A cacheTTL of zero disables caching.
func NewTree(store Store, readWrite bool, cacheTTL time.Duration) *Tree {
	return &Tree{
		store:     store,
		cache:     newCache(cacheTTL),
		readWrite: readWrite,
	}
}

// ReadWrite reports whether mutating operations are permitted.
func (t *Tree) ReadWrite() bool { return t.readWrite }

// InvalidateAll drops every cached listing and document.
func (t *Tree) InvalidateAll() { t.cache.invalidateAll() }

// Readdir returns the children of dir ("" is the mount root).
//
// Entries are returned sorted by name so readdir output is stable between
// calls; Vault's LIST is already sorted, but the collision fold below can
// reorder, and a filesystem that reorders its own directory between two `ls`
// invocations is needlessly surprising.
func (t *Tree) Readdir(ctx context.Context, dir string) ([]Entry, error) {
	dir, err := cleanPath(dir)
	if err != nil {
		return nil, err
	}
	if cached, ok := t.cache.lookupDir(dir); ok {
		return cached, nil
	}

	raw, err := t.store.List(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("list %q: %w", displayPath(dir), err)
	}

	byName := make(map[string]Kind, len(raw))
	for _, name := range raw {
		kind := KindFile
		if strings.HasSuffix(name, "/") {
			kind = KindDir
			name = strings.TrimSuffix(name, "/")
		}
		// Vault should not return a name a KV path cannot carry, but the
		// listing is server-supplied: a name with an embedded slash or an
		// empty segment would otherwise become a path component the mount
		// cannot address, so drop it rather than surface a broken entry.
		if err := validateName(name); err != nil {
			slog.Warn("vaultfs: skipping unusable name in Vault listing", "path", displayPath(dir))
			continue
		}
		if kind == KindFile {
			name = fileDisplayName(name)
		}
		// The fold is in filename space, not KV space, which is why the
		// extension shrinks the problem rather than merely moving it: a
		// secret and a folder sharing a KV name now produce two different
		// filenames and both stay reachable. What remains is the narrow
		// case of a folder whose name already ends in the extension,
		// colliding with the secret of the same stem.
		if prev, dup := byName[name]; dup && prev != kind {
			t.warnCollision(joinPath(dir, name))
			kind = KindDir
		}
		byName[name] = kind
	}

	entries := make([]Entry, 0, len(byName))
	for name, kind := range byName {
		entries = append(entries, Entry{Name: name, Kind: kind})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	t.cache.storeDir(dir, entries)
	return entries, nil
}

// warnCollision logs a secret/folder collision once per path per process.
func (t *Tree) warnCollision(path string) {
	if _, seen := t.warned.LoadOrStore(path, struct{}{}); seen {
		return
	}
	slog.Warn("vaultfs: a folder and a secret claim the same filename; the folder is shown and the secret is not reachable through the mount",
		"path", displayPath(path),
		"cause", "a KV folder whose name ends in "+FileExtension+" collides with the secret of the same stem")
}

// Lookup resolves one name within dir.
//
// The parent's listing is authoritative when it can be obtained: a successful
// LIST that does not mention the name means the name does not exist, and
// answering from it costs no extra Vault call. When the LIST fails — most
// plausibly a policy that grants read on a known path but not list on its
// parent — the lookup degrades to reading the path directly, so a caller who
// knows the name can still open the file even though `ls` shows nothing.
func (t *Tree) Lookup(ctx context.Context, dir, name string) (Kind, error) {
	if err := validateName(name); err != nil {
		return KindNone, err
	}
	entries, listErr := t.Readdir(ctx, dir)
	if listErr == nil {
		for _, e := range entries {
			if e.Name == name {
				return e.Kind, nil
			}
		}
		return KindNone, nil
	}

	doc, err := t.Document(ctx, joinPath(dir, name))
	if err != nil {
		// Report the listing failure, not the read's: the read was only a
		// fallback, and the listing is the operation that was supposed to
		// answer this. Wrapping both would make the common permission case
		// read as two unrelated failures.
		return KindNone, listErr
	}
	if doc == nil {
		return KindNone, nil
	}
	return KindFile, nil
}

// Document returns the rendered secret at path, or (nil, nil) when no secret
// exists there.
func (t *Tree) Document(ctx context.Context, path string) (*Document, error) {
	path, err := cleanPath(path)
	if err != nil {
		return nil, err
	}
	if path == "" {
		// The root is a directory, never a document.
		return nil, nil
	}
	// A path whose leaf carries no extension cannot name a secret. That is
	// "nothing here" rather than an error: the speculative lookups a
	// filesystem fields land here constantly, and Lookup's fallback asks
	// about directory names too.
	kvPath, err := kvPathForFile(path)
	if err != nil {
		return nil, nil
	}
	if doc, ok := t.cache.lookupDoc(kvPath); ok {
		return doc, nil
	}

	secret, err := t.store.Read(ctx, kvPath)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", displayPath(path), err)
	}
	if secret == nil {
		t.cache.storeDoc(kvPath, nil)
		return nil, nil
	}

	doc, err := renderDocument(secret)
	if err != nil {
		return nil, err
	}
	t.cache.storeDoc(kvPath, doc)
	return doc, nil
}

// Put parses content as a JSON object and writes it to the secret at path,
// creating it if absent.
func (t *Tree) Put(ctx context.Context, path string, content []byte) error {
	if !t.readWrite {
		return ErrReadOnly
	}
	kvPath, err := kvPathForFile(path)
	if err != nil {
		return err
	}
	data, err := parseDocument(content)
	if err != nil {
		return err
	}
	if err := t.store.Write(ctx, kvPath, data); err != nil {
		// The error comes from the Vault client, which formats paths but
		// never secret values, so it is safe to wrap as-is.
		return fmt.Errorf("write %q: %w", displayPath(kvPath), err)
	}
	t.cache.invalidate(kvPath)
	return nil
}

// Remove deletes the secret at path, including every version of it. There is
// no soft-delete equivalent in the filesystem model — unlink means gone — so
// this is the destructive one, which is why it is reachable only in
// read-write mode.
func (t *Tree) Remove(ctx context.Context, path string) error {
	if !t.readWrite {
		return ErrReadOnly
	}
	kvPath, err := kvPathForFile(path)
	if err != nil {
		return err
	}
	if err := t.store.Delete(ctx, kvPath); err != nil {
		return fmt.Errorf("delete %q: %w", displayPath(kvPath), err)
	}
	t.cache.invalidate(kvPath)
	return nil
}

// cleanPath validates a slash-separated relative path and returns it in
// canonical form (no leading or trailing slash, no empty segments).
//
// It deliberately does not use path.Clean: Vault treats logical path segments
// literally and does not collapse "..", so cleaning a path here would let
// "a/../b" resolve to a different Vault path than the one the caller named.
// Anything that is not already canonical is rejected instead.
func cleanPath(p string) (string, error) {
	p = strings.Trim(p, "/")
	if p == "" {
		return "", nil
	}
	for _, seg := range strings.Split(p, "/") {
		if err := validateName(seg); err != nil {
			return "", err
		}
	}
	return p, nil
}

// validateName checks a single path component.
func validateName(name string) error {
	if name == "" || name == "." || name == ".." {
		return ErrInvalidName
	}
	if strings.ContainsAny(name, "/\x00") {
		return ErrInvalidName
	}
	return nil
}

func joinPath(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

// leafName returns the final segment of a path.
func leafName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func parentPath(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return ""
}

// displayPath renders a path for a log line or an error. The root is shown as
// "/" rather than as an empty string. Path *names* are not secret — they are
// visible in any directory listing — but values are, and nothing in this
// package puts a value in a message.
func displayPath(p string) string {
	if p == "" {
		return "/"
	}
	return "/" + p
}
