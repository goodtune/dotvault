package dockervol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/vaultfs"
)

// rendered is the desired on-disk state of one volume: every file with its
// contents, and every directory, as relative slash-separated paths.
type rendered struct {
	files   map[string]fileEntry
	dirs    map[string]bool
	secrets int
}

type fileEntry struct {
	data    []byte
	modTime time.Time
}

// render reads every secret the spec selects and lays it out in memory.
//
// A missing secret is not an error — a selection naming a secret that has
// not been enrolled yet simply renders nothing for it, and a later refresh
// picks it up — but a Vault failure is, because a refresh that silently
// rendered half a volume would then prune the other half from disk.
func render(ctx context.Context, store vaultfs.Store, spec Spec) (*rendered, error) {
	r := &rendered{files: map[string]fileEntry{}, dirs: map[string]bool{}}

	var walk func(dir string) error
	walk = func(dir string) error {
		names, err := store.List(ctx, dir)
		if err != nil {
			return fmt.Errorf("list %q: %w", displayPath(dir), err)
		}
		for _, name := range names {
			folder := strings.HasSuffix(name, "/")
			name = strings.TrimSuffix(name, "/")
			if !validComponent(name) {
				// The listing is server-supplied; a name a path cannot
				// carry becomes no file rather than a broken one.
				slog.Warn("dockervol: skipping unusable name in vault listing", "path", displayPath(dir))
				continue
			}
			child := joinRel(dir, name)
			if folder {
				if err := walk(child); err != nil {
					return err
				}
				continue
			}
			if err := r.emitPath(ctx, store, child, spec); err != nil {
				return err
			}
		}
		return nil
	}

	if len(spec.Secrets) == 0 {
		if err := walk(""); err != nil {
			return nil, err
		}
	}
	for _, sel := range spec.Secrets {
		if folder, ok := strings.CutSuffix(sel, "/"); ok {
			if err := walk(folder); err != nil {
				return nil, err
			}
			continue
		}
		if err := r.emitPath(ctx, store, sel, spec); err != nil {
			return nil, err
		}
	}

	// A directory and a file cannot share a name. The extension makes the
	// case rare in the JSON layout (only a KV folder itself named "x.json"
	// collides with the secret "x"); in the fields layout a field collides
	// with a same-named child secret of the same folder. The directory wins,
	// as it does in the mount, so the secrets beneath it stay reachable.
	for p := range r.files {
		if r.dirs[p] {
			warnCollision(p)
			delete(r.files, p)
		}
	}
	return r, nil
}

// collisionWarned records the paths already warned about, so a collision
// is logged once per process rather than on every refresh — the same
// once-per-path rule vaultfs.Tree applies.
var collisionWarned sync.Map

func warnCollision(p string) {
	if _, seen := collisionWarned.LoadOrStore(p, struct{}{}); seen {
		return
	}
	slog.Warn("dockervol: a directory and a file claim the same name; the file is not written",
		"path", displayPath(p))
}

// emitPath reads one secret and adds its rendering to r. A secret that does
// not exist adds nothing.
func (r *rendered) emitPath(ctx context.Context, store vaultfs.Store, kvPath string, spec Spec) error {
	secret, err := store.Read(ctx, kvPath)
	if err != nil {
		return fmt.Errorf("read %q: %w", displayPath(kvPath), err)
	}
	if secret == nil {
		return nil
	}
	r.secrets++
	switch spec.Layout {
	case LayoutFields:
		for field, value := range secret.Data {
			if !validComponent(field) {
				slog.Warn("dockervol: skipping a field whose name cannot be a filename", "path", displayPath(kvPath))
				continue
			}
			data, ok := fieldBytes(value)
			if !ok {
				slog.Warn("dockervol: skipping a field whose value cannot be rendered", "path", displayPath(kvPath))
				continue
			}
			r.addFile(joinRel(kvPath, field), fileEntry{data: data, modTime: secret.CreatedTime})
		}
		// A secret with no renderable field is still a directory, so its
		// presence is visible even when empty.
		r.addDir(kvPath)
	default:
		doc, err := vaultfs.RenderDocument(secret)
		if err != nil {
			return err
		}
		r.addFile(kvPath+vaultfs.FileExtension, fileEntry{data: doc.Bytes, modTime: doc.ModTime})
	}
	return nil
}

func (r *rendered) addFile(p string, e fileEntry) {
	r.files[p] = e
	r.addDir(parentRel(p))
}

func (r *rendered) addDir(d string) {
	for d != "" {
		if r.dirs[d] {
			return
		}
		r.dirs[d] = true
		d = parentRel(d)
	}
}

// fieldBytes renders one field's value for the fields layout: a string is
// written verbatim (a credential is bytes, and a trailing newline the caller
// did not put there is a classic source of "the password has a newline in
// it"); anything else is written as JSON.
func fieldBytes(v any) ([]byte, bool) {
	if s, ok := v.(string); ok {
		return []byte(s), true
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, false
	}
	return b, true
}

// apply makes dir look exactly like r: files are written atomically when
// their contents or mode differ, and anything present that r does not
// describe is removed. dir itself is never removed — a container may hold it
// bind-mounted, and its inode is the container's view of the volume.
//
// Every operation inside dir goes through an os.Root, and that is a security
// boundary rather than tidiness. Under a rootless engine container root *is*
// the uid that owns these files, and unless the volume was mounted read-only
// it can rearrange the directory between two refreshes — replace a
// subdirectory with a symlink to ~/.ssh, say. Plain os calls would follow
// that link: chmod the target to the volume's directory mode, or rename a
// freshly rendered secret into it. An os.Root refuses any path that
// resolves outside dir, so the worst such a container can do is disturb its
// own volume, which the next refresh repairs.
func apply(dir string, r *rendered, spec Spec) error {
	dirMode := spec.DirMode()
	if err := prepareVolumeDir(dir, dirMode); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()

	dirs := make([]string, 0, len(r.dirs))
	for d := range r.dirs {
		dirs = append(dirs, d)
	}
	// Parents before children: a shorter path can never be a descendant
	// of a longer one.
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) < len(dirs[j]) })
	for _, d := range dirs {
		if err := ensureDir(root, filepath.FromSlash(d), dirMode); err != nil {
			return err
		}
	}

	for p, e := range r.files {
		rel := filepath.FromSlash(p)
		if unchanged(root, rel, e.data, spec.Mode) {
			// Same bytes in a new KV version still carry a new
			// created_time; keep the inode and just move its mtime.
			if !e.modTime.IsZero() {
				if info, err := root.Lstat(rel); err == nil && !info.ModTime().Truncate(time.Second).Equal(e.modTime.Truncate(time.Second)) {
					_ = root.Chtimes(rel, e.modTime, e.modTime)
				}
			}
			continue
		}
		if err := writeAtomic(root, rel, e, spec.Mode); err != nil {
			return err
		}
	}

	return prune(root, r)
}

// prepareVolumeDir makes sure dir is a real directory at mode. A symlink is
// refused rather than followed for the same reason vaultfs refuses a
// symlinked mountpoint: the engine bind-mounts whatever this resolves to.
func prepareVolumeDir(dir string, mode os.FileMode) error {
	info, err := os.Lstat(dir)
	switch {
	case err == nil && info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("volume directory %s is a symlink", dir)
	case err == nil && !info.IsDir():
		return fmt.Errorf("volume directory %s exists and is not a directory", dir)
	case err == nil:
		return os.Chmod(dir, mode)
	case errors.Is(err, fs.ErrNotExist):
		return os.Mkdir(dir, mode)
	default:
		return err
	}
}

// ensureDir creates a directory at rel with the given mode, replacing
// whatever non-directory is in the way (a file left by a previous layout,
// or a link a container planted).
func ensureDir(root *os.Root, rel string, mode os.FileMode) error {
	info, err := root.Lstat(rel)
	switch {
	case err == nil && info.IsDir():
		return root.Chmod(rel, mode)
	case err == nil:
		if err := root.RemoveAll(rel); err != nil {
			return err
		}
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}
	return root.Mkdir(rel, mode)
}

// unchanged reports whether the regular file at rel already holds data at
// mode, so a refresh that found nothing new leaves the inode alone and a
// reader mid-way through the file is not switched to a new one for nothing.
func unchanged(root *os.Root, rel string, data []byte, mode os.FileMode) bool {
	info, err := root.Lstat(rel)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Size() != int64(len(data)) {
		return false
	}
	existing, err := root.ReadFile(rel)
	return err == nil && bytes.Equal(existing, data)
}

// tempPrefix marks the in-progress file writeAtomic renames over the target.
// A leftover from a crash is pruned like any other undesired entry.
const tempPrefix = ".dotvault-tmp-"

// writeAtomic writes a file so a reader sees either the previous contents or
// the new ones, never a partial write: the bytes land in a temp file in the
// same directory, get their mode and mtime, and are renamed over the target.
func writeAtomic(root *os.Root, rel string, e fileEntry, mode os.FileMode) error {
	parent := filepath.Dir(rel)
	var (
		f    *os.File
		name string
		err  error
	)
	// O_EXCL with a random suffix, retried on collision: the directory is
	// owner-writable and a leftover from a crash (or anything a container
	// left there) must never be reused as our temp file.
	for range 16 {
		name = filepath.Join(parent, fmt.Sprintf("%s%08x", tempPrefix, rand.Uint32()))
		f, err = root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	if err != nil {
		return err
	}
	fail := func(err error) error {
		f.Close()
		root.Remove(name)
		return err
	}
	if _, err := f.Write(e.data); err != nil {
		return fail(err)
	}
	if err := f.Chmod(mode); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		root.Remove(name)
		return err
	}
	if !e.modTime.IsZero() {
		// Best effort: the timestamp is informational (the secret's
		// version time, as the mount reports it), not something a reader
		// depends on.
		_ = root.Chtimes(name, e.modTime, e.modTime)
	}
	// A directory in the way (a layout change turned a file into a
	// directory, or a container planted one) would make the rename fail;
	// clear it first. rename(2) replaces a plain file atomically on its own.
	if info, err := root.Lstat(rel); err == nil && info.IsDir() {
		if err := root.RemoveAll(rel); err != nil {
			root.Remove(name)
			return err
		}
	}
	if err := root.Rename(name, rel); err != nil {
		root.Remove(name)
		return err
	}
	return nil
}

// prune removes everything under the root that r does not describe.
// Anything that is not a regular file or a directory — a symlink, say — is
// removed rather than followed: nothing but this daemon writes here, and a
// link that appeared anyway is not something to resolve.
func prune(root *os.Root, r *rendered) error {
	return fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == "." {
			return nil
		}
		rel := filepath.FromSlash(p)
		switch {
		case d.IsDir():
			if r.dirs[p] {
				return nil
			}
			if err := root.RemoveAll(rel); err != nil {
				return err
			}
			return fs.SkipDir
		case d.Type().IsRegular():
			if _, ok := r.files[p]; ok {
				return nil
			}
			return root.Remove(rel)
		default:
			return root.Remove(rel)
		}
	})
}

// materialise renders the spec from store into dir, returning the number of
// secrets the volume now carries.
func materialise(ctx context.Context, store vaultfs.Store, dir string, spec Spec) (int, error) {
	r, err := render(ctx, store, spec)
	if err != nil {
		return 0, err
	}
	if err := apply(dir, r, spec); err != nil {
		return 0, fmt.Errorf("write volume: %w", err)
	}
	return r.secrets, nil
}

// validComponent reports whether name can be one path component: it must
// survive CleanPath unchanged and carry no separator.
// validComponent reports whether name can be one path component of a volume
// file: a single canonical KV segment. The empty string is refused explicitly
// because vaultfs.CleanPath("") names the root rather than failing, and a KV
// secret can carry an empty field name, which the fields layout would
// otherwise turn into a file at the secret directory's own path.
func validComponent(name string) bool {
	if name == "" {
		return false
	}
	clean, err := vaultfs.CleanPath(name)
	return err == nil && clean == name && !strings.Contains(name, "/")
}

func joinRel(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

func parentRel(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return ""
}

// displayPath renders a relative KV path for a log line. Names are visible in
// any listing; values never appear in a message from this package.
func displayPath(p string) string {
	if p == "" {
		return "/"
	}
	return "/" + path.Clean(p)
}
