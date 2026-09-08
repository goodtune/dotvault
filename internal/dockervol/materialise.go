package dockervol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
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
			slog.Warn("dockervol: a directory and a file claim the same name; the file is not written",
				"path", displayPath(p))
			delete(r.files, p)
		}
	}
	return r, nil
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
func apply(dir string, r *rendered, spec Spec) error {
	dirMode := spec.DirMode()
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		return err
	}

	dirs := make([]string, 0, len(r.dirs))
	for d := range r.dirs {
		dirs = append(dirs, d)
	}
	// Parents before children: a shorter path can never be a descendant
	// of a longer one.
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) < len(dirs[j]) })
	for _, d := range dirs {
		full := filepath.Join(dir, filepath.FromSlash(d))
		if err := ensureDir(full, dirMode); err != nil {
			return err
		}
	}

	for p, e := range r.files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if unchanged(full, e.data, spec.Mode) {
			continue
		}
		if err := writeAtomic(full, e, spec.Mode); err != nil {
			return err
		}
	}

	return prune(dir, r)
}

// ensureDir creates a directory at full with the given mode, replacing a
// non-directory that is in the way (a file left by a previous layout).
func ensureDir(full string, mode os.FileMode) error {
	info, err := os.Lstat(full)
	switch {
	case err == nil && info.IsDir():
		return os.Chmod(full, mode)
	case err == nil:
		if err := os.RemoveAll(full); err != nil {
			return err
		}
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}
	return os.Mkdir(full, mode)
}

// unchanged reports whether the regular file at full already holds data at
// mode, so a refresh that found nothing new leaves the inode alone and a
// reader mid-way through the file is not switched to a new one for nothing.
func unchanged(full string, data []byte, mode os.FileMode) bool {
	info, err := os.Lstat(full)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Size() != int64(len(data)) {
		return false
	}
	existing, err := os.ReadFile(full)
	return err == nil && bytes.Equal(existing, data)
}

// tempPrefix marks the in-progress file writeAtomic renames over the target.
// A leftover from a crash is pruned like any other undesired entry.
const tempPrefix = ".dotvault-tmp-"

// writeAtomic writes a file so a reader sees either the previous contents or
// the new ones, never a partial write: the bytes land in a temp file in the
// same directory, get their mode and mtime, and are renamed over the target.
func writeAtomic(full string, e fileEntry, mode os.FileMode) error {
	parent := filepath.Dir(full)
	tmp, err := os.CreateTemp(parent, tempPrefix+"*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if _, err := tmp.Write(e.data); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if !e.modTime.IsZero() {
		// Best effort: the timestamp is informational (the secret's
		// version time, as the mount reports it), not something a reader
		// depends on.
		_ = os.Chtimes(name, e.modTime, e.modTime)
	}
	// A non-directory in the way (a layout change turned a file into a
	// directory or back) would make the rename fail or, worse, land inside
	// a directory; clear it first. rename(2) replaces a plain file
	// atomically on its own.
	if info, err := os.Lstat(full); err == nil && info.IsDir() {
		if err := os.RemoveAll(full); err != nil {
			os.Remove(name)
			return err
		}
	}
	if err := os.Rename(name, full); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// prune removes everything under dir that r does not describe. Anything
// that is not a regular file or a directory — a symlink, say — is removed
// rather than followed: nothing but this daemon writes here, and a link
// that appeared anyway is not something to resolve.
func prune(dir string, r *rendered) error {
	return filepath.WalkDir(dir, func(full string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if full == dir {
			return nil
		}
		rel, err := filepath.Rel(dir, full)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch {
		case d.IsDir():
			if r.dirs[rel] {
				return nil
			}
			if err := os.RemoveAll(full); err != nil {
				return err
			}
			return fs.SkipDir
		case d.Type().IsRegular():
			if _, ok := r.files[rel]; ok {
				return nil
			}
			return os.Remove(full)
		default:
			return os.Remove(full)
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
func validComponent(name string) bool {
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
