// Package vaultfs projects the user's KVv2 secrets as a filesystem: a secret
// becomes a file whose contents are its data section rendered as JSON, and a
// KV folder becomes a directory. Mounted at ~/.dotvault, a secret at
// kv/users/gary/gh reads as ~/.dotvault/gh, so `jq . ~/.dotvault/gh` works and
// stat reports the current version's created_time as the file's mtime.
//
// The package is split so that almost none of it depends on FUSE. Everything
// here and in tree.go / cache.go / document.go is platform-neutral and
// testable on any OS, including Windows; only mount_fuse.go binds the tree to
// github.com/hanwen/go-fuse, and it is build-tagged to the platforms that have
// a FUSE implementation (Linux, macOS via macFUSE, FreeBSD). Windows gets
// mount_other.go, which reports ErrUnsupported — the same shape internal/tray
// and internal/securestore use for platform-specific surfaces.
//
// # Layout expectations
//
// A KV path is expected to be either a secret or a folder, never both. Vault
// permits both (a secret at users/you/databricks alongside users/you/databricks/prod,
// which LIST returns as the two entries "databricks" and "databricks/"), but a
// filesystem name can only be one thing. dotvault treats that overlap as
// unsupported: the behaviour is deterministic — the directory wins, so grouped
// enrolment keys stay reachable — but the secret sharing the folder's name has
// no path in the mount. Lay the KV tree out so it does not arise; the daemon
// logs a warning naming the path when it does.
//
// # Read-only by default
//
// The mount is read-only unless fuse.read_write is set, regardless of what the
// Vault token could do. The guard lives in the tree (Tree.ReadWrite), not only
// in the mount options, so a caller cannot obtain a writable view by mounting
// with different flags.
package vaultfs

import (
	"context"
	"errors"
	"time"
)

// ErrUnsupported is returned by Mount on platforms with no FUSE implementation
// (Windows today). Callers should treat it as "this surface does not exist
// here" rather than as a failure to start.
var ErrUnsupported = errors.New("vaultfs: filesystem mounting is not supported on this platform")

// ErrReadOnly is returned by every mutating Tree operation when the mount was
// not configured read-write.
var ErrReadOnly = errors.New("vaultfs: filesystem is read-only")

// ErrInvalidDocument is returned when the bytes written to a secret file are
// not a JSON object with at least one field. It is deliberately content-free:
// the bytes being rejected are secret material, so neither the error nor any
// log line derived from it may quote them.
var ErrInvalidDocument = errors.New("vaultfs: not a JSON object with at least one field")

// ErrInvalidName is returned for a path component a KV path cannot carry: an
// empty name, "." or "..", or one containing a slash or NUL.
var ErrInvalidName = errors.New("vaultfs: invalid name")

// Secret is one KVv2 secret as the filesystem needs it: the data section plus
// the version metadata that becomes the file's mtime.
type Secret struct {
	Data        map[string]any
	Version     int
	CreatedTime time.Time
}

// Store is the KV access seam. Paths are relative to the user's own prefix
// (kv/{user_prefix}{username}/), so the store — not the tree — owns the mount
// and prefix. Keeping the tree in relative paths means the FUSE layer can
// never address a path outside the user's own subtree, and it makes the whole
// tree testable against an in-memory store.
type Store interface {
	// List returns the child names directly under relPath ("" is the root).
	// Folder entries carry a trailing slash, exactly as Vault's LIST returns
	// them. A path that does not exist is (nil, nil), not an error.
	List(ctx context.Context, relPath string) ([]string, error)

	// Read returns the secret at relPath, or (nil, nil) if none exists.
	Read(ctx context.Context, relPath string) (*Secret, error)

	// Write replaces the data at relPath, creating the secret if absent.
	Write(ctx context.Context, relPath string, data map[string]any) error

	// Delete removes the secret at relPath and all of its versions.
	Delete(ctx context.Context, relPath string) error
}
