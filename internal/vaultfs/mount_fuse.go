//go:build linux || darwin || freebsd

// This file is the only place in the package that depends on FUSE. Everything
// it does is a translation: FUSE operations in, Tree calls out, errnos back.
// Any behaviour worth testing belongs in tree.go, which is testable without a
// kernel mount on any platform.
package vaultfs

import (
	"context"
	"errors"
	"hash/fnv"
	"log/slog"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// opTimeout bounds the Vault work behind a single filesystem operation. A
// filesystem call that never returns is worse than one that fails: the calling
// process sits in uninterruptible sleep, and on shutdown it holds the mount
// busy. Matches the 30s the web API's Vault-backed handlers use.
const opTimeout = 30 * time.Second

// File and directory modes. Both are owner-only, and the write bit tracks the
// mount's mode so `test -w` and an editor's read-only detection agree with
// what a write would actually do.
const (
	fileModeRO = 0o400
	fileModeRW = 0o600
	dirModeRO  = 0o500
	dirModeRW  = 0o700
)

// filesystem is the shared state behind every node.
type filesystem struct {
	tree *Tree
	opts Options

	// mountTime stands in for a missing created_time so stat never reports
	// the zero time, which tools render as 1970 and staleness comparisons
	// treat as infinitely old.
	mountTime time.Time
}

// node is one file or directory in the mount. Directories and files share a
// type because the distinction is one bit of Vault metadata rather than two
// different behaviours, and because a node can be constructed before the
// kernel asks which it is.
type node struct {
	fs.Inode

	fsys *filesystem

	// path is the node's path relative to the mount root; "" is the root.
	path string

	// dir distinguishes a KV folder from a secret.
	dir bool

	// ephemeral marks a directory created by mkdir that does not exist in
	// Vault yet. KVv2 has no directories of its own — a folder exists only
	// because secrets exist beneath it — so `mkdir` cannot write anything.
	// Holding the directory in memory lets the obvious sequence work:
	//   mkdir ~/.dotvault/databricks && echo '{...}' > ~/.dotvault/databricks/prod
	// The directory materialises when the first secret under it is written,
	// and an empty one simply disappears at unmount.
	ephemeral bool

	// handles are the open file descriptions on this node. They are tracked
	// because a truncate does not always arrive with a file handle attached:
	// for `open(O_TRUNC)` the kernel strips O_TRUNC from the OPEN request
	// and follows it with a SETATTR carrying a size and no FATTR_FH, so the
	// only way to apply it to the buffer the caller is about to write into
	// is to find that buffer from the node. go-fuse reuses one node per
	// inode for the life of the mount, so this list is stable across the
	// repeated lookups the kernel performs.
	hmu     sync.Mutex
	handles []*handle
}

func (n *node) addHandle(h *handle) {
	n.hmu.Lock()
	defer n.hmu.Unlock()
	n.handles = append(n.handles, h)
}

func (n *node) removeHandle(h *handle) {
	n.hmu.Lock()
	defer n.hmu.Unlock()
	for i, existing := range n.handles {
		if existing == h {
			n.handles = append(n.handles[:i], n.handles[i+1:]...)
			return
		}
	}
}

func (n *node) openHandles() []*handle {
	n.hmu.Lock()
	defer n.hmu.Unlock()
	return append([]*handle(nil), n.handles...)
}

// Compile-time assertions for every FUSE interface node implements. Without
// these a signature that drifts from go-fuse's expectation silently stops
// being called rather than failing to build.
var (
	_ fs.NodeGetattrer = (*node)(nil)
	_ fs.NodeLookuper  = (*node)(nil)
	_ fs.NodeReaddirer = (*node)(nil)
	_ fs.NodeOpener    = (*node)(nil)
	_ fs.NodeSetattrer = (*node)(nil)
	_ fs.NodeCreater   = (*node)(nil)
	_ fs.NodeUnlinker  = (*node)(nil)
	_ fs.NodeMkdirer   = (*node)(nil)
	_ fs.NodeRmdirer   = (*node)(nil)

	_ fs.FileReader   = (*handle)(nil)
	_ fs.FileWriter   = (*handle)(nil)
	_ fs.FileFlusher  = (*handle)(nil)
	_ fs.FileReleaser = (*handle)(nil)
	_ fs.FileFsyncer  = (*handle)(nil)
)

// mount attaches the tree at mountpoint. It is the platform seam Service.Run
// calls; the other build of this function returns ErrUnsupported.
func mount(mountpoint string, tree *Tree, opts Options) (mountedFS, error) {
	fsys := &filesystem{tree: tree, opts: opts, mountTime: time.Now()}
	root := &node{fsys: fsys, dir: true}

	// The kernel may cache an entry or an attribute for this long before
	// asking again. Matching the cache TTL means the two layers expire
	// together: a longer kernel timeout would let the kernel serve stale
	// answers the package's own cache had already dropped, and there is no
	// way to reach past it. A zero TTL (caching disabled) leaves both at
	// zero, so every operation reaches Vault.
	timeout := opts.CacheTTL
	mountOpts := fuse.MountOptions{
		FsName: "dotvault",
		Name:   "dotvault",
		// DirectMount asks go-fuse to call mount(2) itself, falling back to
		// the fusermount helper when that is not permitted. That ordering
		// covers both deployments: an unprivileged user's daemon needs
		// fusermount, while a container or service account with CAP_SYS_ADMIN
		// but no fuse package installed can still mount.
		DirectMount: true,
		// The default FUSE mount is already owner-only, and dotvault does not
		// offer allow_other: the whole point of the per-user daemon is that
		// the secrets it holds belong to one uid.
		Options: []string{"nosuid", "nodev"},
	}
	if !opts.ReadWrite {
		// Belt and braces with the node-level guard: the kernel then rejects
		// writes before they ever reach a handler.
		mountOpts.Options = append(mountOpts.Options, "ro")
	}

	server, err := fs.Mount(mountpoint, root, &fs.Options{
		MountOptions: mountOpts,
		EntryTimeout: &timeout,
		AttrTimeout:  &timeout,
		// Files and directories carry explicit modes, so a zero mode is a
		// bug rather than a request for go-fuse's default.
		NullPermissions: false,
		UID:             uint32(os.Getuid()),
		GID:             uint32(os.Getgid()),
	})
	if err != nil {
		return nil, err
	}
	return server, nil
}

// clearStaleMount handles a mountpoint left behind by a daemon that died
// without unmounting. The kernel keeps the mount in place with no server
// attached, so stat reports ENOTCONN and a fresh mount over it fails. Nothing
// but an unmount clears it, and it is unambiguously ours to clear: a
// connected mount does not report ENOTCONN.
//
// MNT_DETACH (lazy) rather than a plain unmount, because the dead mount may
// still have processes with open file descriptors on it, and they can never
// be served again anyway.
func clearStaleMount(dir string, statErr error) bool {
	if !errors.Is(statErr, syscall.ENOTCONN) {
		return false
	}
	if err := unmountStale(dir); err != nil {
		slog.Warn("could not clear stale filesystem mount", "mountpoint", dir, "error", err)
		return false
	}
	slog.Info("cleared stale filesystem mount left by a previous run", "mountpoint", dir)
	return true
}

// --- attributes ---------------------------------------------------------

func (n *node) fileMode() uint32 {
	if n.fsys.opts.ReadWrite {
		return fileModeRW
	}
	return fileModeRO
}

func (n *node) dirMode() uint32 {
	if n.fsys.opts.ReadWrite {
		return dirModeRW
	}
	return dirModeRO
}

// stableAttr derives the inode identity for a path. The number is a hash of
// the path and kind, so it stays the same across lookups (which `find -inum`,
// rsync's hardlink detection and anything caching by inode rely on) and
// changes if a name ever flips between file and directory — go-fuse requires
// an inode number and a file type to agree for the life of the mount.
func stableAttr(path string, dir bool) fs.StableAttr {
	h := fnv.New64a()
	if dir {
		_, _ = h.Write([]byte{'d'})
	} else {
		_, _ = h.Write([]byte{'f'})
	}
	_, _ = h.Write([]byte(path))
	// Inode 1 is the root; never hand it to a child.
	ino := h.Sum64()
	if ino <= 1 {
		ino += 2
	}
	mode := uint32(fuse.S_IFREG)
	if dir {
		mode = fuse.S_IFDIR
	}
	return fs.StableAttr{Mode: mode, Ino: ino}
}

func (n *node) setDirAttr(out *fuse.Attr) {
	out.Mode = fuse.S_IFDIR | n.dirMode()
	out.Nlink = 2
	out.Size = 0
	n.setTimes(out, time.Time{})
}

func (n *node) setFileAttr(out *fuse.Attr, doc *Document) {
	out.Mode = fuse.S_IFREG | n.fileMode()
	out.Nlink = 1
	out.Size = uint64(doc.Size())
	n.setTimes(out, doc.ModTime)
}

// setTimes reports the same instant for mtime, ctime and atime. KVv2 records
// one timestamp per version, so inventing a distinction between the three
// would be making data up; atime in particular would otherwise imply the
// filesystem tracks reads, which it does not.
func (n *node) setTimes(out *fuse.Attr, t time.Time) {
	if t.IsZero() {
		t = n.fsys.mountTime
	}
	secs := uint64(t.Unix())
	nsecs := uint32(t.Nanosecond())
	out.Mtime, out.Mtimensec = secs, nsecs
	out.Ctime, out.Ctimensec = secs, nsecs
	out.Atime, out.Atimensec = secs, nsecs
	out.Owner = fuse.Owner{Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid())}
}

func (n *node) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if n.dir {
		n.setDirAttr(&out.Attr)
		return 0
	}

	// An open handle is the authority on size while the file is being
	// written: the buffer holds bytes Vault has not seen yet, and reporting
	// the stored size instead would make a partially-written file look
	// truncated to anything that stats between write and close.
	if h, ok := f.(*handle); ok {
		if size, ok := h.pendingSize(); ok {
			out.Attr.Mode = fuse.S_IFREG | n.fileMode()
			out.Attr.Nlink = 1
			out.Attr.Size = uint64(size)
			n.setTimes(&out.Attr, time.Time{})
			return 0
		}
	}

	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	doc, err := n.fsys.tree.Document(ctx, n.path)
	if err != nil {
		return logErrno("getattr", n.path, err)
	}
	if doc == nil {
		return syscall.ENOENT
	}
	n.setFileAttr(&out.Attr, doc)
	return 0
}

// Setattr exists to make truncation work, which is what every "replace this
// file" idiom actually does: a shell `>` redirect, an editor's save, `jq ... |
// sponge`. Other attribute changes are accepted and discarded rather than
// refused — chmod and utimes have nothing to act on here (the mode is derived
// from the mount's read-write flag, and the timestamp comes from Vault), and
// failing them would break tools that set them reflexively after a write.
func (n *node) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if n.dir {
		return syscall.EISDIR
	}
	if size, ok := in.GetSize(); ok {
		if !n.fsys.opts.ReadWrite {
			return syscall.EROFS
		}
		targets := []*handle{}
		if h, ok := f.(*handle); ok {
			targets = append(targets, h)
		} else {
			// `open(O_TRUNC)` arrives here with no handle attached (see the
			// handles field), so the truncate has to be applied to every
			// open description on this node — in practice the one the
			// caller just opened and is about to write into.
			targets = n.openHandles()
		}
		if len(targets) == 0 {
			// A bare truncate(2) on a path with nothing open. There is no
			// buffer to shorten and no valid document with fewer bytes to
			// write: a secret is a whole JSON object or it is not a secret.
			return syscall.EINVAL
		}
		for _, h := range targets {
			if errno := h.truncate(int64(size)); errno != 0 {
				return errno
			}
		}
	}
	return n.Getattr(ctx, f, out)
}

// --- directory operations -----------------------------------------------

func (n *node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if !n.dir {
		return nil, syscall.ENOTDIR
	}
	// An ephemeral directory exists only in this process, so no amount of
	// asking Vault will find it. The kernel re-looks-up entries once their
	// timeout expires, so without this check a `mkdir` would evaporate
	// moments later.
	if child := n.GetChild(name); child != nil {
		if cn, ok := child.Operations().(*node); ok && cn.ephemeral {
			cn.setDirAttr(&out.Attr)
			return child, 0
		}
	}

	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	kind, err := n.fsys.tree.Lookup(ctx, n.path, name)
	if err != nil {
		if errors.Is(err, ErrInvalidName) {
			return nil, syscall.EINVAL
		}
		return nil, logErrno("lookup", joinPath(n.path, name), err)
	}
	switch kind {
	case KindDir:
		return n.newChild(ctx, name, true, out, nil), 0
	case KindFile:
		doc, err := n.fsys.tree.Document(ctx, joinPath(n.path, name))
		if err != nil {
			return nil, logErrno("lookup", joinPath(n.path, name), err)
		}
		if doc == nil {
			// Deleted between the listing and the read.
			return nil, syscall.ENOENT
		}
		return n.newChild(ctx, name, false, out, doc), 0
	default:
		return nil, syscall.ENOENT
	}
}

// newChild builds (or reuses) the inode for a child and fills in its attrs.
func (n *node) newChild(ctx context.Context, name string, dir bool, out *fuse.EntryOut, doc *Document) *fs.Inode {
	path := joinPath(n.path, name)
	child := &node{fsys: n.fsys, path: path, dir: dir}
	inode := n.NewInode(ctx, child, stableAttr(path, dir))
	if out != nil {
		if dir {
			child.setDirAttr(&out.Attr)
		} else {
			child.setFileAttr(&out.Attr, doc)
		}
	}
	return inode
}

func (n *node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	if !n.dir {
		return nil, syscall.ENOTDIR
	}

	listCtx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	entries, err := n.fsys.tree.Readdir(listCtx, n.path)
	if err != nil {
		return nil, logErrno("readdir", n.path, err)
	}

	seen := make(map[string]bool, len(entries))
	out := make([]fuse.DirEntry, 0, len(entries))
	for _, e := range entries {
		seen[e.Name] = true
		out = append(out, fuse.DirEntry{
			Name: e.Name,
			Mode: stableAttr(joinPath(n.path, e.Name), e.Kind == KindDir).Mode,
			Ino:  stableAttr(joinPath(n.path, e.Name), e.Kind == KindDir).Ino,
		})
	}
	// Ephemeral directories are not in Vault, so they have to be added from
	// the in-memory tree or an `ls` immediately after `mkdir` would not show
	// the directory that was just created.
	for name, child := range n.Children() {
		if seen[name] {
			continue
		}
		cn, ok := child.Operations().(*node)
		if !ok || !cn.ephemeral {
			continue
		}
		out = append(out, fuse.DirEntry{
			Name: name,
			Mode: fuse.S_IFDIR,
			Ino:  stableAttr(cn.path, true).Ino,
		})
	}
	return fs.NewListDirStream(out), 0
}

// Mkdir creates a directory that exists only until a secret is written inside
// it — see node.ephemeral. It is not a Vault write, so it does not need the
// read-write mount for safety's sake, but it is refused on a read-only mount
// anyway: a directory that can never be filled is a trap, not a feature.
func (n *node) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if !n.fsys.opts.ReadWrite {
		return nil, syscall.EROFS
	}
	if err := validateName(name); err != nil {
		return nil, syscall.EINVAL
	}

	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	kind, err := n.fsys.tree.Lookup(ctx, n.path, name)
	if err != nil {
		return nil, logErrno("mkdir", joinPath(n.path, name), err)
	}
	if kind != KindNone {
		return nil, syscall.EEXIST
	}
	if n.GetChild(name) != nil {
		return nil, syscall.EEXIST
	}

	path := joinPath(n.path, name)
	child := &node{fsys: n.fsys, path: path, dir: true, ephemeral: true}
	// Persistent so the inode is not reclaimed while the kernel is not
	// looking at it; nothing else remembers that this directory exists.
	inode := n.NewPersistentInode(ctx, child, stableAttr(path, true))
	if !n.AddChild(name, inode, false) {
		return nil, syscall.EEXIST
	}
	child.setDirAttr(&out.Attr)
	return inode, 0
}

// Rmdir removes an empty ephemeral directory. A directory backed by Vault has
// no independent existence — it is implied by the secrets beneath it — so
// there is nothing for rmdir to delete: emptying it is what removes it, and
// reporting ENOTEMPTY says exactly that.
func (n *node) Rmdir(ctx context.Context, name string) syscall.Errno {
	if !n.fsys.opts.ReadWrite {
		return syscall.EROFS
	}
	child := n.GetChild(name)
	if child == nil {
		return syscall.ENOENT
	}
	cn, ok := child.Operations().(*node)
	if !ok || !cn.ephemeral {
		return syscall.ENOTEMPTY
	}

	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	// The directory may have become real since mkdir — a secret written
	// inside it materialises the folder in Vault.
	entries, err := n.fsys.tree.Readdir(ctx, cn.path)
	if err != nil {
		return logErrno("rmdir", cn.path, err)
	}
	if len(entries) > 0 || len(child.Children()) > 0 {
		return syscall.ENOTEMPTY
	}
	child.ForgetPersistent()
	n.RmChild(name)
	return 0
}

func (n *node) Unlink(ctx context.Context, name string) syscall.Errno {
	if !n.fsys.opts.ReadWrite {
		return syscall.EROFS
	}

	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	path := joinPath(n.path, name)
	if err := n.fsys.tree.Remove(ctx, path); err != nil {
		return logErrno("unlink", path, err)
	}
	return 0
}

// --- file operations ----------------------------------------------------

func (n *node) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if n.dir {
		return nil, 0, syscall.EISDIR
	}
	writing := flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0
	if writing && !n.fsys.opts.ReadWrite {
		return nil, 0, syscall.EROFS
	}
	if flags&syscall.O_APPEND != 0 {
		// Appending to a JSON document produces something that is not a JSON
		// document. Refusing is honest; accepting would defer the failure to
		// close(), long after the caller could do anything about it.
		return nil, 0, syscall.EINVAL
	}

	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	h := &handle{node: n, writable: writing}
	if flags&syscall.O_TRUNC != 0 {
		// Nothing to load: the caller is replacing the whole document, and
		// reading first would be a pointless Vault round trip.
		h.buf = nil
		h.dirty = true
	} else {
		doc, err := n.fsys.tree.Document(ctx, n.path)
		if err != nil {
			return nil, 0, logErrno("open", n.path, err)
		}
		if doc == nil {
			return nil, 0, syscall.ENOENT
		}
		// The handle owns its snapshot: a concurrent write through the same
		// mount must not mutate bytes another reader is part-way through.
		h.buf = append([]byte(nil), doc.Bytes...)
	}
	n.addHandle(h)
	// FOPEN_DIRECT_IO is deliberately not set. The page cache is what makes
	// repeated reads of an open file free, and the entry/attr timeouts above
	// already bound how stale any of it can be.
	return h, 0, 0
}

func (n *node) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	if !n.fsys.opts.ReadWrite {
		return nil, nil, 0, syscall.EROFS
	}
	if err := validateName(name); err != nil {
		return nil, nil, 0, syscall.EINVAL
	}

	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	path := joinPath(n.path, name)
	kind, err := n.fsys.tree.Lookup(ctx, n.path, name)
	if err != nil {
		return nil, nil, 0, logErrno("create", path, err)
	}
	if kind == KindDir {
		return nil, nil, 0, syscall.EISDIR
	}

	child := &node{fsys: n.fsys, path: path}
	inode := n.NewInode(ctx, child, stableAttr(path, false))
	// dirty from the outset, so a create with nothing written to it fails on
	// close rather than silently leaving a file that vanishes on the next
	// lookup. `touch` on this filesystem is not meaningful — a secret with no
	// fields is not a thing KVv2 stores — and an error says so at the point
	// the user can still act on it.
	h := &handle{node: child, writable: true, dirty: true}
	// Register on the node the inode actually carries: go-fuse reuses an
	// existing node when one is already live for this inode, in which case
	// the freshly built child above is discarded and a later SETATTR would
	// look for the handle on the surviving node.
	owner := child
	if existing, ok := inode.Operations().(*node); ok {
		owner = existing
	}
	h.node = owner
	owner.addHandle(h)
	child.setTimes(&out.Attr, time.Time{})
	out.Attr.Mode = fuse.S_IFREG | child.fileMode()
	out.Attr.Nlink = 1
	return inode, h, 0, 0
}

// handle is one open file description. It buffers the whole document: secrets
// are small (a few hundred bytes), and a write must be applied to Vault as one
// atomic KVv2 version rather than as a series of partial updates, so there is
// nothing to gain from streaming.
type handle struct {
	node     *node
	writable bool

	mu    sync.Mutex
	buf   []byte
	dirty bool
}

func (h *handle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if off < 0 {
		return nil, syscall.EINVAL
	}
	if off >= int64(len(h.buf)) {
		return fuse.ReadResultData(nil), 0
	}
	return fuse.ReadResultData(h.buf[off:]), 0
}

func (h *handle) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	if !h.writable {
		return 0, syscall.EBADF
	}
	if off < 0 {
		return 0, syscall.EINVAL
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	end := off + int64(len(data))
	if end > maxDocumentSize {
		// A secret is not a place to put a large file, and an unbounded
		// buffer here would let any process running as this user exhaust the
		// daemon's memory through the mount.
		return 0, syscall.EFBIG
	}
	if end > int64(len(h.buf)) {
		grown := make([]byte, end)
		copy(grown, h.buf)
		h.buf = grown
	}
	copy(h.buf[off:], data)
	h.dirty = true
	return uint32(len(data)), 0
}

// maxDocumentSize caps what a single secret file can hold. Vault's own
// default max request size is 32 MiB; this is far below it because a KV
// secret holding a megabyte of JSON is a misuse of the mount, and the cap's
// real job is to stop a runaway `cat /dev/urandom >` from growing the
// daemon's heap without bound.
const maxDocumentSize = 1 << 20

func (h *handle) truncate(size int64) syscall.Errno {
	if size < 0 || size > maxDocumentSize {
		return syscall.EINVAL
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case size < int64(len(h.buf)):
		h.buf = h.buf[:size]
	case size > int64(len(h.buf)):
		grown := make([]byte, size)
		copy(grown, h.buf)
		h.buf = grown
	}
	h.dirty = true
	return 0
}

// pendingSize reports the in-flight buffer length for a handle with unwritten
// changes, so stat during a write sees what has been written so far.
func (h *handle) pendingSize() (int64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.dirty {
		return 0, false
	}
	return int64(len(h.buf)), true
}

// Flush is where a write reaches Vault. The kernel calls it on every close(),
// which is the last moment the caller can be told the write failed — so
// invalid JSON surfaces as a failing close() rather than as a silently
// discarded edit.
func (h *handle) Flush(ctx context.Context) syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.dirty {
		return 0
	}

	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	if err := h.node.fsys.tree.Put(ctx, h.node.path, h.buf); err != nil {
		return logErrno("flush", h.node.path, err)
	}
	// Cleared only on success, so a close() that failed leaves the data in
	// the handle for a retry rather than dropping it.
	h.dirty = false
	return 0
}

// Fsync applies pending changes for callers that ask for durability before
// close — editors that write, fsync, then rename, most notably.
func (h *handle) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	return h.Flush(ctx)
}

func (h *handle) Release(ctx context.Context) syscall.Errno {
	h.node.removeHandle(h)
	h.mu.Lock()
	defer h.mu.Unlock()
	// Release cannot report an error to the caller, so it must not be where
	// a write is attempted: Flush already ran on close and reported anything
	// that went wrong. Dropping the buffer here just releases the memory.
	h.buf = nil
	return 0
}

// logErrno maps a tree error onto an errno, logging the detail an errno
// cannot carry. Paths are logged; values never are, and no error produced by
// this package embeds one.
func logErrno(op, path string, err error) syscall.Errno {
	switch {
	case errors.Is(err, ErrReadOnly):
		return syscall.EROFS
	case errors.Is(err, ErrInvalidDocument):
		slog.Debug("vaultfs: rejected write of a document that is not a JSON object", "op", op, "path", displayPath(path))
		return syscall.EINVAL
	case errors.Is(err, ErrInvalidName):
		return syscall.EINVAL
	case errors.Is(err, context.Canceled):
		return syscall.EINTR
	case errors.Is(err, context.DeadlineExceeded):
		slog.Warn("vaultfs: vault did not respond in time", "op", op, "path", displayPath(path))
		return syscall.ETIMEDOUT
	case vault.IsForbidden(err):
		slog.Warn("vaultfs: vault denied the request", "op", op, "path", displayPath(path))
		return syscall.EACCES
	default:
		slog.Warn("vaultfs: operation failed", "op", op, "path", displayPath(path), "error", err)
		return syscall.EIO
	}
}
