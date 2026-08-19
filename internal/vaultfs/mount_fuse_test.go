//go:build linux || darwin || freebsd

package vaultfs

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// mountForTest mounts a filesystem over store and returns the mountpoint.
//
// Mounting needs a working FUSE stack, which a sandboxed CI container may not
// have (no /dev/fuse, no fusermount helper, no macFUSE). Rather than fail
// there, the test skips: everything these tests cover about *behaviour* is
// also covered by the tree tests, which need no kernel. What is only
// verifiable here is the FUSE binding itself.
//
// The skip is deliberately narrow. Service.Run does two things that can fail —
// prepare the mountpoint, then mount — and only the second is the environment's
// fault. Preparing the mountpoint is run here first and is fatal, so a
// regression in prepareMountpoint fails loudly instead of being reported as
// "FUSE is unavailable" on a machine where FUSE works fine. A skip that can
// swallow a real bug is worse than no test.
func mountForTest(t *testing.T, store Store, opts Options) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "mnt")
	opts.Mountpoint = dir
	if err := prepareMountpoint(dir); err != nil {
		t.Fatalf("prepareMountpoint: %v", err)
	}
	svc, err := NewService(store, opts)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- svc.Run(ctx) }()

	// Wait for the mount to come up, or for Run to report why it could not.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if svc.Status().State == StateMounted {
			break
		}
		select {
		case err := <-errc:
			cancel()
			t.Skipf("FUSE is not usable in this environment: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("timed out waiting for the filesystem to mount")
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Cleanup(func() {
		cancel()
		select {
		case <-errc:
		case <-time.After(15 * time.Second):
			t.Error("timed out waiting for the filesystem to unmount")
		}
	})
	return dir
}

func seededStore() *memStore {
	store := newMemStore()
	store.put("gh", map[string]any{"oauth_token": "gho_example", "user": "gary"})
	store.put("databricks/prod", map[string]any{"host": "https://example.databricks.com"})
	return store
}

func TestMountReadsSecretAsJSON(t *testing.T) {
	store := seededStore()
	mnt := mountForTest(t, store, Options{CacheTTL: time.Second})

	b, err := os.ReadFile(filepath.Join(mnt, "gh"))
	if err != nil {
		t.Fatalf("read gh: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("file contents are not JSON: %v", err)
	}
	if got["oauth_token"] != "gho_example" {
		t.Errorf("oauth_token = %v, want gho_example", got["oauth_token"])
	}
	// The trailing newline is what makes `cat` behave; assert it explicitly
	// so a future change to renderDocument cannot drop it silently.
	if len(b) == 0 || b[len(b)-1] != '\n' {
		t.Error("rendered document does not end in a newline")
	}
}

func TestMountStatReportsSizeAndModTime(t *testing.T) {
	store := seededStore()
	mnt := mountForTest(t, store, Options{CacheTTL: time.Second})

	path := filepath.Join(mnt, "gh")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Size must match the bytes exactly: tools that mmap or that read
	// st_size bytes rely on it, and a filesystem that lies here truncates.
	if info.Size() != int64(len(b)) {
		t.Errorf("stat size = %d, read %d bytes", info.Size(), len(b))
	}

	want := time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC)
	if !info.ModTime().UTC().Equal(want) {
		t.Errorf("mtime = %s, want the version's created_time %s", info.ModTime().UTC(), want)
	}
	if perm := info.Mode().Perm(); perm != fileModeRO {
		t.Errorf("mode = %o, want %o on a read-only mount", perm, fileModeRO)
	}
}

func TestMountListsFoldersAsDirectories(t *testing.T) {
	store := seededStore()
	mnt := mountForTest(t, store, Options{CacheTTL: time.Second})

	entries, err := os.ReadDir(mnt)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	kinds := map[string]bool{}
	for _, e := range entries {
		kinds[e.Name()] = e.IsDir()
	}
	if isDir, ok := kinds["gh"]; !ok || isDir {
		t.Errorf("gh should be listed as a file, got dir=%v present=%v", isDir, ok)
	}
	if isDir, ok := kinds["databricks"]; !ok || !isDir {
		t.Errorf("databricks should be listed as a directory, got dir=%v present=%v", isDir, ok)
	}

	// The grouped key is reachable at its nested path.
	if _, err := os.ReadFile(filepath.Join(mnt, "databricks", "prod")); err != nil {
		t.Errorf("read databricks/prod: %v", err)
	}
}

func TestMountReadOnlyRejectsWrites(t *testing.T) {
	store := seededStore()
	mnt := mountForTest(t, store, Options{CacheTTL: time.Second})

	err := os.WriteFile(filepath.Join(mnt, "gh"), []byte(`{"a":"b"}`), 0o600)
	if err == nil {
		t.Fatal("write to a read-only mount succeeded")
	}
	if !errors.Is(err, syscall.EROFS) && !errors.Is(err, os.ErrPermission) {
		t.Errorf("write error = %v, want EROFS/EPERM", err)
	}
	if err := os.Remove(filepath.Join(mnt, "gh")); err == nil {
		t.Error("unlink on a read-only mount succeeded")
	}
	if _, _, writes, deletes := store.counts(); writes != 0 || deletes != 0 {
		t.Errorf("read-only mount reached the store: %d writes, %d deletes", writes, deletes)
	}
}

func TestMountReadWriteReplacesSecret(t *testing.T) {
	store := seededStore()
	mnt := mountForTest(t, store, Options{ReadWrite: true, CacheTTL: time.Second})

	path := filepath.Join(mnt, "gh")
	if err := os.WriteFile(path, []byte(`{"oauth_token":"gho_rotated"}`+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	store.mu.Lock()
	got := store.secrets["gh"]["oauth_token"]
	store.mu.Unlock()
	if got != "gho_rotated" {
		t.Errorf("stored oauth_token = %v, want gho_rotated", got)
	}

	// A read straight after the write must see the new value: the write
	// invalidates the cache entry it just superseded.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("read back is not JSON: %v", err)
	}
	if back["oauth_token"] != "gho_rotated" {
		t.Errorf("read back oauth_token = %v, want gho_rotated", back["oauth_token"])
	}
}

// A replacement shorter than what was stored must not leave the tail of the
// old document behind. The kernel does not pass O_TRUNC through to OPEN — it
// sends a separate, handle-less SETATTR — so this is the test that fails if
// the node stops tracking its open handles.
func TestMountReadWriteShorterReplacementTruncates(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{
		"oauth_token": "gho_a_deliberately_long_value_to_make_the_document_big",
		"user":        "gary",
		"note":        "several more fields so the stored document is clearly longer",
	})
	mnt := mountForTest(t, store, Options{ReadWrite: true, CacheTTL: time.Second})

	path := filepath.Join(mnt, "gh")
	if err := os.WriteFile(path, []byte(`{"k":"v"}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("read back is not valid JSON (stale tail left behind?): %v", err)
	}
	if len(back) != 1 || back["k"] != "v" {
		t.Errorf("read back = %v, want exactly {k: v}", back)
	}
}

func TestMountReadWriteRejectsInvalidJSON(t *testing.T) {
	store := seededStore()
	mnt := mountForTest(t, store, Options{ReadWrite: true, CacheTTL: time.Second})

	err := os.WriteFile(filepath.Join(mnt, "gh"), []byte("not json"), 0o600)
	if err == nil {
		t.Fatal("writing non-JSON succeeded")
	}
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("error = %v, want EINVAL", err)
	}
	if _, _, writes, _ := store.counts(); writes != 0 {
		t.Errorf("invalid document reached the store (%d writes)", writes)
	}
}

func TestMountReadWriteCreateAndUnlink(t *testing.T) {
	store := seededStore()
	mnt := mountForTest(t, store, Options{ReadWrite: true, CacheTTL: 10 * time.Millisecond})

	path := filepath.Join(mnt, "newsecret")
	if err := os.WriteFile(path, []byte(`{"k":"v"}`), 0o600); err != nil {
		t.Fatalf("create: %v", err)
	}
	store.mu.Lock()
	_, created := store.secrets["newsecret"]
	store.mu.Unlock()
	if !created {
		t.Fatal("created file did not reach the store")
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	store.mu.Lock()
	_, stillThere := store.secrets["newsecret"]
	store.mu.Unlock()
	if stillThere {
		t.Error("unlink did not delete the secret")
	}
}

func TestMountReadWriteMkdirThenCreate(t *testing.T) {
	store := seededStore()
	mnt := mountForTest(t, store, Options{ReadWrite: true, CacheTTL: 10 * time.Millisecond})

	group := filepath.Join(mnt, "newgroup")
	if err := os.Mkdir(group, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// The directory must survive long enough to be used — it exists only in
	// memory, so a kernel re-lookup after the entry timeout must still find it.
	time.Sleep(30 * time.Millisecond)
	if info, err := os.Stat(group); err != nil {
		t.Fatalf("stat after mkdir: %v", err)
	} else if !info.IsDir() {
		t.Fatal("mkdir did not produce a directory")
	}

	if err := os.WriteFile(filepath.Join(group, "thing"), []byte(`{"a":"b"}`), 0o600); err != nil {
		t.Fatalf("create inside new directory: %v", err)
	}
	store.mu.Lock()
	_, ok := store.secrets["newgroup/thing"]
	store.mu.Unlock()
	if !ok {
		t.Error("secret under the new directory did not reach the store at newgroup/thing")
	}
}

func TestMountAppendIsRejected(t *testing.T) {
	store := seededStore()
	mnt := mountForTest(t, store, Options{ReadWrite: true, CacheTTL: time.Second})

	f, err := os.OpenFile(filepath.Join(mnt, "gh"), os.O_WRONLY|os.O_APPEND, 0o600)
	if err == nil {
		f.Close()
		t.Fatal("opening a secret for append succeeded")
	}
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("error = %v, want EINVAL", err)
	}
}

// A descriptor opened read-only must never become the thing that writes to
// Vault. The kernel applies `open(O_TRUNC)` as a handle-less SETATTR, which
// has to be resolved by searching the node's open handles — so without the
// writable filter a reader holding the file open would have its buffer
// emptied and marked dirty, and its close() would push that emptiness up.
func TestMountReadOnlyHandleIsNotTruncatedByAWriter(t *testing.T) {
	store := seededStore()
	mnt := mountForTest(t, store, Options{ReadWrite: true, CacheTTL: time.Second})
	path := filepath.Join(mnt, "gh")

	reader, err := os.Open(path)
	if err != nil {
		t.Fatalf("open read-only: %v", err)
	}

	if err := os.WriteFile(path, []byte(`{"oauth_token":"gho_rotated"}`), 0o600); err != nil {
		reader.Close()
		t.Fatalf("write: %v", err)
	}
	// Closing the read-only descriptor must not produce a second write.
	if err := reader.Close(); err != nil {
		t.Fatalf("close read-only descriptor: %v", err)
	}

	if _, _, writes, _ := store.counts(); writes != 1 {
		t.Errorf("writes = %d, want exactly 1 — the read-only descriptor wrote too", writes)
	}
	store.mu.Lock()
	got := store.secrets["gh"]["oauth_token"]
	store.mu.Unlock()
	if got != "gho_rotated" {
		t.Errorf("stored oauth_token = %v, want gho_rotated", got)
	}
}

func TestReserveBufferEnforcesTheMountWideBudget(t *testing.T) {
	fsys := &filesystem{}

	if !fsys.reserveBuffer(0, maxBufferedBytes) {
		t.Fatal("reserving the whole budget was refused")
	}
	if fsys.reserveBuffer(0, 1) {
		t.Error("a reservation past the budget was allowed")
	}
	// A refused reservation must not leave the counter inflated, or the
	// mount would be permanently poisoned by one over-large write.
	if got := fsys.buffered.Load(); got != maxBufferedBytes {
		t.Errorf("buffered = %d after a refused reservation, want %d", got, int64(maxBufferedBytes))
	}

	fsys.releaseBuffer(maxBufferedBytes)
	if got := fsys.buffered.Load(); got != 0 {
		t.Errorf("buffered = %d after release, want 0", got)
	}
	// Shrinking is always allowed and gives the bytes back.
	if !fsys.reserveBuffer(0, 100) || !fsys.reserveBuffer(100, 20) {
		t.Fatal("shrinking a buffer was refused")
	}
	if got := fsys.buffered.Load(); got != 20 {
		t.Errorf("buffered = %d after shrinking to 20, want 20", got)
	}
}

// A KV folder has no independent existence — it is implied by the secrets
// beneath it — so rmdir on one reports ENOTEMPTY rather than pretending to
// delete something. An ephemeral directory from mkdir is the only kind that
// can actually be removed.
func TestMountRmdir(t *testing.T) {
	store := seededStore()
	mnt := mountForTest(t, store, Options{ReadWrite: true, CacheTTL: 10 * time.Millisecond})

	if err := os.Remove(filepath.Join(mnt, "databricks")); err == nil {
		t.Error("rmdir on a folder backed by secrets succeeded")
	} else if !errors.Is(err, syscall.ENOTEMPTY) {
		t.Errorf("error = %v, want ENOTEMPTY", err)
	}

	group := filepath.Join(mnt, "ephemeral")
	if err := os.Mkdir(group, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Remove(group); err != nil {
		t.Errorf("rmdir on an empty ephemeral directory: %v", err)
	}
	if _, err := os.Stat(group); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stat after rmdir = %v, want not-exist", err)
	}

	// Nothing about any of this may reach Vault: KVv2 has no directories.
	if _, _, writes, deletes := store.counts(); writes != 0 || deletes != 0 {
		t.Errorf("directory operations reached the store: %d writes, %d deletes", writes, deletes)
	}
}

// IsMounted is what `dotvault status` reports from, and it runs in a separate
// process from the daemon — so it has to be right about a live mount as well
// as an ordinary directory.
func TestIsMountedTracksTheMount(t *testing.T) {
	plain := t.TempDir()
	if mounted, err := IsMounted(plain); err != nil || mounted {
		t.Errorf("IsMounted(%q) = %v, %v; want false for an ordinary directory", plain, mounted, err)
	}

	mnt := mountForTest(t, seededStore(), Options{CacheTTL: time.Second})
	mounted, err := IsMounted(mnt)
	if err != nil {
		t.Fatalf("IsMounted: %v", err)
	}
	if !mounted {
		t.Error("IsMounted reported false for a live mount")
	}
}

// Fsync is what an editor calls before it renames its temp file into place;
// it has to apply the pending write rather than silently succeed.
func TestMountFsyncAppliesThePendingWrite(t *testing.T) {
	store := seededStore()
	mnt := mountForTest(t, store, Options{ReadWrite: true, CacheTTL: time.Second})

	f, err := os.OpenFile(filepath.Join(mnt, "gh"), os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	if _, err := f.Write([]byte(`{"oauth_token":"gho_fsynced"}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("fsync: %v", err)
	}

	// Before close: the write must already be in Vault.
	store.mu.Lock()
	got := store.secrets["gh"]["oauth_token"]
	store.mu.Unlock()
	if got != "gho_fsynced" {
		t.Errorf("stored oauth_token = %v after fsync, want gho_fsynced", got)
	}
}
