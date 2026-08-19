package vaultfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareMountpointCreatesOwnerOnlyDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mnt")
	if err := prepareMountpoint(dir); err != nil {
		t.Fatalf("prepareMountpoint: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("mountpoint is not a directory")
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("mode = %o, want 0700 — secrets are about to appear here", perm)
	}
}

func TestPrepareMountpointAcceptsAnExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := prepareMountpoint(dir); err != nil {
		t.Errorf("prepareMountpoint on an existing directory: %v", err)
	}
}

func TestPrepareMountpointRejectsAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	err := prepareMountpoint(path)
	if err == nil {
		t.Fatal("prepareMountpoint accepted a regular file")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("error = %v, want it to say the path is not a directory", err)
	}
}

// mount(2) resolves a symlink, so a symlinked mountpoint publishes the secrets
// wherever it points. Refuse rather than follow.
func TestPrepareMountpointRejectsASymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("setup: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	err := prepareMountpoint(link)
	if err == nil {
		t.Fatal("prepareMountpoint followed a symlinked mountpoint")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error = %v, want it to name the symlink", err)
	}
}

func TestNewServiceRejectsBadInput(t *testing.T) {
	if _, err := NewService(nil, Options{Mountpoint: "/tmp/x"}); err == nil {
		t.Error("NewService accepted a nil store")
	}
	if _, err := NewService(newMemStore(), Options{}); err == nil {
		t.Error("NewService accepted an empty mountpoint")
	}
}

func TestServiceStatusBeforeRun(t *testing.T) {
	svc, err := NewService(newMemStore(), Options{Mountpoint: "/tmp/x", ReadWrite: true})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	st := svc.Status()
	if st.State != StateStopped {
		t.Errorf("State = %q, want %q before Run", st.State, StateStopped)
	}
	if st.Mountpoint != "/tmp/x" || !st.ReadWrite {
		t.Errorf("Status = %+v, want it to echo the options", st)
	}
	if st.Error != "" {
		t.Errorf("Error = %q, want empty", st.Error)
	}
}

func TestAccessMode(t *testing.T) {
	if got := AccessMode(false); got != "read-only" {
		t.Errorf("AccessMode(false) = %q, want read-only", got)
	}
	if got := AccessMode(true); got != "read-write" {
		t.Errorf("AccessMode(true) = %q, want read-write", got)
	}
}
