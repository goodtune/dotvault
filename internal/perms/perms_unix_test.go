//go:build !windows

package perms

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsPrivateFile_Exact0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	os.WriteFile(path, []byte("secret"), 0o600)

	insecure, err := IsPrivateFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if insecure {
		t.Error("expected 0600 file to be reported as private")
	}
}

func TestIsPrivateFile_TooPermissive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	os.WriteFile(path, []byte("secret"), 0o644)

	insecure, err := IsPrivateFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !insecure {
		t.Error("expected 0644 file to be reported as insecure")
	}
}

func TestIsPrivateFile_Missing(t *testing.T) {
	_, err := IsPrivateFile(filepath.Join(t.TempDir(), "nonexistent"))
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestIsGroupWorldWritable_NotWritable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	os.WriteFile(path, []byte("data"), 0o640)

	insecure, err := IsGroupWorldWritable(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if insecure {
		t.Error("expected 0640 file to not be group/world writable")
	}
}

func TestIsGroupWorldWritable_GroupWritable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	os.WriteFile(path, []byte("data"), 0o600)
	os.Chmod(path, 0o660)

	insecure, err := IsGroupWorldWritable(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !insecure {
		t.Error("expected 0660 file to be reported as group writable")
	}
}

func TestIsGroupWorldWritable_WorldWritable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	os.WriteFile(path, []byte("data"), 0o600)
	os.Chmod(path, 0o606)

	insecure, err := IsGroupWorldWritable(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !insecure {
		t.Error("expected 0606 file to be reported as world writable")
	}
}
