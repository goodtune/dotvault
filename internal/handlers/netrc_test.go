package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetrcHandler_ReadExisting(t *testing.T) {
	h := &NetrcHandler{}
	data, err := h.Read("testdata/existing.netrc")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if data == nil {
		t.Fatal("Read() returned nil")
	}
}

func TestNetrcHandler_ReadMissing(t *testing.T) {
	h := &NetrcHandler{}
	data, err := h.Read("testdata/nonexistent.netrc")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if data == nil {
		t.Fatal("Read() returned nil for missing file")
	}
}

func TestNetrcHandler_MergeUpdatesExisting(t *testing.T) {
	h := &NetrcHandler{}

	existing, _ := h.Read("testdata/existing.netrc")

	// Vault data: each key is a machine name, value is JSON with login+password
	incoming := NetrcVaultData{
		"api.github.com": {Login: "goodtune", Password: "ghx_proxyToken"},
		"example.com":    {Login: "gary", Password: "hunter2"},
		"newhost.com":    {Login: "newuser", Password: "newpass"},
	}

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "merged.netrc")
	if err := h.Write(outPath, merged, 0600); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	got, _ := os.ReadFile(outPath)
	s := string(got)

	// Updated entries
	if !strings.Contains(s, "goodtune") {
		t.Errorf("missing updated login 'goodtune':\n%s", s)
	}
	if !strings.Contains(s, "ghx_proxyToken") {
		t.Errorf("missing updated password:\n%s", s)
	}
	if !strings.Contains(s, "hunter2") {
		t.Errorf("missing updated password 'hunter2':\n%s", s)
	}

	// New entry appended
	if !strings.Contains(s, "newhost.com") {
		t.Errorf("missing new machine 'newhost.com':\n%s", s)
	}

	// Old credentials gone
	if strings.Contains(s, "old-token") {
		t.Errorf("still contains old password:\n%s", s)
	}
}

func TestNetrcHandler_MergePreservesUnmanagedEntries(t *testing.T) {
	h := &NetrcHandler{}

	existing, _ := h.Read("testdata/existing.netrc")

	// Only update one machine — the other should remain untouched
	incoming := NetrcVaultData{
		"api.github.com": {Login: "updated", Password: "updated-pass"},
	}

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.netrc")
	h.Write(outPath, merged, 0600)

	got, _ := os.ReadFile(outPath)
	s := string(got)

	// Unmanaged entry preserved
	if !strings.Contains(s, "example.com") {
		t.Errorf("unmanaged machine 'example.com' was removed:\n%s", s)
	}
	if !strings.Contains(s, "existing-pass") {
		t.Errorf("unmanaged entry password was changed:\n%s", s)
	}
}

func TestNetrcHandler_WritePermissions(t *testing.T) {
	h := &NetrcHandler{}
	existing, _ := h.Read("testdata/existing.netrc")

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.netrc")
	h.Write(outPath, existing, 0600)

	info, _ := os.Stat(outPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestNetrcHandler_MergeFromEmptyFile(t *testing.T) {
	h := &NetrcHandler{}

	existing, _ := h.Read("testdata/nonexistent.netrc")
	incoming := NetrcVaultData{
		"newhost.com": {Login: "user", Password: "pass"},
	}

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.netrc")
	h.Write(outPath, merged, 0600)

	got, _ := os.ReadFile(outPath)
	s := string(got)

	if !strings.Contains(s, "newhost.com") {
		t.Errorf("missing new machine:\n%s", s)
	}
}
