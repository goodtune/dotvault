package sync

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStateStore_LoadEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := NewStateStore(path)
	err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(s.Rules()) != 0 {
		t.Errorf("expected empty rules, got %d", len(s.Rules()))
	}
}

func TestStateStore_GetSetSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := NewStateStore(path)
	s.Load()

	now := time.Now().Truncate(time.Second)
	s.Set("gh", RuleState{
		VaultVersion: 3,
		LastSynced:   now,
		FileChecksum: "sha256:abcdef",
	})

	// Save
	err := s.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load into new store
	s2 := NewStateStore(path)
	s2.Load()

	rs := s2.Get("gh")
	if rs.VaultVersion != 3 {
		t.Errorf("VaultVersion = %d, want 3", rs.VaultVersion)
	}
	if !rs.LastSynced.Equal(now) {
		t.Errorf("LastSynced = %v, want %v", rs.LastSynced, now)
	}
	if rs.FileChecksum != "sha256:abcdef" {
		t.Errorf("FileChecksum = %q, want %q", rs.FileChecksum, "sha256:abcdef")
	}
}

func TestStateStore_GetMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := NewStateStore(path)
	s.Load()

	rs := s.Get("nonexistent")
	if rs.VaultVersion != 0 {
		t.Errorf("VaultVersion = %d, want 0 for missing rule", rs.VaultVersion)
	}
}

func TestFileChecksum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	writeFile(t, path, "hello world\n")

	sum, err := FileChecksum(path)
	if err != nil {
		t.Fatalf("FileChecksum: %v", err)
	}
	if sum == "" {
		t.Error("checksum is empty")
	}
	// Same content = same checksum
	sum2, _ := FileChecksum(path)
	if sum != sum2 {
		t.Errorf("checksums differ for same content: %q vs %q", sum, sum2)
	}
}

func TestFileChecksum_Missing(t *testing.T) {
	sum, err := FileChecksum("/nonexistent/file")
	if err != nil {
		t.Fatalf("FileChecksum should not error for missing file: %v", err)
	}
	if sum != "" {
		t.Errorf("checksum = %q, want empty for missing file", sum)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}
