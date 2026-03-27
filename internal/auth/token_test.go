package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadTokenFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".vault-token")
	os.WriteFile(path, []byte("s.test-token-value\n"), 0600)

	token, err := ReadTokenFile(path)
	if err != nil {
		t.Fatalf("ReadTokenFile: %v", err)
	}
	if token != "s.test-token-value" {
		t.Errorf("token = %q, want %q", token, "s.test-token-value")
	}
}

func TestReadTokenFromFileMissing(t *testing.T) {
	token, err := ReadTokenFile("/nonexistent/path/.vault-token")
	if err != nil {
		t.Fatalf("ReadTokenFile should not error for missing file: %v", err)
	}
	if token != "" {
		t.Errorf("token = %q, want empty for missing file", token)
	}
}

func TestReadTokenFromEnv(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "env-token-value")
	token := ReadTokenEnv()
	if token != "env-token-value" {
		t.Errorf("token = %q, want %q", token, "env-token-value")
	}
}

func TestWriteTokenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".vault-token")

	err := WriteTokenFile(path, "new-token-value")
	if err != nil {
		t.Fatalf("WriteTokenFile: %v", err)
	}

	// Read it back
	data, _ := os.ReadFile(path)
	if string(data) != "new-token-value" {
		t.Errorf("file content = %q, want %q", data, "new-token-value")
	}

	// Check permissions
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Errorf("permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestResolveToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".vault-token")

	// No file, no env — empty
	token := ResolveToken(path)
	if token != "" {
		t.Errorf("token = %q, want empty", token)
	}

	// File exists
	os.WriteFile(path, []byte("file-token"), 0600)
	token = ResolveToken(path)
	if token != "file-token" {
		t.Errorf("token = %q, want %q", token, "file-token")
	}

	// Env takes precedence
	t.Setenv("VAULT_TOKEN", "env-token")
	token = ResolveToken(path)
	if token != "env-token" {
		t.Errorf("token = %q, want %q (env should take precedence)", token, "env-token")
	}
}
