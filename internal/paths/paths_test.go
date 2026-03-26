package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("cannot get home dir: %v", err)
	}

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "tilde prefix",
			input: "~/.config/gh/hosts.yml",
			want:  filepath.Join(home, ".config/gh/hosts.yml"),
		},
		{
			name:  "tilde alone",
			input: "~",
			want:  home,
		},
		{
			name:  "no tilde",
			input: "/etc/foo/bar",
			want:  "/etc/foo/bar",
		},
		{
			name:  "tilde in middle not expanded",
			input: "/foo/~/bar",
			want:  "/foo/~/bar",
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandHome(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("ExpandHome(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSystemConfigPath(t *testing.T) {
	path := SystemConfigPath()
	if path == "" {
		t.Fatal("SystemConfigPath() returned empty string")
	}
	// Just verify it ends with the expected filename
	if filepath.Base(path) != "config.yaml" {
		t.Errorf("SystemConfigPath() = %q, want basename config.yaml", path)
	}
}

func TestCacheDir(t *testing.T) {
	dir := CacheDir()
	if dir == "" {
		t.Fatal("CacheDir() returned empty string")
	}
	// Should contain "dotvault" somewhere in the path
	if filepath.Base(dir) != "dotvault" {
		t.Errorf("CacheDir() = %q, want dir ending in dotvault", dir)
	}
}

func TestLogDir(t *testing.T) {
	dir := LogDir()
	if dir == "" {
		t.Fatal("LogDir() returned empty string")
	}
}

func TestVaultTokenPath(t *testing.T) {
	home, _ := os.UserHomeDir()
	path := VaultTokenPath()
	want := filepath.Join(home, ".vault-token")
	if path != want {
		t.Errorf("VaultTokenPath() = %q, want %q", path, want)
	}
}

func TestUsername(t *testing.T) {
	name, err := Username()
	if err != nil {
		t.Fatalf("Username() error: %v", err)
	}
	if name == "" {
		t.Fatal("Username() returned empty string")
	}
	// Should not contain backslash (domain prefix stripped)
	for _, c := range name {
		if c == '\\' {
			t.Errorf("Username() = %q, contains backslash (domain not stripped)", name)
		}
	}
}

func TestPlatformPaths(t *testing.T) {
	// Verify paths are appropriate for current OS
	switch runtime.GOOS {
	case "darwin":
		if got := CacheDir(); filepath.Dir(got) != filepath.Join(testHomeDir(t), "Library/Caches") {
			t.Errorf("CacheDir() on darwin = %q, want parent ~/Library/Caches", got)
		}
	case "linux":
		if got := CacheDir(); filepath.Dir(got) != filepath.Join(testHomeDir(t), ".cache") {
			t.Errorf("CacheDir() on linux = %q, want parent ~/.cache", got)
		}
	}
}

func testHomeDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("cannot get home dir: %v", err)
	}
	return home
}
