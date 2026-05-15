package loginsuppress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWindow(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		want    time.Duration
		wantErr bool
	}{
		{"default", "", DefaultHours * time.Hour, false},
		{"one hour", "1", time.Hour, false},
		{"large", "240", 240 * time.Hour, false},
		{"zero", "0", 0, true},
		{"negative", "-1", 0, true},
		{"non-integer", "1.5", 0, true},
		{"alpha", "abc", 0, true},
		{"empty-string-spaces", "  ", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envHours, tc.value)
			got, err := Window()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Window(%q) = %v, want error", tc.value, got)
				}
				if !strings.Contains(err.Error(), "DOTVAULT_SUPPRESS_HOURS") {
					t.Errorf("error %q should mention DOTVAULT_SUPPRESS_HOURS", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Window(%q): unexpected error: %v", tc.value, err)
			}
			if got != tc.want {
				t.Errorf("Window(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestPath_OverrideEnv(t *testing.T) {
	override := filepath.Join(t.TempDir(), "custom-marker")
	t.Setenv(envMarker, override)
	if got := Path(); got != override {
		t.Errorf("Path() = %q, want %q", got, override)
	}
}

func TestPath_XDGStateHome(t *testing.T) {
	unsetenv(t, envMarker)
	tmp := t.TempDir()
	t.Setenv("XDG_STATE_HOME", tmp)
	want := filepath.Join(tmp, dirName, fileName)
	if got := Path(); got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
}

func TestPath_HomeFallback(t *testing.T) {
	unsetenv(t, envMarker)
	unsetenv(t, "XDG_STATE_HOME")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory available")
	}
	want := filepath.Join(home, ".local", "state", dirName, fileName)
	if got := Path(); got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
}

// unsetenv removes an environment variable for the duration of the test
// and restores its original value on cleanup. t.Setenv does not support
// "unset," so we replicate its restore semantics by hand.
func unsetenv(t *testing.T, key string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unsetenv %s: %v", key, err)
	}
	t.Cleanup(func() {
		if had {
			os.Setenv(key, prev)
		} else {
			os.Unsetenv(key)
		}
	})
}

func TestIsFresh(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	window := 6 * time.Hour

	t.Run("missing", func(t *testing.T) {
		if IsFresh(filepath.Join(dir, "nope"), window, now) {
			t.Error("missing marker should not be fresh")
		}
	})

	t.Run("fresh", func(t *testing.T) {
		writeMarker(t, marker, now.Add(-1*time.Hour))
		if !IsFresh(marker, window, now) {
			t.Error("marker 1h old with 6h window should be fresh")
		}
	})

	t.Run("stale", func(t *testing.T) {
		writeMarker(t, marker, now.Add(-7*time.Hour))
		if IsFresh(marker, window, now) {
			t.Error("marker 7h old with 6h window should be stale")
		}
	})

	t.Run("boundary-exact", func(t *testing.T) {
		// mtime exactly window-old: age == window, not strictly less than
		// window, so treated as stale.
		writeMarker(t, marker, now.Add(-window))
		if IsFresh(marker, window, now) {
			t.Error("marker at exact window boundary should be stale")
		}
	})

	t.Run("future-mtime", func(t *testing.T) {
		writeMarker(t, marker, now.Add(2*time.Hour))
		if IsFresh(marker, window, now) {
			t.Error("future mtime should be treated as stale")
		}
	})

	t.Run("empty-path", func(t *testing.T) {
		if IsFresh("", window, now) {
			t.Error("empty path should not be fresh")
		}
	})
}

func TestRefresh_CreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "c", "marker")
	if err := Refresh(nested); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	info, err := os.Stat(nested)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if time.Since(info.ModTime()) > 5*time.Second {
		t.Errorf("marker mtime not recent: %v", info.ModTime())
	}
}

func TestRefresh_UpdatesExistingMtime(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	old := time.Now().Add(-24 * time.Hour)
	writeMarker(t, marker, old)
	if err := Refresh(marker); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	info, err := os.Stat(marker)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.ModTime().After(old) {
		t.Errorf("mtime not bumped: was %v, now %v", old, info.ModTime())
	}
}

func TestRefresh_EmptyPath(t *testing.T) {
	if err := Refresh(""); err == nil {
		t.Error("Refresh(\"\") should error")
	}
}

func TestSuppressionEndToEnd(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	window := 6 * time.Hour

	// First call: stale -> would proceed, then refresh.
	if IsFresh(marker, window, time.Now()) {
		t.Fatal("fresh before first refresh")
	}
	if err := Refresh(marker); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// Second call: fresh -> suppress.
	if !IsFresh(marker, window, time.Now()) {
		t.Error("marker should be fresh immediately after Refresh")
	}
}

func writeMarker(t *testing.T, path string, mtime time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}
