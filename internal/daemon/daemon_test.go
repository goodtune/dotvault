package daemon

import (
	"os"
	"testing"
)

func TestIsDaemonized(t *testing.T) {
	// Default: not daemonized.
	os.Unsetenv(envDaemonized)
	if IsDaemonized() {
		t.Error("expected IsDaemonized()=false when env is unset")
	}

	// Set the env var.
	t.Setenv(envDaemonized, "1")
	if !IsDaemonized() {
		t.Error("expected IsDaemonized()=true when env is set to 1")
	}

	// Wrong value.
	t.Setenv(envDaemonized, "0")
	if IsDaemonized() {
		t.Error("expected IsDaemonized()=false when env is set to 0")
	}
}

func TestFilterFlag(t *testing.T) {
	tests := []struct {
		name string
		args []string
		flag string
		want []string
	}{
		{"removes flag", []string{"run", "--daemon", "--config", "x"}, "--daemon", []string{"run", "--config", "x"}},
		{"no match", []string{"run", "--config", "x"}, "--daemon", []string{"run", "--config", "x"}},
		{"empty", nil, "--daemon", []string{}},
		{"multiple", []string{"--daemon", "--daemon"}, "--daemon", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterFlag(tt.args, tt.flag)
			if len(got) != len(tt.want) {
				t.Fatalf("filterFlag(%v, %q) = %v, want %v", tt.args, tt.flag, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("filterFlag(%v, %q)[%d] = %q, want %q", tt.args, tt.flag, i, got[i], tt.want[i])
				}
			}
		})
	}
}
