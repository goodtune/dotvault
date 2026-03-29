package daemon

import (
	"path/filepath"
	"testing"
)

func TestPIDFilePath(t *testing.T) {
	p := PIDFilePath()
	if p == "" {
		t.Fatal("PIDFilePath() returned empty string")
	}

	if filepath.Base(p) != "daemon.pid" {
		t.Errorf("PIDFilePath() = %q, want path ending with %q", p, "daemon.pid")
	}
}
