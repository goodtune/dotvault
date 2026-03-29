package daemon

import (
	"testing"
)

func TestPIDFilePath(t *testing.T) {
	p := PIDFilePath()
	if p == "" {
		t.Error("PIDFilePath() returned empty string")
	}
}
