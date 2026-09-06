//go:build linux || freebsd || netbsd || openbsd || dragonfly || illumos || darwin

package clipboard

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestRunToolCmd_RealExec runs the real runToolCmd against a shell that
// copies stdin to a file, proving the stdin wiring and the no-output-pipe
// design actually deliver the text: dropping cmd.Stdin, or reintroducing
// output capture (which would hang on a forking tool), would fail here
// rather than only on a manual desktop test.
func TestRunToolCmd_RealExec(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh unavailable: %v", err)
	}
	out := filepath.Join(t.TempDir(), "clip.txt")
	text := "s3cr3t line1\nline2 with ünicode"
	if err := runToolCmd(sh, []string{"-c", `cat > "$0"`, out}, text); err != nil {
		t.Fatalf("runToolCmd: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != text {
		t.Errorf("tool received %q, want the text verbatim", got)
	}
}

func TestRunToolCmd_ReportsFailure(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh unavailable: %v", err)
	}
	if err := runToolCmd(sh, []string{"-c", "exit 3"}, "t"); err == nil {
		t.Fatal("expected an error from a failing tool")
	}
}
