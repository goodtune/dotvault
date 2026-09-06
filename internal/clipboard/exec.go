package clipboard

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// tool is one clipboard-writer candidate for the exec-based platforms: a
// binary name resolved via PATH plus its copy-to-clipboard arguments. Text is
// always delivered on stdin, never argv (argv is visible in process listings,
// and the payload is typically a credential).
type tool struct {
	name string
	args []string
}

// Seams for tests: lookPath resolves a candidate binary, runTool executes it.
// Kept in this non-build-tagged file so candidate ordering and error assembly
// are unit-tested on every platform, including the ones (Windows) whose real
// writer never execs.
var (
	lookPath = exec.LookPath
	runTool  = runToolCmd
)

func runToolCmd(path string, args []string, text string) error {
	cmd := exec.Command(path, args...)
	cmd.Stdin = strings.NewReader(text)
	// Deliberately no stdout/stderr capture: wl-copy and xclip fork a
	// long-lived child that owns the selection and inherits the output
	// descriptors, so capturing via pipes would block until the clipboard is
	// next replaced. With no pipes the fork inherits /dev/null and Run
	// returns as soon as the direct child exits.
	return cmd.Run()
}

// execSet tries each candidate in order and returns on the first success. A
// candidate that is not installed is skipped silently; one that runs but
// fails (e.g. wl-copy on an X11 session with no Wayland socket) records its
// error and falls through to the next. When nothing is installed the error
// names what was looked for, so the fix is actionable.
func execSet(candidates []tool, text string) error {
	var errs []error
	for _, t := range candidates {
		path, err := lookPath(t.name)
		if err != nil {
			continue
		}
		if err := runTool(path, t.args, text); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.name, err))
			continue
		}
		return nil
	}
	if len(errs) == 0 {
		names := make([]string, len(candidates))
		for i, t := range candidates {
			names[i] = t.name
		}
		return fmt.Errorf("no clipboard tool found (looked for %s)", strings.Join(names, ", "))
	}
	return errors.Join(errs...)
}
