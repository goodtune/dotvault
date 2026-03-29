//go:build !windows

package daemon

import (
	"os/exec"
	"syscall"
)

// detach configures the command to run in a new session, fully detached from
// the controlling terminal.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
}
