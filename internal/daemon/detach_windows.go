//go:build windows

package daemon

import (
	"os/exec"
	"syscall"
)

// detach configures the command to run without a console window on Windows.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x00000008, // CREATE_NO_WINDOW
	}
}
