package enrol

import (
	"os/exec"
	"strings"
)

func tryClipboard(text string) {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(text)
	_ = cmd.Run()
}
