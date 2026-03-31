package enrol

import (
	"os/exec"
	"strings"
)

func tryClipboard(text string) {
	for _, tool := range []string{"xclip", "xsel"} {
		if path, err := exec.LookPath(tool); err == nil {
			var args []string
			if tool == "xclip" {
				args = []string{"-selection", "clipboard"}
			} else {
				args = []string{"--clipboard", "--input"}
			}
			cmd := exec.Command(path, args...)
			cmd.Stdin = strings.NewReader(text)
			if cmd.Run() == nil {
				return
			}
		}
	}
}
