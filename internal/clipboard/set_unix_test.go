//go:build linux || freebsd || netbsd || openbsd || dragonfly || illumos

package clipboard

import (
	"errors"
	"testing"
)

// The production candidate list is what actually ships — a typo in a tool
// name or its copy-to-clipboard arguments would otherwise only surface on a
// manual desktop test. Assert the names, the order (Wayland-native first,
// X11 fallthrough), and each tool's exact arguments through the real
// platformSet.
func TestPlatformSet_CandidateListAndArgs(t *testing.T) {
	var looked []string
	wantArgs := map[string][]string{
		"wl-copy": nil,
		"xclip":   {"-selection", "clipboard"},
		"xsel":    {"--clipboard", "--input"},
	}
	withExecSeams(t,
		func(name string) (string, error) {
			looked = append(looked, name)
			return "", errors.New("not found") // exhaust every candidate
		},
		func(path string, args []string, text string) error { return nil },
	)
	if err := platformSet("t"); err == nil {
		t.Fatal("expected an error with no tool installed")
	}
	wantOrder := []string{"wl-copy", "xclip", "xsel"}
	if len(looked) != len(wantOrder) {
		t.Fatalf("looked up %v, want %v", looked, wantOrder)
	}
	for i, name := range wantOrder {
		if looked[i] != name {
			t.Fatalf("candidate %d = %q, want %q (order matters: Wayland first)", i, looked[i], name)
		}
	}

	// Second pass: everything installed; verify the winning tool's args.
	for _, tool := range wantOrder {
		tool := tool
		var gotArgs []string
		ran := false
		withExecSeams(t,
			func(name string) (string, error) {
				if name == tool {
					return "/usr/bin/" + name, nil
				}
				return "", errors.New("not found")
			},
			func(path string, args []string, text string) error {
				ran = true
				gotArgs = args
				return nil
			},
		)
		if err := platformSet("t"); err != nil {
			t.Fatalf("platformSet with only %s installed: %v", tool, err)
		}
		if !ran {
			t.Fatalf("%s was not run", tool)
		}
		want := wantArgs[tool]
		if len(gotArgs) != len(want) {
			t.Fatalf("%s args = %v, want %v", tool, gotArgs, want)
		}
		for i := range want {
			if gotArgs[i] != want[i] {
				t.Errorf("%s args = %v, want %v", tool, gotArgs, want)
			}
		}
	}
}
