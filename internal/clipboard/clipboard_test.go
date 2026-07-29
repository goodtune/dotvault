package clipboard

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateText(t *testing.T) {
	cases := []struct {
		name    string
		text    string
		wantErr bool
	}{
		{"token", "ghp_abc123", false},
		{"multiline pem", "-----BEGIN KEY-----\nabc\n-----END KEY-----\n", false},
		{"unicode", "pässwörd → ok", false},
		{"at the cap", strings.Repeat("a", MaxTextLen), false},
		{"empty", "", true},
		{"over the cap", strings.Repeat("a", MaxTextLen+1), true},
		{"interior NUL", "abc\x00def", true},
		{"invalid utf-8", "abc\xff\xfe", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateText(tc.text)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateText(%d bytes) error = %v, wantErr %v", len(tc.text), err, tc.wantErr)
			}
		})
	}
}

// Error messages must never carry the text itself — it is typically a
// credential. Exercise every rejecting branch with a recognisable payload.
func TestValidateText_ErrorsNeverIncludeText(t *testing.T) {
	for _, text := range []string{
		strings.Repeat("SECRETVALUE", MaxTextLen/10),
		"SECRETVALUE\x00",
		"SECRETVALUE\xff\xfe",
	} {
		if err := ValidateText(text); err == nil {
			t.Fatal("expected a validation error")
		} else if strings.Contains(err.Error(), "SECRETVALUE") {
			t.Errorf("error %q includes the clipboard text", err.Error())
		}
	}
}

// withExecSeams installs fake lookPath/runTool and restores them on cleanup.
func withExecSeams(t *testing.T, look func(string) (string, error), run func(string, []string, string) error) {
	t.Helper()
	prevLook, prevRun := lookPath, runTool
	lookPath, runTool = look, run
	t.Cleanup(func() { lookPath, runTool = prevLook, prevRun })
}

func TestExecSet_FirstAvailableToolWins(t *testing.T) {
	var ran []string
	withExecSeams(t,
		func(name string) (string, error) {
			if name == "wl-copy" {
				return "", errors.New("not found")
			}
			return "/usr/bin/" + name, nil
		},
		func(path string, args []string, text string) error {
			ran = append(ran, path)
			if text != "the text" {
				t.Errorf("tool got text %q, want it verbatim", text)
			}
			return nil
		},
	)
	candidates := []tool{{name: "wl-copy"}, {name: "xclip", args: []string{"-selection", "clipboard"}}, {name: "xsel"}}
	if err := execSet(candidates, "the text"); err != nil {
		t.Fatalf("execSet: %v", err)
	}
	if len(ran) != 1 || ran[0] != "/usr/bin/xclip" {
		t.Errorf("ran %v, want exactly the first available tool (xclip)", ran)
	}
}

func TestExecSet_FallsThroughOnRunFailure(t *testing.T) {
	// wl-copy is installed but fails (e.g. an X11 session with no Wayland
	// socket); xclip must still be tried and succeed.
	withExecSeams(t,
		func(name string) (string, error) { return "/usr/bin/" + name, nil },
		func(path string, args []string, text string) error {
			if strings.HasSuffix(path, "wl-copy") {
				return errors.New("no wayland display")
			}
			return nil
		},
	)
	if err := execSet([]tool{{name: "wl-copy"}, {name: "xclip"}}, "t"); err != nil {
		t.Fatalf("execSet: %v", err)
	}
}

func TestExecSet_NoToolInstalled(t *testing.T) {
	withExecSeams(t,
		func(name string) (string, error) { return "", errors.New("not found") },
		func(path string, args []string, text string) error {
			t.Error("runTool called with nothing installed")
			return nil
		},
	)
	err := execSet([]tool{{name: "wl-copy"}, {name: "xclip"}}, "t")
	if err == nil {
		t.Fatal("expected an error with no tool installed")
	}
	for _, name := range []string{"wl-copy", "xclip"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name the missing tool %s", err.Error(), name)
		}
	}
}

func TestExecSet_AllToolsFail(t *testing.T) {
	withExecSeams(t,
		func(name string) (string, error) { return "/usr/bin/" + name, nil },
		func(path string, args []string, text string) error { return errors.New("exit status 1") },
	)
	err := execSet([]tool{{name: "xclip"}, {name: "xsel"}}, "t")
	if err == nil {
		t.Fatal("expected an error when every tool fails")
	}
	if !strings.Contains(err.Error(), "xclip") || !strings.Contains(err.Error(), "xsel") {
		t.Errorf("error %q should name each failed tool", err.Error())
	}
}

func TestSet_ValidatesBeforeWriting(t *testing.T) {
	withExecSeams(t,
		func(name string) (string, error) { return "/usr/bin/" + name, nil },
		func(path string, args []string, text string) error {
			t.Error("platform writer called for invalid text")
			return nil
		},
	)
	if err := Set(""); err == nil {
		t.Fatal("expected a validation error for empty text")
	}
}
