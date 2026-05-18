package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/enrol"
)

func TestTuiModel_Navigation(t *testing.T) {
	m := &tuiModel{
		statuses: []enrol.Status{
			{Key: "a"},
			{Key: "b"},
			{Key: "c"},
		},
	}

	// up at the top is a no-op
	m.up()
	if m.cursor != 0 {
		t.Errorf("up at top: cursor = %d, want 0", m.cursor)
	}
	m.down()
	m.down()
	if m.cursor != 2 {
		t.Errorf("after 2x down: cursor = %d, want 2", m.cursor)
	}
	// down at the bottom is a no-op
	m.down()
	if m.cursor != 2 {
		t.Errorf("down at bottom: cursor = %d, want 2", m.cursor)
	}
	m.up()
	if m.cursor != 1 {
		t.Errorf("after up: cursor = %d, want 1", m.cursor)
	}
}

func TestTuiModel_Render(t *testing.T) {
	m := &tuiModel{
		statuses: []enrol.Status{
			{Key: "github", Engine: "github", EngineName: "GitHub", Enrolled: true},
			{Key: "ssh", Engine: "ssh", EngineName: "SSH"},
			{Key: "bad", Engine: "nope", Error: `unknown engine "nope"`},
		},
		cursor: 1,
	}
	var buf bytes.Buffer
	m.render(&buf)
	out := buf.String()

	for _, want := range []string{
		"dotvault — enrolments",
		"github",
		"GitHub",
		"enrolled",
		"ssh",
		"SSH",
		"not enrolled",
		"bad",
		`unknown engine "nope"`,
		"↑/↓ navigate",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q\noutput:\n%s", want, out)
		}
	}

	// The cursor (index 1, "ssh") should be inside the inverted region.
	invStart := strings.Index(out, "\x1b[7m")
	invEnd := strings.Index(out, "\x1b[0m")
	if invStart < 0 || invEnd < invStart {
		t.Fatalf("expected an inverted highlight in output:\n%s", out)
	}
	highlighted := out[invStart:invEnd]
	if !strings.Contains(highlighted, "ssh") {
		t.Errorf("highlighted region should contain %q, got %q", "ssh", highlighted)
	}
	if strings.Contains(highlighted, "github") {
		t.Errorf("highlighted region should not contain %q, got %q", "github", highlighted)
	}
}

// pipeKeys writes b to a pipe and returns the read side as *os.File so it
// can drive readSingleKey, which expects a real fd-backed reader.
func pipeKeys(t *testing.T, b []byte) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	go func() {
		defer w.Close()
		_, _ = w.Write(b)
	}()
	return r
}

func TestReadSingleKey(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  keyKind
	}{
		{"up", []byte{0x1b, '[', 'A'}, keyUp},
		{"down", []byte{0x1b, '[', 'B'}, keyDown},
		{"enter CR", []byte{'\r'}, keyEnter},
		{"enter LF", []byte{'\n'}, keyEnter},
		{"q", []byte{'q'}, keyQuit},
		{"Q", []byte{'Q'}, keyQuit},
		{"esc alone", []byte{0x1b}, keyQuit},
		{"ctrl-c", []byte{0x03}, keyQuit},
		// EOF on the pipe collapses to quit so the picker exits cleanly
		// when the user closes the terminal session.
		{"eof", nil, keyQuit},
		// Unknown sequences (e.g. right arrow) collapse to keyNone.
		{"right arrow", []byte{0x1b, '[', 'C'}, keyNone},
		{"other char", []byte{'x'}, keyNone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := pipeKeys(t, tc.input)
			got, err := readSingleKey(r)
			if err != nil && err != io.EOF {
				t.Fatalf("readSingleKey: %v", err)
			}
			if got != tc.want {
				t.Errorf("readSingleKey = %v, want %v", got, tc.want)
			}
		})
	}
}
