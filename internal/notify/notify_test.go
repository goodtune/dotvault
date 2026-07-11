package notify

import (
	"runtime"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want Level
		ok   bool
	}{
		{"info", LevelInfo, true},
		{"INFO", LevelInfo, true},
		{"  warning  ", LevelWarning, true},
		{"error", LevelError, true},
		{"attention", LevelAttention, true},
		{"", "", false},
		{"critical", "", false},
		{"warn", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseLevel(tc.in)
			if tc.ok != (err == nil) {
				t.Fatalf("ParseLevel(%q) err = %v, want ok=%v", tc.in, err, tc.ok)
			}
			if tc.ok && got != tc.want {
				t.Errorf("ParseLevel(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if !tc.ok && err != nil && !strings.Contains(err.Error(), "info, warning, error, attention") {
				t.Errorf("error %q should list the accepted levels", err)
			}
		})
	}
}

func TestNewMessage_Validation(t *testing.T) {
	if _, err := NewMessage("bogus", "t", "b"); err == nil {
		t.Error("expected an error for an unknown level")
	}
	if _, err := NewMessage("info", "   ", "b"); err == nil {
		t.Error("expected an error for an empty title")
	}
	if _, err := NewMessage("info", "\x00\x07", "b"); err == nil {
		t.Error("expected an error for a title that is empty after control-char stripping")
	}
	m, err := NewMessage("Error", "  Hello  ", "  world  ")
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	if m.Level != LevelError {
		t.Errorf("level = %q, want error", m.Level)
	}
	if m.Title != "Hello" || m.Body != "world" {
		t.Errorf("got title=%q body=%q, want trimmed", m.Title, m.Body)
	}
}

func TestSanitize_StripsControlChars(t *testing.T) {
	// Newlines, tabs, NULs and other control bytes collapse to spaces so a
	// title/body can't break out of the single-line field or inject into the
	// exec/XML/AppleScript backends.
	got := sanitize("a\nb\tc\x00d\x1b[31m", maxTitleLen)
	if strings.ContainsAny(got, "\n\t\x00\x1b") {
		t.Errorf("sanitize left control chars: %q", got)
	}
	if got != "a b c d [31m" {
		t.Errorf("sanitize = %q, want %q", got, "a b c d [31m")
	}
}

func TestSanitize_Truncates(t *testing.T) {
	got := sanitize(strings.Repeat("x", maxTitleLen+50), maxTitleLen)
	if n := len([]rune(got)); n > maxTitleLen {
		t.Errorf("sanitize length = %d, want <= %d", n, maxTitleLen)
	}
}

func TestSanitize_TruncatesByRuneNotByte(t *testing.T) {
	// Multi-byte runes must be counted as one each, and truncation must not
	// split a rune (which would produce U+FFFD).
	got := sanitize(strings.Repeat("é", maxBodyLen+10), maxBodyLen)
	if n := len([]rune(got)); n > maxBodyLen {
		t.Errorf("rune count = %d, want <= %d", n, maxBodyLen)
	}
	if strings.ContainsRune(got, '�') {
		t.Error("truncation split a multi-byte rune")
	}
}

func TestLevels_CoversTable(t *testing.T) {
	// Levels() and the delivery table must stay in lockstep — every
	// advertised level must have delivery attributes, and vice versa.
	if len(Levels()) != len(levelTable) {
		t.Fatalf("Levels() has %d entries, table has %d", len(Levels()), len(levelTable))
	}
	for _, name := range Levels() {
		if _, ok := levelTable[Level(name)]; !ok {
			t.Errorf("level %q advertised but missing from the table", name)
		}
	}
}

func TestIconArg_PlatformBehaviour(t *testing.T) {
	// iconArg must never return a stock name on a platform that treats the
	// icon as a file path (macOS/Windows), and must return the level's stock
	// name on Linux/BSD. Assert against the current platform.
	for _, l := range levelOrder {
		got := iconArg(l)
		switch runtime.GOOS {
		case "linux", "freebsd", "netbsd", "openbsd", "dragonfly", "illumos":
			if got != levelTable[l].stockIcon {
				t.Errorf("iconArg(%q) = %q, want stock name %q", l, got, levelTable[l].stockIcon)
			}
		default:
			if got != "" {
				t.Errorf("iconArg(%q) = %q, want empty on this platform", l, got)
			}
		}
	}
}
