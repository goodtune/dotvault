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
	if _, err := NewMessage("bogus", "t", "b", ""); err == nil {
		t.Error("expected an error for an unknown level")
	}
	if _, err := NewMessage("info", "   ", "b", ""); err == nil {
		t.Error("expected an error for an empty title")
	}
	if _, err := NewMessage("info", "\x00\x07", "b", ""); err == nil {
		t.Error("expected an error for a title that is empty after control-char stripping")
	}
	m, err := NewMessage("Error", "  Hello  ", "  world  ", "")
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
	// Use a 3-byte rune with a cap that is NOT a multiple of 3, so a
	// regression to byte-slicing would land mid-rune and produce U+FFFD (and
	// a rune count above the cap). "あ" is 3 bytes; maxBodyLen (1000) is not a
	// multiple of 3.
	if maxBodyLen%3 == 0 {
		t.Fatalf("test assumes maxBodyLen (%d) is not a multiple of 3", maxBodyLen)
	}
	got := sanitize(strings.Repeat("あ", maxBodyLen+10), maxBodyLen)
	if n := len([]rune(got)); n > maxBodyLen {
		t.Errorf("rune count = %d, want <= %d", n, maxBodyLen)
	}
	if strings.ContainsRune(got, '�') {
		t.Error("truncation split a multi-byte rune")
	}
}

func TestSanitize_TrimsWhitespaceAtTruncationBoundary(t *testing.T) {
	// A space sitting exactly at the truncation boundary must be trimmed, so
	// the result never ends in dangling whitespace.
	in := strings.Repeat("x", maxTitleLen-1) + " " + strings.Repeat("y", 10)
	got := sanitize(in, maxTitleLen)
	if strings.HasSuffix(got, " ") {
		t.Errorf("sanitize left trailing whitespace after truncation: %q", got)
	}
	if n := len([]rune(got)); n > maxTitleLen {
		t.Errorf("rune count = %d, want <= %d", n, maxTitleLen)
	}
}

func TestSanitize_NeutralizesToastMetachars(t *testing.T) {
	// beeep's Windows toast backends interpolate title/body into an XML CDATA
	// and a PowerShell expandable here-string. sanitize must defuse the
	// breakout sequences so neither an injected toast-XML action nor a
	// PowerShell subexpression survives.
	cases := []struct {
		name, in string
		// substrings that must NOT survive verbatim
		absent []string
	}{
		{"cdata terminator", "boom]]><action/>", []string{"]]>"}},
		{"ps subexpression", "hi $(calc.exe)", []string{"$("}},
		{"ps brace var", "x ${env:PATH} y", []string{"${"}},
		{"ps bare var", "value is $env:SECRET", []string{"$env"}},
		{"ps digit var", "pay $5now", []string{"$5"}},
		{"ps double dollar", "$$", []string{"$$"}},
		{"backtick", "a`b`c", []string{"`"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitize(tc.in, maxTitleLen)
			for _, bad := range tc.absent {
				if strings.Contains(got, bad) {
					t.Errorf("sanitize(%q) = %q still contains %q", tc.in, got, bad)
				}
			}
		})
	}
}

func TestSanitize_PreservesBenignDollar(t *testing.T) {
	// A trailing or space-separated `$` is not an expansion introducer and
	// must be preserved verbatim, so legitimate text isn't mangled.
	for _, in := range []string{"cost: $", "price $ each"} {
		if got := sanitize(in, maxTitleLen); got != in {
			t.Errorf("sanitize(%q) = %q, want it preserved", in, got)
		}
	}
}

func TestValidateActionURL(t *testing.T) {
	cases := []struct {
		name, in string
		ok       bool
	}{
		{"empty is allowed", "", true},
		{"https", "https://ci.example/build/42", true},
		{"http", "http://x.example", true},
		{"trims", "  https://x.example  ", true},
		{"file scheme", "file:///etc/passwd", false},
		{"custom scheme", "vscode://open", false},
		{"no host", "https:///nohost", false},
		{"bare path", "/relative", false},
		{"userinfo", "https://user:pass@x.example", false},
		{"control char", "https://x.example/\x01", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateActionURL(tc.in)
			if tc.ok != (err == nil) {
				t.Fatalf("validateActionURL(%q) err = %v, want ok=%v", tc.in, err, tc.ok)
			}
			if tc.ok && tc.in != "" && got == "" {
				t.Errorf("validateActionURL(%q) returned empty for a valid URL", tc.in)
			}
		})
	}
}

func TestNewMessage_ActionURL(t *testing.T) {
	m, err := NewMessage("info", "t", "b", "https://x.example/go")
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	if m.ActionURL != "https://x.example/go" {
		t.Errorf("ActionURL = %q, want the validated URL", m.ActionURL)
	}
	if _, err := NewMessage("info", "t", "b", "file:///etc"); err == nil {
		t.Error("expected an error for a non-http(s) action URL")
	}
}

func TestNewMessage_ActionURLPreservesQueryChars(t *testing.T) {
	// The stored action URL must keep `&` and `$` in the query intact:
	// safeToastArgs's XML-escaping of `&` back to a real separator depends on
	// receiving an unmangled URL from NewMessage → validateActionURL.
	in := "https://ci.example/build?a=1&b=2&t=$rev"
	m, err := NewMessage("info", "t", "b", in)
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	if m.ActionURL != in {
		t.Errorf("ActionURL = %q, want %q (query separators preserved)", m.ActionURL, in)
	}
}

func TestActionBody(t *testing.T) {
	cases := []struct {
		body, url, want string
	}{
		{"", "", ""},
		{"detail", "", "detail"},
		{"", "https://x/y", "https://x/y"},
		{"detail", "https://x/y", "detail https://x/y"},
	}
	for _, tc := range cases {
		got := actionBody(Message{Body: tc.body, ActionURL: tc.url})
		if got != tc.want {
			t.Errorf("actionBody(body=%q,url=%q) = %q, want %q", tc.body, tc.url, got, tc.want)
		}
	}
}

func TestSafeToastArgs(t *testing.T) {
	// The launch attribute is an unescaped XML attribute embedded in a
	// PowerShell expandable here-string. `& " < >` must XML-escape (so they
	// decode back — keeping `&` query separators intact); `$` and backtick must
	// percent-encode (the here-string expands them before XML parsing).
	got := safeToastArgs(`https://x/a?b=1&c="<>"$v` + "`z")
	for _, bad := range []string{"&c=", `"`, "<", ">", "$v", "`"} {
		if strings.Contains(got, bad) {
			t.Errorf("safeToastArgs left %q in %q", bad, got)
		}
	}
	if !strings.Contains(got, "&amp;") {
		t.Errorf("safeToastArgs should XML-escape & (got %q)", got)
	}
	if !strings.Contains(got, "%24") || !strings.Contains(got, "%60") {
		t.Errorf("safeToastArgs should percent-encode $ and backtick (got %q)", got)
	}
	// A plain URL with no dangerous characters is untouched.
	plain := "https://ci.example/build/42"
	if safeToastArgs(plain) != plain {
		t.Errorf("safeToastArgs mangled a benign URL: %q", safeToastArgs(plain))
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
