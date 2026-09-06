package urlallow

import "testing"

func TestValidate(t *testing.T) {
	cases := []struct {
		name, in string
		ok       bool
	}{
		{"https", "https://example.com/x", true},
		{"http", "http://example.com", true},
		{"trims", "  https://example.com  ", true},
		{"query preserved", "https://x/y?a=1&b=2", true},
		{"empty", "", false},
		{"file", "file:///etc/passwd", false},
		{"custom scheme", "vscode://open", false},
		{"javascript", "javascript:alert(1)", false},
		{"data", "data:text/html,x", false},
		{"no host", "https:///nohost", false},
		{"port but no host", "http://:80", false},
		{"bare path", "/relative", false},
		{"bare hostname", "example.com", false},
		{"userinfo", "https://user:pass@example.com", false},
		{"control char", "https://example.com/\x01", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := Validate(tc.in)
			if tc.ok != (err == nil) {
				t.Fatalf("Validate(%q) err = %v, want ok=%v", tc.in, err, tc.ok)
			}
			if tc.ok && u == nil {
				t.Errorf("Validate(%q) returned nil URL on success", tc.in)
			}
		})
	}
}

func TestValidate_PreservesQuerySeparators(t *testing.T) {
	// The canonical form must keep `&` and `$` in the query intact — the
	// Windows toast encoder (notify.safeToastArgs) relies on this so it can
	// XML-escape `&` back to a real separator rather than receiving a mangled
	// URL.
	u, err := Validate("https://x/y?a=1&b=2&c=$v")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	s := u.String()
	if s != "https://x/y?a=1&b=2&c=$v" {
		t.Errorf("canonical form = %q, want the query separators preserved", s)
	}
}
