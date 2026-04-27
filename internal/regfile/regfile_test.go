package regfile

import (
	"bytes"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

func mustGenerate(t *testing.T, cfg *config.Config) string {
	t.Helper()
	got, err := GenerateText(cfg)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	return got
}

func TestGenerateMinimal(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Sync:  config.SyncConfig{RawInterval: "15m"},
	}

	got := mustGenerate(t, cfg)

	wantContains := []string{
		"Windows Registry Editor Version 5.00\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\dotvault]\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\dotvault\\Vault]\r\n",
		"\"Address\"=\"https://vault.example.com:8200\"\r\n",
		"\"DisableTokenRenewal\"=dword:00000000\r\n",
		"\"TLSSkipVerify\"=dword:00000000\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\dotvault\\Sync]\r\n",
		"\"Interval\"=\"15m\"\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\dotvault\\Web]\r\n",
		"\"Enabled\"=dword:00000000\r\n",
	}
	for _, want := range wantContains {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, got)
		}
	}
}

func TestGenerateRulesAndOAuth(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:        "gh",
				Description: "GitHub host config",
				VaultKey:    "gh",
				Target: config.Target{
					Path:   "~/.config/gh/hosts.yml",
					Format: "yaml",
				},
				OAuth: &config.OAuthConfig{
					Provider: "github",
					Scopes:   []string{"repo", "read:org"},
				},
			},
		},
	}

	got := mustGenerate(t, cfg)

	wantContains := []string{
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\dotvault\\Rules]\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\dotvault\\Rules\\gh]\r\n",
		"\"Description\"=\"GitHub host config\"\r\n",
		"\"TargetFormat\"=\"yaml\"\r\n",
		"\"TargetPath\"=\"~/.config/gh/hosts.yml\"\r\n",
		"\"VaultKey\"=\"gh\"\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\dotvault\\Rules\\gh\\OAuth]\r\n",
		"\"Provider\"=\"github\"\r\n",
		// REG_MULTI_SZ for ["repo", "read:org"]: "repo"\0"read:org"\0\0
		// As UTF-16LE bytes the value starts with the prefix below; the
		// rest may be on a continuation line because of line wrapping.
		"\"Scopes\"=hex(7):72,00,65,00,70,00,6f,00,00,00,",
	}
	for _, want := range wantContains {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, got)
		}
	}
}

func TestGenerateMultilineTemplate(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:     "gh",
				VaultKey: "gh",
				Target: config.Target{
					Path:     "~/.config/gh/hosts.yml",
					Format:   "yaml",
					Template: "github.com:\n  oauth_token: \"x\"\n",
				},
			},
		},
	}

	got := mustGenerate(t, cfg)

	if !strings.Contains(got, "\"TargetTemplate\"=hex(1):") {
		t.Errorf("multi-line template should be emitted as hex(1):\n%s", got)
	}
	// First two characters of the template are 'g' (0x67) and 'i' (0x69)
	// in UTF-16LE: 67,00,69,00.
	if !strings.Contains(got, "67,00,69,00") {
		t.Errorf("expected UTF-16LE bytes for template start; got:\n%s", got)
	}
	// Newline (0x0A) should appear in the hex bytes.
	if !strings.Contains(got, "0a,00") {
		t.Errorf("expected UTF-16LE LF byte (0a,00); got:\n%s", got)
	}
}

func TestGenerateEnrolments(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Enrolments: map[string]config.Enrolment{
			"gh": {
				Engine: "github",
				Settings: map[string]any{
					"host":   "github.com",
					"scopes": []any{"repo", "gist"},
				},
			},
			"ssh": {
				Engine: "ssh",
				Settings: map[string]any{
					"passphrase": "recommended",
				},
			},
		},
	}

	got := mustGenerate(t, cfg)

	wantContains := []string{
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\dotvault\\Enrolments]\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\dotvault\\Enrolments\\gh]\r\n",
		"\"Engine\"=\"github\"\r\n",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\dotvault\\Enrolments\\gh\\Settings]\r\n",
		"\"host\"=\"github.com\"\r\n",
		"\"scopes\"=hex(7):",
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\dotvault\\Enrolments\\ssh]\r\n",
		"\"Engine\"=\"ssh\"\r\n",
		"\"passphrase\"=\"recommended\"\r\n",
	}
	for _, want := range wantContains {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, got)
		}
	}

	// gh should appear before ssh (sorted output).
	ghIdx := strings.Index(got, `\Enrolments\gh]`)
	sshIdx := strings.Index(got, `\Enrolments\ssh]`)
	if ghIdx == -1 || sshIdx == -1 || ghIdx > sshIdx {
		t.Errorf("expected gh before ssh in sorted output; gh=%d ssh=%d", ghIdx, sshIdx)
	}
}

func TestGenerateUnsupportedSettingTypeErrors(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Enrolments: map[string]config.Enrolment{
			"gh": {
				Engine: "github",
				Settings: map[string]any{
					"port": 22, // ints are not representable
				},
			},
		},
	}
	_, err := GenerateText(cfg)
	if err == nil {
		t.Fatalf("expected error for unsupported setting type")
	}
	if !strings.Contains(err.Error(), "port") || !strings.Contains(err.Error(), "int") {
		t.Errorf("error should mention the offending setting and type; got: %v", err)
	}
}

func TestGenerateMixedListErrors(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Enrolments: map[string]config.Enrolment{
			"gh": {
				Engine: "github",
				Settings: map[string]any{
					"scopes": []any{"repo", 42}, // mixed list
				},
			},
		},
	}
	_, err := GenerateText(cfg)
	if err == nil {
		t.Fatalf("expected error for mixed-type list")
	}
}

func TestGenerateRejectsControlCharsInName(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Enrolments: map[string]config.Enrolment{
			"gh": {
				Engine: "github",
				Settings: map[string]any{
					"bad\nname": "value",
				},
			},
		},
	}
	_, err := GenerateText(cfg)
	if err == nil {
		t.Fatalf("expected error for control char in setting name")
	}
}

func TestGenerateEscapesQuoteAndBackslashInName(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Enrolments: map[string]config.Enrolment{
			"gh": {
				Engine: "github",
				Settings: map[string]any{
					`weird"name\path`: "value",
				},
			},
		},
	}
	got := mustGenerate(t, cfg)
	// Both " and \ in the name must be backslash-escaped on the wire.
	if !strings.Contains(got, `"weird\"name\\path"="value"`) {
		t.Errorf("setting name not escaped correctly; got:\n%s", got)
	}
}

func TestQuoteREGSZ(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{`hello`, `"hello"`},
		{`with"quote`, `"with\"quote"`},
		{`back\slash`, `"back\\slash"`},
		{`C:\Program Files\foo`, `"C:\\Program Files\\foo"`},
	}
	for _, tt := range tests {
		got := quoteREGSZ(tt.in)
		if got != tt.want {
			t.Errorf("quoteREGSZ(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNeedsHex(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"hello", false},
		{"with\nnewline", true},
		{"with\ttab", true},
		{"unicode é", true},
		{"all printable !@#$%^&*()", false},
	}
	for _, tt := range tests {
		got := needsHex(tt.in)
		if got != tt.want {
			t.Errorf("needsHex(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestUTF16StringBytes(t *testing.T) {
	// "A" -> 41,00 plus NUL terminator 00,00.
	got := utf16StringBytes("A")
	want := []byte{0x41, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("utf16StringBytes(\"A\") = % x, want % x", got, want)
	}
}

func TestUTF16MultiStringBytesSingle(t *testing.T) {
	// REG_MULTI_SZ for ["A"]: "A"\0\0
	// As UTF-16LE bytes: 41,00,00,00,00,00 (single string + double-NUL terminator)
	got := utf16MultiStringBytes([]string{"A"})
	want := []byte{0x41, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("utf16MultiStringBytes([\"A\"]) = % x, want % x", got, want)
	}
}

func TestUTF16MultiStringBytesMulti(t *testing.T) {
	// ["A", "B"] -> 41,00,00,00,42,00,00,00,00,00
	got := utf16MultiStringBytes([]string{"A", "B"})
	want := []byte{0x41, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("utf16MultiStringBytes = % x, want % x", got, want)
	}
}

func TestUTF16MultiStringBytesEmpty(t *testing.T) {
	// Empty MULTI_SZ is just the trailing NUL pair.
	got := utf16MultiStringBytes(nil)
	want := []byte{0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("utf16MultiStringBytes(nil) = % x, want % x", got, want)
	}
}

func TestEncodeUTF16LE(t *testing.T) {
	got := encodeUTF16LE("A")
	// BOM + A in UTF-16LE
	want := []byte{0xFF, 0xFE, 0x41, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("encodeUTF16LE = % x, want % x", got, want)
	}
}

func TestGenerateProducesUTF16LEWithBOM(t *testing.T) {
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
	}
	got, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(got) < 2 || got[0] != 0xFF || got[1] != 0xFE {
		t.Errorf("Generate output missing UTF-16LE BOM; first bytes = % x", got[:min(8, len(got))])
	}
	// First payload character is 'W' from "Windows Registry...".
	if len(got) < 4 || got[2] != 'W' || got[3] != 0x00 {
		t.Errorf("Generate output not UTF-16LE encoded; bytes 2-3 = % x", got[2:4])
	}
}

func TestHexLineWrapping(t *testing.T) {
	// Build a value long enough to force multiple continuations.
	value := strings.Repeat("a", 200)
	cfg := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Rules: []config.Rule{
			{
				Name:     "r",
				VaultKey: "k",
				Target: config.Target{
					Path:     "/tmp/x",
					Format:   "text",
					Template: "\n" + value, // leading newline forces hex(1)
				},
			},
		},
	}
	got := mustGenerate(t, cfg)

	if !strings.Contains(got, ",\\\r\n  ") {
		t.Errorf("expected backslash continuation in wrapped hex value; got:\n%s", got)
	}
	// Now that wrapping accounts for the two-space continuation indent,
	// no emitted line should exceed maxLineLen characters.
	for _, line := range strings.Split(got, "\r\n") {
		if len(line) > maxLineLen {
			t.Errorf("line exceeds wrap limit (%d > %d): %q", len(line), maxLineLen, line)
		}
	}
}
