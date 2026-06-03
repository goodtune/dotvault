package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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

	// Exactly one inverted region (the cursor row) is expected — a
	// regression that highlighted everything would still satisfy a
	// "contains \x1b[7m" check, so we count and bound the region.
	if got := strings.Count(out, "\x1b[7m"); got != 1 {
		t.Errorf("expected exactly one inverted region (\\x1b[7m), got %d:\n%s", got, out)
	}
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

func TestSanitizeOneLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "hello world", "hello world"},
		{"keeps unicode", "café — ☕", "café — ☕"},
		{"strips esc", "before\x1b[31mafter", "before[31mafter"},
		{"strips newline", "line one\nline two", "line oneline two"},
		{"strips bell", "ding\x07dong", "dingdong"},
		{"strips osc title", "x\x1b]0;evil\x07y", "x]0;evily"},
		{"strips delete", "a\x7fb", "ab"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeOneLine(tc.in); got != tc.want {
				t.Errorf("sanitizeOneLine(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestTuiRender_SanitizesUntrustedFields(t *testing.T) {
	// Vault could theoretically return an error message containing
	// ESC sequences. They must not survive into the rendered line.
	m := &tuiModel{
		statuses: []enrol.Status{
			{Key: "evil\x1b]0;owned\x07", Engine: "x", EngineName: "X\x1bbroken", Error: "boom\nnewline"},
		},
	}
	var buf bytes.Buffer
	m.render(&buf)
	out := buf.String()
	// The leading `\x1b[H\x1b[2J` clear and the `\x1b[7m`/`\x1b[0m`
	// highlight ANSI come from render's own templates; they're safe.
	// Strip those before checking for untrusted ESC.
	cleaned := strings.NewReplacer(
		"\x1b[H", "",
		"\x1b[2J", "",
		"\x1b[7m", "",
		"\x1b[0m", "",
	).Replace(out)
	if strings.ContainsRune(cleaned, 0x1b) {
		t.Errorf("render leaked an untrusted ESC into output:\n%q", cleaned)
	}
	if strings.ContainsRune(cleaned, 0x07) {
		t.Errorf("render leaked an untrusted BEL into output:\n%q", cleaned)
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

// TestEnrolUnauthenticated_SubprocessRoundTrip exercises the "no
// token, point at `dotvault login`" exit path end-to-end by invoking
// the compiled binary with no VAULT_TOKEN and a HOME that contains no
// .dotvault-token file. The auth check at the top of runEnrol must
// short-circuit before any Vault round-trip and exit 1 with the
// documented message. Done as a subprocess test because runEnrol
// calls os.Exit directly and is not refactorable into an in-process
// table test without an exit injection seam.
func TestEnrolUnauthenticated_SubprocessRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess test")
	}
	if runtime.GOOS == "windows" {
		// PATH/exec semantics under a Go-built test binary differ
		// enough on Windows that this round-trip is best-effort POSIX.
		// The unit tests on tuiModel / readSingleKey / sanitizeOneLine
		// already cover the platform-independent surface.
		t.Skip("subprocess test exercises POSIX-shell semantics")
	}

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "dotvault")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build: %v", err)
	}

	workDir := t.TempDir()
	configPath := filepath.Join(workDir, "config.yaml")
	cfgYAML := `vault:
  address: http://127.0.0.1:8200
rules:
  - name: r1
    vault_key: k1
    target:
      path: /tmp/dotvault-test
      format: text
enrolments:
  gh:
    engine: github
`
	if err := os.WriteFile(configPath, []byte(cfgYAML), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(binPath, "--config", configPath, "enrol")
	// Force "no token" — empty VAULT_TOKEN, HOME pointing at a fresh
	// dir without a .dotvault-token file.
	cmd.Env = append(os.Environ(),
		"VAULT_TOKEN=",
		"HOME="+workDir,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit, got success\noutput:\n%s", out)
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if code := exitErr.ExitCode(); code != 1 {
			t.Errorf("exit code = %d, want 1\noutput:\n%s", code, out)
		}
	}
	wantSubstr := "not authenticated"
	if !strings.Contains(string(out), wantSubstr) {
		t.Errorf("output missing %q\noutput:\n%s", wantSubstr, out)
	}
	if !strings.Contains(string(out), "dotvault login") {
		t.Errorf("output should point at `dotvault login`\noutput:\n%s", out)
	}
}

// TestEnrolTransientVaultError_SubprocessRoundTrip exercises the
// path Copilot flagged in the fourth review pass: a LookupSelf
// failure that isn't a 403 (transient network/TLS/Vault-down) must
// surface as a connectivity message, not "run dotvault login". The
// test points the binary at an httptest server returning 404 on
// every request, which the Vault SDK turns into a non-Forbidden
// ResponseError.
func TestEnrolTransientVaultError_SubprocessRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess test")
	}
	if runtime.GOOS == "windows" {
		t.Skip("subprocess test exercises POSIX-shell semantics")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 404 (not 403) — outside vault.IsForbidden's predicate so
		// the test exercises the non-Forbidden branch. retryablehttp
		// doesn't retry on 4xx so the test stays fast.
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "dotvault")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build: %v", err)
	}

	workDir := t.TempDir()
	configPath := filepath.Join(workDir, "config.yaml")
	cfgYAML := "vault:\n  address: " + srv.URL + "\nrules:\n  - name: r1\n    vault_key: k1\n    target:\n      path: /tmp/dotvault-test\n      format: text\nenrolments:\n  gh:\n    engine: github\n"
	if err := os.WriteFile(configPath, []byte(cfgYAML), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(binPath, "--config", configPath, "enrol")
	// Provide a token so the auth check moves past the "no token"
	// branch and exercises LookupSelf against our fake server.
	cmd.Env = append(os.Environ(),
		"VAULT_TOKEN=fake-token-for-test",
		"HOME="+workDir,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit, got success\noutput:\n%s", out)
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if code := exitErr.ExitCode(); code != 1 {
			t.Errorf("exit code = %d, want 1\noutput:\n%s", code, out)
		}
	}
	if !strings.Contains(string(out), "vault unreachable") {
		t.Errorf("output missing %q (should mention vault unreachable, not login)\noutput:\n%s", "vault unreachable", out)
	}
	if strings.Contains(string(out), "dotvault login") {
		t.Errorf("transient error path should not point at `dotvault login` — that wouldn't help here\noutput:\n%s", out)
	}
}

// TestReadSingleKey_SplitArrowSequence exercises the slow-link path
// flagged in PR #70 review: under VMIN=1 VTIME=0 a Read may return as
// soon as the ESC byte is available, with the `[A` tail arriving
// later. The drain loop should keep polling+reading until it has a
// classifiable sequence and return keyUp rather than collapsing to
// quit.
func TestReadSingleKey_SplitArrowSequence(t *testing.T) {
	if runtime.GOOS == "windows" {
		// On Windows term.MakeRaw enables VT input, which delivers
		// each keystroke atomically — splits don't occur and the
		// waitForMoreInput shim is a no-op.
		t.Skip("split-escape peek is POSIX-only")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	go func() {
		defer w.Close()
		_, _ = w.Write([]byte{0x1b})
		// Gap stays well below the 50ms peek window so the follow-up
		// Read picks the tail up. Long enough that it's plausibly the
		// kind of split a real terminal might produce.
		time.Sleep(15 * time.Millisecond)
		_, _ = w.Write([]byte{'[', 'A'})
	}()
	got, err := readSingleKey(context.Background(), r)
	if err != nil {
		t.Fatalf("readSingleKey: %v", err)
	}
	if got != keyUp {
		t.Errorf("split arrow = %v, want keyUp", got)
	}
}

// TestReadSingleKey_OneByteAtATime exercises the worst case Copilot
// flagged in the second review pass: every byte of the arrow sequence
// arrives in its own Read. The drain loop must keep accumulating
// across multiple polls until the full ESC '[' 'A' is in hand.
func TestReadSingleKey_OneByteAtATime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("split-escape peek is POSIX-only")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	go func() {
		defer w.Close()
		for _, b := range []byte{0x1b, '[', 'B'} {
			_, _ = w.Write([]byte{b})
			time.Sleep(10 * time.Millisecond)
		}
	}()
	got, err := readSingleKey(context.Background(), r)
	if err != nil {
		t.Fatalf("readSingleKey: %v", err)
	}
	if got != keyDown {
		t.Errorf("one-byte-at-a-time arrow = %v, want keyDown", got)
	}
}

// TestReadSingleKey_ContextCancellation verifies that an external
// SIGTERM/SIGINT (modelled here by cancelling the parent ctx) wakes
// the picker out of an idle blocking read on POSIX — without the
// blockUntilInput poll loop the goroutine would stay parked in Read
// until something arrived on the pipe.
func TestReadSingleKey_ContextCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		// On Windows blockUntilInput returns immediately, so the
		// Read remains plain blocking — ctx cancellation isn't
		// observable mid-Read and the test would hang. The picker
		// on Windows observes ctx after the next keystroke.
		t.Skip("ctx-aware blocking read is POSIX-only")
	}
	// A pipe with the writer still open and no data — Read on the
	// read side would block forever without ctx awareness.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan keyKind, 1)
	go func() {
		got, _ := readSingleKey(ctx, r)
		done <- got
	}()

	// Give the goroutine a moment to park in blockUntilInput.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case got := <-done:
		if got != keyQuit {
			t.Errorf("ctx cancellation returned %v, want keyQuit", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readSingleKey did not return within 2s of ctx cancellation")
	}
}

// TestReadSingleKey_EscThenOtherKey exercises the "Esc then immediate
// other key" race: a user presses Esc and types another key within
// the 50ms peek window. The drain loop pulls the follow-up byte in,
// notices it isn't '[' (so not a CSI sequence), stops early, and the
// classifier treats the leading ESC as quit. The follow-up byte is
// intentionally dropped — it would take a sub-50ms two-key burst for
// this to happen in practice.
func TestReadSingleKey_EscThenOtherKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("split-escape peek is POSIX-only")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	go func() {
		defer w.Close()
		_, _ = w.Write([]byte{0x1b})
		time.Sleep(5 * time.Millisecond)
		_, _ = w.Write([]byte{'x'})
	}()
	got, err := readSingleKey(context.Background(), r)
	if err != nil {
		t.Fatalf("readSingleKey: %v", err)
	}
	if got != keyQuit {
		t.Errorf("esc-then-other = %v, want keyQuit", got)
	}
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
			got, err := readSingleKey(context.Background(), r)
			if err != nil && err != io.EOF {
				t.Fatalf("readSingleKey: %v", err)
			}
			if got != tc.want {
				t.Errorf("readSingleKey = %v, want %v", got, tc.want)
			}
		})
	}
}
