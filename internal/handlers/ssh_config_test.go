package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mergeRender is a small helper: parse existing + incoming ssh_config text,
// merge, and return the rendered result.
func mergeRender(t *testing.T, existing, incoming string) string {
	t.Helper()
	h := &SSHConfigHandler{}
	ex, err := h.Parse(existing)
	if err != nil {
		t.Fatalf("Parse(existing): %v", err)
	}
	in, err := h.Parse(incoming)
	if err != nil {
		t.Fatalf("Parse(incoming): %v", err)
	}
	merged, err := h.Merge(ex, in)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "config")
	if err := h.Write(out, merged, 0600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return string(b)
}

func TestSSHConfig_ReadMissing(t *testing.T) {
	h := &SSHConfigHandler{}
	data, err := h.Read(filepath.Join(t.TempDir(), "nonexistent"))
	if err != nil {
		t.Fatalf("Read(missing): %v", err)
	}
	cfg, ok := data.(*sshConfig)
	if !ok {
		t.Fatalf("Read returned %T, want *sshConfig", data)
	}
	if got := cfg.render(); got != "" {
		t.Errorf("empty config rendered %q, want empty", got)
	}
}

// TestSSHConfig_RoundTripVerbatim is the load-bearing surgical-edit guarantee:
// reading a complex hand-maintained file and writing it back without any merge
// must reproduce it byte-for-byte (comments, indentation, blank lines, repeated
// directives, Match blocks, and all).
func TestSSHConfig_RoundTripVerbatim(t *testing.T) {
	src, err := os.ReadFile("testdata/existing.ssh_config")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	h := &SSHConfigHandler{}
	cfg, err := h.Parse(string(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := cfg.(*sshConfig).render()
	if got != string(src) {
		t.Errorf("round-trip not byte-identical.\n--- want ---\n%q\n--- got ---\n%q", string(src), got)
	}
}

// TestSSHConfig_GlobalExample exercises the motivating use case: a template with
// no Host block injects directives into the implicit global section. The
// forward and User land at the top of the file, below an existing header
// comment, and nothing else is disturbed.
func TestSSHConfig_GlobalExample(t *testing.T) {
	existing := `# my ssh config
Host example
    User bob
`
	incoming := "User alice\n" +
		`RemoteForward /home/alice/.ssh/dotvault.sock 127.0.0.1:8200` + "\n"

	got := mergeRender(t, existing, incoming)

	want := `# my ssh config
User alice
RemoteForward /home/alice/.ssh/dotvault.sock 127.0.0.1:8200
Host example
    User bob
`
	if got != want {
		t.Errorf("global merge mismatch.\n--- want ---\n%s\n--- got ---\n%s", want, got)
	}
}

// TestSSHConfig_GlobalRemoteForwardUpdateByUsername reproduces the forward
// update reported against {{ username }}: an existing global-section directive
// whose RemoteForward listen spec embeds the username keeps that listen spec
// stable across a template change (both interpolate the same username), so only
// the forward target is rewritten in place — no duplicate line, and User is left
// alone. The incoming text is what the sync engine produces after
// RenderWithUsername binds {{ username }} to "goodtune"; the handler never sees
// the template, only its rendered output.
func TestSSHConfig_GlobalRemoteForwardUpdateByUsername(t *testing.T) {
	existing := "User goodtune\n" +
		"RemoteForward /home/goodtune/.ssh/dotvault.sock oldhost:9000\n"
	// Template `User {{ username }}` / `RemoteForward /home/{{ username }}/...`
	// after rendering {{ username }} -> goodtune.
	incoming := "User goodtune\n" +
		"RemoteForward /home/goodtune/.ssh/dotvault.sock newhost:9001\n"

	got := mergeRender(t, existing, incoming)

	want := "User goodtune\n" +
		"RemoteForward /home/goodtune/.ssh/dotvault.sock newhost:9001\n"
	if got != want {
		t.Errorf("merge mismatch:\n--- want ---\n%q\n--- got ---\n%q", want, got)
	}
	if n := strings.Count(got, "RemoteForward"); n != 1 {
		t.Errorf("expected exactly one RemoteForward (update in place, not duplicate), got %d:\n%s", n, got)
	}
}

// TestSSHConfig_UpdateInPlace updates a single-valued directive within an
// existing Host block and confirms surrounding directives, an indented comment,
// and the block's indentation style are all preserved.
func TestSSHConfig_UpdateInPlace(t *testing.T) {
	existing, err := os.ReadFile("testdata/existing.ssh_config")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	incoming := "Host bastion\n    User newuser\n    Port 22\n"

	got := mergeRender(t, string(existing), incoming)

	if !strings.Contains(got, "    User newuser\n") {
		t.Errorf("User not updated in place:\n%s", got)
	}
	if strings.Contains(got, "olduser") {
		t.Errorf("old User value lingering:\n%s", got)
	}
	if !strings.Contains(got, "    Port 22\n") || strings.Contains(got, "Port 2222") {
		t.Errorf("Port not updated in place:\n%s", got)
	}
	// Untouched neighbours preserved.
	for _, want := range []string{
		"    HostName bastion.corp.example.com\n",
		"    # never remove this proxy line\n",
		"    ProxyCommand none\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lost untouched line %q:\n%s", want, got)
		}
	}
	// Exactly one User directive in the bastion block.
	if n := strings.Count(got, "User newuser"); n != 1 {
		t.Errorf("expected 1 'User newuser', got %d:\n%s", n, got)
	}
}

// TestSSHConfig_RemoteForwardReplaceByListen confirms a multi-valued forward is
// matched on its listen spec (first argument): re-syncing the same listen path
// updates the target rather than appending a duplicate.
func TestSSHConfig_RemoteForwardReplaceByListen(t *testing.T) {
	existing := "Host tunnel\n" +
		"    RemoteForward /home/alice/.ssh/dotvault.sock 127.0.0.1:9000\n"
	incoming := "Host tunnel\n" +
		"    RemoteForward /home/alice/.ssh/dotvault.sock 127.0.0.1:8200\n"

	got := mergeRender(t, existing, incoming)

	if n := strings.Count(got, "RemoteForward"); n != 1 {
		t.Errorf("expected forward replaced in place (1 line), got %d:\n%s", n, got)
	}
	if strings.Contains(got, "127.0.0.1:9000") {
		t.Errorf("old forward target lingering:\n%s", got)
	}
	if !strings.Contains(got, "127.0.0.1:8200") {
		t.Errorf("new forward target missing:\n%s", got)
	}
}

// TestSSHConfig_RemoteForwardDistinctListensCoexist confirms forwards with
// different listen specs accumulate rather than overwrite.
func TestSSHConfig_RemoteForwardDistinctListensCoexist(t *testing.T) {
	existing := "Host tunnel\n    RemoteForward 2222 localhost:22\n"
	incoming := "Host tunnel\n    RemoteForward 8080 localhost:80\n"

	got := mergeRender(t, existing, incoming)

	if !strings.Contains(got, "RemoteForward 2222 localhost:22") {
		t.Errorf("existing forward dropped:\n%s", got)
	}
	if !strings.Contains(got, "RemoteForward 8080 localhost:80") {
		t.Errorf("new forward missing:\n%s", got)
	}
}

// TestSSHConfig_IdentityFileAdditiveAndDedup confirms IdentityFile (a
// multi-valued keyed-by-path keyword) appends a new path but does not duplicate
// one already present.
func TestSSHConfig_IdentityFileAdditiveAndDedup(t *testing.T) {
	existing := "Host *\n    IdentityFile ~/.ssh/id_a\n"
	incoming := "Host *\n    IdentityFile ~/.ssh/id_a\n    IdentityFile ~/.ssh/id_b\n"

	got := mergeRender(t, existing, incoming)

	if n := strings.Count(got, "IdentityFile ~/.ssh/id_a"); n != 1 {
		t.Errorf("expected id_a once (dedup), got %d:\n%s", n, got)
	}
	if !strings.Contains(got, "IdentityFile ~/.ssh/id_b") {
		t.Errorf("id_b not appended:\n%s", got)
	}
}

// TestSSHConfig_SetEnvReplaceByName confirms SetEnv is keyed on the variable
// name (before '='), so a changed value replaces in place while a new variable
// is appended.
func TestSSHConfig_SetEnvReplaceByName(t *testing.T) {
	existing := "Host h\n    SetEnv FOO=old\n"
	incoming := "Host h\n    SetEnv FOO=new\n    SetEnv BAR=baz\n"

	got := mergeRender(t, existing, incoming)

	if strings.Contains(got, "FOO=old") {
		t.Errorf("old FOO value lingering:\n%s", got)
	}
	if !strings.Contains(got, "SetEnv FOO=new") {
		t.Errorf("FOO not updated:\n%s", got)
	}
	if !strings.Contains(got, "SetEnv BAR=baz") {
		t.Errorf("BAR not appended:\n%s", got)
	}
	if n := strings.Count(got, "SetEnv FOO="); n != 1 {
		t.Errorf("expected one FOO line, got %d:\n%s", n, got)
	}
}

// TestSSHConfig_NewBlockAppended confirms a Host block absent from the existing
// file is appended wholesale.
func TestSSHConfig_NewBlockAppended(t *testing.T) {
	existing := "Host a\n    User one\n"
	incoming := "Host b\n    User two\n    HostName b.example.com\n"

	got := mergeRender(t, existing, incoming)

	if !strings.Contains(got, "Host a\n    User one\n") {
		t.Errorf("existing block disturbed:\n%s", got)
	}
	for _, want := range []string{"Host b\n", "    User two\n", "    HostName b.example.com\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("new block missing %q:\n%s", want, got)
		}
	}
	// New block comes after the existing one.
	if strings.Index(got, "Host b") < strings.Index(got, "Host a") {
		t.Errorf("new block ordered before existing:\n%s", got)
	}
}

// TestSSHConfig_MatchBlockMerge confirms Match sections merge by their full
// (whitespace-collapsed) criteria line.
func TestSSHConfig_MatchBlockMerge(t *testing.T) {
	existing, err := os.ReadFile("testdata/existing.ssh_config")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	// Note the doubled space — must still match the fixture's single-spaced
	// Match line.
	incoming := "Match host  *.internal  user deploy\n    StrictHostKeyChecking yes\n"

	got := mergeRender(t, string(existing), incoming)

	if !strings.Contains(got, "StrictHostKeyChecking yes") {
		t.Errorf("Match directive not updated:\n%s", got)
	}
	if strings.Contains(got, "StrictHostKeyChecking no") {
		t.Errorf("old Match directive lingering:\n%s", got)
	}
	if n := strings.Count(got, "Match host"); n != 1 {
		t.Errorf("expected Match block merged, not duplicated; got %d:\n%s", n, got)
	}
}

// TestSSHConfig_Idempotent confirms merging the same incoming twice produces a
// stable result with no duplicated directives.
func TestSSHConfig_Idempotent(t *testing.T) {
	existing, err := os.ReadFile("testdata/existing.ssh_config")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	incoming := "Host bastion\n    User newuser\n    RemoteForward /run/agent.sock localhost:1\n"

	once := mergeRender(t, string(existing), incoming)
	twice := mergeRender(t, once, incoming)

	if once != twice {
		t.Errorf("merge not idempotent.\n--- once ---\n%s\n--- twice ---\n%s", once, twice)
	}
}

// TestSSHConfig_EqualsSeparator confirms the "Keyword=Value" / "Keyword = Value"
// separators parse, and an untouched such line round-trips verbatim.
func TestSSHConfig_EqualsSeparator(t *testing.T) {
	h := &SSHConfigHandler{}
	cfg, err := h.Parse("Host h\n    User=bob\n    Port = 2200\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Untouched round-trip keeps the original separators.
	if got := cfg.(*sshConfig).render(); !strings.Contains(got, "User=bob") || !strings.Contains(got, "Port = 2200") {
		t.Errorf("equals-separator lines not preserved verbatim:\n%s", got)
	}

	// And a merge updating those directives parses the original args correctly.
	got := mergeRender(t, "Host h\n    User=bob\n    Port = 2200\n", "Host h\n    User alice\n")
	if !strings.Contains(got, "User alice") || strings.Contains(got, "bob") {
		t.Errorf("User not updated across '=' separator:\n%s", got)
	}
	if !strings.Contains(got, "Port = 2200") {
		t.Errorf("untouched '=' directive disturbed:\n%s", got)
	}
}

// TestSSHConfig_CRLF confirms CRLF input parses and that merged output is
// normalised to LF.
func TestSSHConfig_CRLF(t *testing.T) {
	existing := "Host h\r\n    User old\r\n"
	incoming := "Host h\n    User new\n"

	got := mergeRender(t, existing, incoming)

	if strings.Contains(got, "\r") {
		t.Errorf("output retained CR:\n%q", got)
	}
	if !strings.Contains(got, "    User new\n") || strings.Contains(got, "old") {
		t.Errorf("CRLF directive not updated:\n%q", got)
	}
}

// TestSSHConfig_MergeRejectsNonTemplateData confirms the template-only contract:
// passing raw Vault data (a map) rather than parsed ssh_config content fails
// with a clear, actionable error.
func TestSSHConfig_MergeRejectsNonTemplateData(t *testing.T) {
	h := &SSHConfigHandler{}
	existing, _ := h.Parse("")
	_, err := h.Merge(existing, map[string]any{"foo": "bar"})
	if err == nil {
		t.Fatal("expected error merging raw map, got nil")
	}
	if !strings.Contains(err.Error(), "requires a template") {
		t.Errorf("error %q should mention the template requirement", err)
	}
}

// TestSSHConfig_BareKeyword confirms a keyword with no arguments parses and
// round-trips.
func TestSSHConfig_BareKeyword(t *testing.T) {
	h := &SSHConfigHandler{}
	cfg, err := h.Parse("Host h\n    ForwardAgent\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.(*sshConfig).render(); !strings.Contains(got, "    ForwardAgent\n") {
		t.Errorf("bare keyword not preserved:\n%s", got)
	}
}

// TestSSHConfig_KeywordCaseInsensitive confirms a directive is matched for
// update regardless of the keyword's letter case, and the existing line's case
// is preserved on update.
func TestSSHConfig_KeywordCaseInsensitive(t *testing.T) {
	existing := "Host h\n    user bob\n"
	incoming := "Host h\n    User alice\n"

	got := mergeRender(t, existing, incoming)

	if n := strings.Count(strings.ToLower(got), "user "); n != 1 {
		t.Errorf("expected single user directive after case-insensitive match, got %d:\n%s", n, got)
	}
	if !strings.Contains(got, "alice") || strings.Contains(got, "bob") {
		t.Errorf("value not updated across case-mismatched keyword:\n%s", got)
	}
}

// TestSSHConfig_HostPatternCaseSensitive documents that Host pattern arguments
// are matched case-sensitively (ssh_config(5) patterns are literal, not
// case-folded): "Host FOO" and "Host foo" are distinct sections and do not
// merge. Only the keyword itself ("Host"/"Match") is case-insensitive.
func TestSSHConfig_HostPatternCaseSensitive(t *testing.T) {
	existing := "Host FOO\n    User a\n"
	incoming := "Host foo\n    User b\n"

	got := mergeRender(t, existing, incoming)

	if !strings.Contains(got, "Host FOO\n    User a\n") {
		t.Errorf("original case-distinct block disturbed:\n%s", got)
	}
	if !strings.Contains(got, "Host foo\n    User b\n") {
		t.Errorf("case-distinct incoming block not appended:\n%s", got)
	}
	// Keyword case still merges: "host"/"Host" same section.
	got2 := mergeRender(t, "host bar\n    User a\n", "Host bar\n    User b\n")
	if n := strings.Count(got2, "ar\n"); n != 1 || !strings.Contains(got2, "User b") {
		t.Errorf("case-insensitive keyword should merge into one section:\n%s", got2)
	}
}

// TestSSHConfig_IncomingCommentsNotMergedIntoExisting documents the merge
// asymmetry: comments in an incoming section are dropped when merging into an
// existing section (only directives are applied), but survive when the section
// is new and gets cloned wholesale.
func TestSSHConfig_IncomingCommentsNotMergedIntoExisting(t *testing.T) {
	// Existing section: incoming comment is not carried in.
	got := mergeRender(t, "Host h\n    User a\n", "Host h\n    # template comment\n    User b\n")
	if strings.Contains(got, "template comment") {
		t.Errorf("incoming comment should not merge into existing section:\n%s", got)
	}
	if !strings.Contains(got, "User b") {
		t.Errorf("directive should still update:\n%s", got)
	}

	// New section: comment survives via cloneBlock.
	got2 := mergeRender(t, "Host other\n    User a\n", "Host new\n    # keep me\n    User b\n")
	if !strings.Contains(got2, "# keep me") {
		t.Errorf("comment in a new cloned section should survive:\n%s", got2)
	}
}

// TestSSHConfig_BareMultiValuedArgs confirms a multi-valued keyword with empty
// arguments keys consistently (no panic, idempotent re-merge) rather than
// duplicating. Bare forwards are not valid ssh, but the handler must degrade
// safely if a template emits one.
func TestSSHConfig_BareMultiValuedArgs(t *testing.T) {
	existing := "Host h\n    User a\n"
	incoming := "Host h\n    RemoteForward\n"

	once := mergeRender(t, existing, incoming)
	twice := mergeRender(t, once, incoming)
	if once != twice {
		t.Errorf("bare multi-valued merge not idempotent.\n--- once ---\n%s\n--- twice ---\n%s", once, twice)
	}
	if n := strings.Count(once, "RemoteForward"); n != 1 {
		t.Errorf("expected a single bare RemoteForward, got %d:\n%s", n, once)
	}
}

// TestSSHConfig_NewFileFromTemplate confirms merging into a freshly-read missing
// file (empty config) yields exactly the incoming content.
func TestSSHConfig_NewFileFromTemplate(t *testing.T) {
	h := &SSHConfigHandler{}
	existing, err := h.Read(filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatalf("Read(missing): %v", err)
	}
	incoming, _ := h.Parse("Host *\n    User alice\n    RemoteForward /run/a.sock localhost:1\n")

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	got := merged.(*sshConfig).render()
	want := "Host *\n    User alice\n    RemoteForward /run/a.sock localhost:1\n"
	if got != want {
		t.Errorf("new-file merge mismatch.\n--- want ---\n%s\n--- got ---\n%s", want, got)
	}
}
