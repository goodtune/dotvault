package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/clipboard"
)

// newUnixClipboardServer starts an httptest server bound to a Unix socket at
// sockPath, serving POST /api/v1/remote/clipboard. Skips where AF_UNIX is
// unavailable, matching the browse/notify test convention.
func newUnixClipboardServer(t *testing.T, sockPath string, handler http.HandlerFunc) {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix domain sockets unavailable on this platform: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/remote/clipboard", handler)
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
}

func TestPostClipboardToSocket_Success(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "dotvault.sock")
	var text, host string
	newUnixClipboardServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		text, host = r.FormValue("text"), r.Host
		_, _ = w.Write([]byte(`{"status":"clipboard set"}`))
	})

	if err := postClipboardToSocket(context.Background(), sock, "s3cr3t\nline2"); err != nil {
		t.Fatalf("postClipboardToSocket: %v", err)
	}
	if text != "s3cr3t\nline2" {
		t.Errorf("peer got text %q, want it verbatim", text)
	}
	if host != "localhost" {
		t.Errorf("peer Host = %q, want localhost (the DNS-rebinding allowlist)", host)
	}
}

func TestPostClipboardToSocket_MissingSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")
	if err := postClipboardToSocket(context.Background(), sock, "t"); err == nil {
		t.Fatal("expected an error for a missing socket so the caller falls back locally")
	}
}

// runClipboardWith drives runClipboard with a fake local writer, optional
// stdin, and the given --config override, returning the command error and the
// text (if any) the local writer received.
func runClipboardWith(t *testing.T, cfgPath, stdin string, args ...string) (error, *string) {
	t.Helper()
	prevCfg := flagConfig
	flagConfig = cfgPath
	prevSet := setLocalClipboard
	var localText *string
	setLocalClipboard = func(text string) error {
		localText = &text
		return nil
	}
	t.Cleanup(func() {
		flagConfig = prevCfg
		setLocalClipboard = prevSet
	})

	cmd := newClipboardCmd()
	cmd.SetContext(context.Background())
	cmd.SetIn(strings.NewReader(stdin))
	err := runClipboard(cmd, args)
	return err, localText
}

func TestRunClipboard_PrefersPeerSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "p.sock")
	var peerText string
	newUnixClipboardServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		peerText = r.FormValue("text")
		_, _ = w.Write([]byte(`{"status":"clipboard set"}`))
	})

	err, localText := runClipboardWith(t, writeBrowseConfig(t, sock), "", "peer value")
	if err != nil {
		t.Fatalf("runClipboard: %v", err)
	}
	if peerText != "peer value" {
		t.Errorf("peer got text %q, want the posted value", peerText)
	}
	if localText != nil {
		t.Errorf("local writer was called (%q) despite a healthy peer", *localText)
	}
}

func TestRunClipboard_FallsBackWhenPeerUnreachable(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")

	err, localText := runClipboardWith(t, writeBrowseConfig(t, sock), "", "local value")
	if err != nil {
		t.Fatalf("runClipboard: %v", err)
	}
	if localText == nil || *localText != "local value" {
		t.Errorf("local writer got %v, want the value after peer fallback", localText)
	}
}

func TestRunClipboard_FallsBackWhenPeerErrors(t *testing.T) {
	// The peer is reachable but returns a non-200 (e.g. its clipboard writer
	// failed): runClipboard must fall back to the local clipboard rather than
	// surfacing the peer error.
	sock := filepath.Join(t.TempDir(), "p.sock")
	newUnixClipboardServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"no display"}`))
	})

	err, localText := runClipboardWith(t, writeBrowseConfig(t, sock), "", "fallback value")
	if err != nil {
		t.Fatalf("runClipboard: %v", err)
	}
	if localText == nil || *localText != "fallback value" {
		t.Errorf("local writer got %v, want the value after peer error", localText)
	}
}

func TestRunClipboard_FallsBackWhenConfigUnloadable(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "missing.yaml")

	err, localText := runClipboardWith(t, cfgPath, "", "v")
	if err != nil {
		t.Fatalf("runClipboard: %v", err)
	}
	if localText == nil || *localText != "v" {
		t.Errorf("local writer got %v, want the value when config load fails", localText)
	}
}

func TestRunClipboard_ReadsStdinWhenNoArg(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")

	err, localText := runClipboardWith(t, writeBrowseConfig(t, sock), "from stdin\n")
	if err != nil {
		t.Fatalf("runClipboard: %v", err)
	}
	if localText == nil || *localText != "from stdin" {
		t.Errorf("local writer got %v, want the stdin value with the trailing newline stripped", localText)
	}
}

func TestRunClipboard_DashReadsStdin(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")

	err, localText := runClipboardWith(t, writeBrowseConfig(t, sock), "dash value", "-")
	if err != nil {
		t.Fatalf("runClipboard: %v", err)
	}
	if localText == nil || *localText != "dash value" {
		t.Errorf("local writer got %v, want the stdin value for %q", localText, "-")
	}
}

func TestClipboardText_StripsExactlyOneTrailingNewline(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"lf", "token\n", "token"},
		{"crlf", "token\r\n", "token"},
		{"none", "token", "token"},
		{"only one stripped", "token\n\n", "token\n"},
		{"interior kept", "line1\nline2\n", "line1\nline2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newClipboardCmd()
			cmd.SetIn(strings.NewReader(tc.in))
			got, err := clipboardText(cmd, nil)
			if err != nil {
				t.Fatalf("clipboardText: %v", err)
			}
			if got != tc.want {
				t.Errorf("clipboardText(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestClipboardText_ArgTakenVerbatim(t *testing.T) {
	// A positional argument is not newline-stripped — the shell already
	// delivered it verbatim.
	cmd := newClipboardCmd()
	cmd.SetIn(strings.NewReader("unused"))
	got, err := clipboardText(cmd, []string{"arg\n"})
	if err != nil {
		t.Fatalf("clipboardText: %v", err)
	}
	if got != "arg\n" {
		t.Errorf("clipboardText(arg) = %q, want the argument verbatim", got)
	}
}

func TestClipboardText_OversizeStdin(t *testing.T) {
	cmd := newClipboardCmd()
	cmd.SetIn(strings.NewReader(strings.Repeat("a", clipboard.MaxTextLen+1)))
	if _, err := clipboardText(cmd, nil); err == nil {
		t.Fatal("expected an error for over-limit stdin, not silent truncation")
	}
}

func TestRunClipboard_RejectsEmptyBeforeAnything(t *testing.T) {
	err, localText := runClipboardWith(t, "", "")
	if err == nil {
		t.Fatal("expected an error for empty text")
	}
	if localText != nil {
		t.Errorf("local writer was called (%q) for rejected input", *localText)
	}
}
