package sshfwd

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeRunner struct {
	out   string
	err   error
	calls int
}

func (f *fakeRunner) Run(ctx context.Context, cmd string) (string, error) {
	f.calls++
	return f.out, f.err
}

func TestExpandRemotePathAbsoluteDoesNotProbe(t *testing.T) {
	r := &fakeRunner{out: "/home/me\n"}
	got, err := ExpandRemotePath(context.Background(), r, "/run/user/1000/dotvault.sock")
	if err != nil {
		t.Fatalf("ExpandRemotePath() = %v", err)
	}
	if got != "/run/user/1000/dotvault.sock" {
		t.Errorf("got %q, want the path verbatim", got)
	}
	if r.calls != 0 {
		t.Errorf("probed %d times for an absolute path, want 0", r.calls)
	}
}

func TestExpandRemotePathTilde(t *testing.T) {
	r := &fakeRunner{out: "/home/me\n"}
	got, err := ExpandRemotePath(context.Background(), r, "~/.ssh/dotvault.sock")
	if err != nil {
		t.Fatalf("ExpandRemotePath() = %v", err)
	}
	if want := "/home/me/.ssh/dotvault.sock"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExpandRemotePathTrimsProbeOutput(t *testing.T) {
	r := &fakeRunner{out: "  /home/me  \r\n"}
	got, err := ExpandRemotePath(context.Background(), r, "~/x.sock")
	if err != nil {
		t.Fatalf("ExpandRemotePath() = %v", err)
	}
	if want := "/home/me/x.sock"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExpandRemotePathRejectsNonAbsoluteHome(t *testing.T) {
	r := &fakeRunner{out: "relative/home\n"}
	if _, err := ExpandRemotePath(context.Background(), r, "~/x.sock"); err == nil {
		t.Fatal("accepted a non-absolute $HOME; must be rejected")
	}
}

func TestExpandRemotePathRejectsEmptyHome(t *testing.T) {
	r := &fakeRunner{out: "\n"}
	if _, err := ExpandRemotePath(context.Background(), r, "~/x.sock"); err == nil {
		t.Fatal("accepted an empty $HOME; must be rejected")
	}
}

func TestExpandRemotePathPropagatesProbeError(t *testing.T) {
	want := errors.New("exec failed")
	r := &fakeRunner{err: want}
	_, err := ExpandRemotePath(context.Background(), r, "~/x.sock")
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func TestExpandRemotePathRejectsTildeUser(t *testing.T) {
	r := &fakeRunner{out: "/home/me\n"}
	_, err := ExpandRemotePath(context.Background(), r, "~other/x.sock")
	if err == nil || !strings.Contains(err.Error(), "~user/") {
		t.Fatalf("err = %v, want a ~user/ rejection", err)
	}
}

// Test traversal prevention: .. segments must be rejected by ValidateRemoteSocket.
func TestValidateRemoteSocketRejectsTraversalInTildePath(t *testing.T) {
	tests := []string{
		"~/../../etc/dotvault.sock",
		"~/a/../../b.sock",
		"~/../x.sock",
	}
	for _, p := range tests {
		if err := ValidateRemoteSocket(p); err == nil {
			t.Errorf("ValidateRemoteSocket(%q) accepted a .. segment; must reject", p)
		}
	}
}

// Test that filenames containing two dots are still accepted (false-positive guard).
func TestValidateRemoteSocketAcceptsDoublesInFilenames(t *testing.T) {
	tests := []string{
		"~/.ssh/my..sock",
		"~/..hidden/x.sock",
		"~/my.backup.sock",
	}
	for _, p := range tests {
		if err := ValidateRemoteSocket(p); err != nil {
			t.Errorf("ValidateRemoteSocket(%q) rejected a legitimate filename; must accept. Error: %v", p, err)
		}
	}
}

// Test traversal prevention in absolute paths.
func TestValidateRemoteSocketRejectsTraversalInAbsolutePath(t *testing.T) {
	tests := []string{
		"/home/../etc/dotvault.sock",
		"/tmp/a/../../etc/passwd",
		"/../etc/passwd",
	}
	for _, p := range tests {
		if err := ValidateRemoteSocket(p); err == nil {
			t.Errorf("ValidateRemoteSocket(%q) accepted a .. segment; must reject", p)
		}
	}
}

// Test control character rejection in probe output.
func TestExpandRemotePathRejectsInteriorNewlineInHome(t *testing.T) {
	r := &fakeRunner{out: "/home/me\n/evil"}
	_, err := ExpandRemotePath(context.Background(), r, "~/x.sock")
	if err == nil {
		t.Fatal("accepted a $HOME with an interior newline; must reject")
	}
}

func TestExpandRemotePathRejectsCarriageReturnInHome(t *testing.T) {
	r := &fakeRunner{out: "/home/me\r/evil"}
	_, err := ExpandRemotePath(context.Background(), r, "~/x.sock")
	if err == nil {
		t.Fatal("accepted a $HOME with a carriage return; must reject")
	}
}

// Tab and other control characters must also be rejected.
func TestExpandRemotePathRejectsTabInHome(t *testing.T) {
	r := &fakeRunner{out: "/home/me\t/evil"}
	_, err := ExpandRemotePath(context.Background(), r, "~/x.sock")
	if err == nil {
		t.Fatal("accepted a $HOME with a tab; must reject")
	}
}

// A trailing newline (the normal echo output) must still be accepted after TrimSpace.
func TestExpandRemotePathAcceptsTrailingNewlineInHome(t *testing.T) {
	r := &fakeRunner{out: "/home/me\n"}
	got, err := ExpandRemotePath(context.Background(), r, "~/x.sock")
	if err != nil {
		t.Fatalf("rejected a trailing newline (normal echo output): %v", err)
	}
	if want := "/home/me/x.sock"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// DEL character (0x7f) must also be rejected.
func TestExpandRemotePathRejectsDELInHome(t *testing.T) {
	r := &fakeRunner{out: "/home/me\x7f/evil"}
	_, err := ExpandRemotePath(context.Background(), r, "~/x.sock")
	if err == nil {
		t.Fatal("accepted a $HOME with a DEL character; must reject")
	}
}
