//go:build !windows

package uds

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// shortSockDir returns a temp directory with a short absolute path. It
// deliberately avoids t.TempDir(), whose path embeds the full test and
// subtest names: under macOS's already-long /var/folders TMPDIR that blows
// through the 104-byte sun_path limit and every bind fails with a baffling
// "invalid argument" before the test proper begins.
func shortSockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "uds")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// listenerFile binds a real unix listener and returns a dup'd *os.File for
// it, standing in for an fd inherited from systemd. The parent directory is
// tightened to 0700 and the node to 0600 so the fixture satisfies the same
// invariants a packaged socket unit produces; tests loosen them
// deliberately to exercise the refusals. The listener is kept open for the
// test's duration so the socket stays live.
func listenerFile(t *testing.T, path string) *os.File {
	t.Helper()
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := ln.(*net.UnixListener).File()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestAdoptActivated(t *testing.T) {
	t.Run("accepts an owner-only listener and reports its real path", func(t *testing.T) {
		dir := shortSockDir(t)
		path := filepath.Join(dir, "api.sock")
		f := listenerFile(t, path)

		ln, actual, err := adoptActivated("api", f)
		if err != nil {
			t.Fatalf("adoptActivated: %v", err)
		}
		defer ln.Close()
		if actual != path {
			// getsockname is the source of truth: it is what lets the
			// daemon report the socket unit's ListenStream= path rather
			// than a config value that may disagree.
			t.Errorf("actual path = %q, want %q", actual, path)
		}
	})

	t.Run("master survives adoption and is re-adoptable", func(t *testing.T) {
		// The SSH agent's supervision loop tears its listener down and
		// listens again after a failure. Under a consume-once model the
		// retry would self-bind against the systemd-owned path and loop on
		// "already running" forever; re-adoption from the retained master
		// is the fix, so it is the contract under test.
		dir := shortSockDir(t)
		path := filepath.Join(dir, "s.sock")
		f := listenerFile(t, path)

		ln1, _, err := adoptActivated("agent", f)
		if err != nil {
			t.Fatalf("first adopt: %v", err)
		}
		ln1.Close() // the surface's listener dies...

		ln2, actual, err := adoptActivated("agent", f) // ...and the retry re-claims
		if err != nil {
			t.Fatalf("second adopt after closing the first: %v", err)
		}
		defer ln2.Close()
		if actual != path {
			t.Errorf("re-adopted path = %q, want %q", actual, path)
		}
		// The re-adopted listener must actually accept.
		done := make(chan struct{})
		go func() {
			if c, err := ln2.Accept(); err == nil {
				c.Close()
			}
			close(done)
		}()
		c, err := net.DialTimeout("unix", path, 2*time.Second)
		if err != nil {
			t.Fatalf("dial re-adopted listener: %v", err)
		}
		c.Close()
		<-done
	})

	t.Run("refuses a node mode wider than 0600", func(t *testing.T) {
		// SocketMode defaults to 0666, so a hand-written socket unit that
		// omits it would silently hand the token endpoint to every uid on
		// the box. Refusal — not a warning — is the invariant.
		dir := shortSockDir(t)
		path := filepath.Join(dir, "loose.sock")
		f := listenerFile(t, path)
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}

		_, _, err := adoptActivated("api", f)
		if err == nil {
			t.Fatal("adoptActivated accepted a 0666 socket, want refusal")
		}
		if !strings.Contains(err.Error(), "SocketMode=0600") {
			t.Errorf("err = %v, want a message telling the operator the fix", err)
		}
	})

	t.Run("refuses a loose parent directory", func(t *testing.T) {
		// The half of the 0600-in-0700 invariant a node check alone
		// misses: a socket in a directory another user can write to can be
		// unlinked and replaced with an impostor that passes every node
		// check, feeding borrowers a hostile "token". Self-bind creates
		// the parent 0700; activation must refuse what self-bind would
		// never produce.
		dir := shortSockDir(t)
		path := filepath.Join(dir, "s.sock")
		f := listenerFile(t, path)
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}

		_, _, err := adoptActivated("api", f)
		if err == nil {
			t.Fatal("adoptActivated accepted a socket in a 0755 directory, want refusal")
		}
		if !strings.Contains(err.Error(), "DirectoryMode=0700") {
			t.Errorf("err = %v, want a message telling the operator the fix", err)
		}
	})

	t.Run("refusal leaves the node in place", func(t *testing.T) {
		// A refusal must not unlink systemd's node: FileListener-derived
		// listeners have unlink-on-close disabled, and this pins that.
		dir := shortSockDir(t)
		path := filepath.Join(dir, "keep.sock")
		f := listenerFile(t, path)
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
		if _, _, err := adoptActivated("api", f); err == nil {
			t.Fatal("want refusal")
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("refusal removed the socket node: %v", err)
		}
	})

	t.Run("refuses a non-socket fd", func(t *testing.T) {
		f, err := os.CreateTemp(shortSockDir(t), "plain")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, _, err := adoptActivated("api", f); err == nil {
			t.Fatal("adoptActivated accepted a regular file, want refusal")
		}
	})

	t.Run("refuses a tcp listener", func(t *testing.T) {
		// A ListenStream= with a port instead of a path passes a TCP fd —
		// which would silently turn the owner-only socket into a network
		// service. The UnixListener type assertion is the check that
		// catches it.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		f, err := ln.(*net.TCPListener).File()
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, _, err := adoptActivated("api", f); err == nil {
			t.Fatal("adoptActivated accepted a TCP listener, want refusal")
		}
	})
}

func TestActivationStateClaims(t *testing.T) {
	dir := shortSockDir(t)
	fAPI := listenerFile(t, filepath.Join(dir, "api.sock"))
	fUnknown := listenerFile(t, filepath.Join(dir, "u.sock"))
	st := &activationState{byName: map[string][]*os.File{
		"api":     {fAPI},
		"unknown": {fUnknown},
	}}

	if got := st.master("api"); got != fAPI {
		t.Errorf("master(api) returned the wrong file")
	}
	// Masters are retained: a second claim gets the same file (the
	// re-listen contract), not nil.
	if got := st.master("api"); got != fAPI {
		t.Errorf("second master(api) = %v, want the retained master", got)
	}
	if got := st.master("agent"); got != nil {
		t.Errorf("master(agent) = %v, want nil (never passed)", got)
	}
	if got := st.unclaimedNames(); len(got) != 1 || got[0] != "unknown" {
		t.Errorf("unclaimedNames = %v, want [unknown]", got)
	}
	// Sorted output with more than one element, so a broken comparator
	// cannot hide behind single-entry maps.
	st.byName["zzz"] = []*os.File{fUnknown}
	st.byName["aaa"] = []*os.File{fUnknown}
	if got := st.unclaimedNames(); len(got) != 3 || got[0] != "aaa" || got[1] != "unknown" || got[2] != "zzz" {
		t.Errorf("unclaimedNames = %v, want [aaa unknown zzz]", got)
	}
	// A nil state (no activation) is inert everywhere.
	var none *activationState
	if none.master("api") != nil || none.unclaimedNames() != nil {
		t.Error("nil activationState must be inert")
	}
}

func TestDrainListener(t *testing.T) {
	// Draining is the honest refusal for an unclaimed activated fd:
	// systemd retains its own listening fd, so closing our dup refuses
	// nobody — clients would connect into a backlog no one accepts and
	// hang. Drained clients connect and get EOF immediately.
	dir := shortSockDir(t)
	path := filepath.Join(dir, "drain.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go drainListener(ln)

	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		t.Fatalf("dial drained socket: %v", err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err != io.EOF {
		t.Errorf("read on drained connection = %v, want io.EOF (fail fast, not hang)", err)
	}
}
