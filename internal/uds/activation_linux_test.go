//go:build linux

package uds

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestActivationEndToEnd exercises the real Linux glue — env parsing, the
// fds-start-at-3 numbering, and the env scrub — by re-executing the test
// binary as a fake systemd-activated child. exec.Cmd.ExtraFiles places
// files at fd 3+i, which is exactly the sd_listen_fds contract, so the
// child sees precisely what a socket unit would give it. The in-process
// unit tests can't cover this: the snapshot is once-guarded and test fds
// never sit at 3.
func TestActivationEndToEnd(t *testing.T) {
	if os.Getenv("UDS_ACTIVATION_CHILD") == "1" {
		activationChild()
		return
	}

	dir := t.TempDir()
	// The child's adoptActivated enforces the 0700-parent invariant, so the
	// fixture has to satisfy it, exactly as DirectoryMode=0700 does in the
	// packaged socket units.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "api.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := os.Chmod(sock, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := ln.(*net.UnixListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	cmd := exec.Command(os.Args[0], "-test.run", "TestActivationEndToEnd")
	cmd.ExtraFiles = []*os.File{f} // lands at fd 3 in the child
	cmd.Env = append(os.Environ(),
		"UDS_ACTIVATION_CHILD=1",
		"LISTEN_FDS=1",
		"LISTEN_FDNAMES=api",
		// LISTEN_PID must be the child's PID, which we can't know before
		// starting it. Real systemd sets it post-fork; the child
		// substitutes its own PID before snapshotting (see
		// activationChild), which keeps the PID *check* exercised while
		// letting the test drive it.
		"LISTEN_PID_SELF=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	for _, want := range []string{"CLAIMED path=" + sock, "CLOEXEC_SET", "ENV_SCRUBBED", "SERVED", "RECLAIMED"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("child output missing %q:\n%s", want, out)
		}
	}
}

// activationChild runs inside the re-exec: it claims the activated fd,
// verifies the environment was scrubbed, serves one connection to prove the
// listener is live, and reports each step on stdout for the parent to
// assert on. It must os.Exit so the surrounding `go test` harness in the
// child process doesn't run the whole package again.
func activationChild() {
	fail := func(format string, args ...any) {
		fmt.Printf("CHILD_FAIL: "+format+"\n", args...)
		os.Exit(1)
	}
	if os.Getenv("LISTEN_PID_SELF") == "1" {
		os.Setenv("LISTEN_PID", fmt.Sprintf("%d", os.Getpid()))
	}

	ln, path, err := ActivatedListener("api")
	if err != nil {
		fail("ActivatedListener: %v", err)
	}
	if ln == nil {
		fail("no activated listener claimed")
	}
	fmt.Printf("CLAIMED path=%s\n", path)

	// The retained master at fd 3 must carry FD_CLOEXEC: systemd passes it
	// without the flag, and dotvault execs children (clipboard, enrolment)
	// that must not inherit a live listening socket.
	if flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(3), syscall.F_GETFD, 0); errno != 0 {
		fail("F_GETFD on fd 3: %v", errno)
	} else if flags&syscall.FD_CLOEXEC == 0 {
		fail("inherited fd 3 lacks FD_CLOEXEC; children would inherit the listener")
	}
	fmt.Println("CLOEXEC_SET")

	if os.Getenv("LISTEN_FDS") != "" || os.Getenv("LISTEN_PID") != "" || os.Getenv("LISTEN_FDNAMES") != "" {
		fail("LISTEN_* still set after snapshot; children would inherit them")
	}
	fmt.Println("ENV_SCRUBBED")

	// Prove the adopted fd is a working listener: accept one self-dialled
	// connection.
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
		done <- err
	}()
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		fail("dial adopted listener: %v", err)
	}
	c.Close()
	if err := <-done; err != nil {
		fail("accept on adopted listener: %v", err)
	}
	fmt.Println("SERVED")

	// Re-claim after closing the listener — the supervision-loop contract.
	// A consume-once model would return nil here and the surface would
	// self-bind against systemd's node.
	ln.Close()
	ln2, _, err := ActivatedListener("api")
	if err != nil {
		fail("re-claim after close: %v", err)
	}
	if ln2 == nil {
		fail("re-claim returned no listener; activated fds must be re-claimable for listener restarts")
	}
	c2, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		fail("dial re-claimed listener: %v", err)
	}
	c2.Close()
	if conn, err := ln2.Accept(); err != nil {
		fail("accept on re-claimed listener: %v", err)
	} else {
		conn.Close()
	}
	fmt.Println("RECLAIMED")
	os.Exit(0)
}
