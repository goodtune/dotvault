//go:build !windows

package uds

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestListenPermissions pins the owner-only invariant. Anyone who can connect
// to a dotvault socket can borrow the live Vault token or have the agent sign
// for them, so 0600-in-0700 is a security property, not a style choice.
func TestListenPermissions(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "sub", "api.sock")

	ln, err := Listen(sock)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	if fi, err := os.Stat(sock); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("socket perm = %v, want 0600", fi.Mode().Perm())
	}
	if fi, err := os.Stat(filepath.Dir(sock)); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Errorf("dir perm = %v, want 0700", fi.Mode().Perm())
	}
}

// TestListenTightensLooseDirectory covers the pre-existing-directory case:
// XDG_RUNTIME_DIR/dotvault may already exist from an earlier run (or another
// tool) with wider bits, and binding into it must not inherit them.
func TestListenTightensLooseDirectory(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "loose")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	ln, err := Listen(filepath.Join(sub, "api.sock"))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	if fi, err := os.Stat(sub); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Errorf("dir perm = %v, want 0700 after tightening", fi.Mode().Perm())
	}
}

// TestListenRemovesStaleSocket covers the unclean-shutdown case: a leftover
// node with nothing behind it must not block the next start.
func TestListenRemovesStaleSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "api.sock")
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := Listen(sock)
	if err != nil {
		t.Fatalf("Listen over stale socket: %v", err)
	}
	defer ln.Close()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial rebound socket: %v", err)
	}
	c.Close()
}

// TestListenRefusesLiveSocket is the other half of the stale-socket
// handling and the one that matters: a second daemon must never unlink a
// socket a running instance is serving, which would silently disconnect every
// client of the first.
func TestListenRefusesLiveSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "api.sock")

	first, err := Listen(sock)
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	defer first.Close()
	// Accept in the background so the probe dial completes.
	go func() {
		for {
			c, err := first.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	second, err := Listen(sock)
	if err == nil {
		second.Close()
		t.Fatal("second Listen succeeded, want ErrAlreadyListening")
	}
	if !errors.Is(err, ErrAlreadyListening) {
		t.Errorf("err = %v, want ErrAlreadyListening", err)
	}

	// The live socket must still be usable — the failed attempt must not
	// have removed it on its way out.
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("original socket no longer connectable: %v", err)
	}
	c.Close()
}

func TestCleanupRemovesSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "api.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()

	Cleanup(sock)
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("socket still present after Cleanup")
	}
	// An empty path and an already-removed path are both no-ops.
	Cleanup("")
	Cleanup(sock)
}

// TestRemoveStaleToleratesMissingNode is the unit-level form of the
// concurrent-cold-start race: two processes both get past the liveness probe
// on the same stale path, only one of them performs the removal, and the
// loser must not fail startup over a node that is already gone — which is the
// state it wanted in the first place.
func TestRemoveStaleToleratesMissingNode(t *testing.T) {
	dir := t.TempDir()
	absent := filepath.Join(dir, "never-existed.sock")

	if err := removeStale(absent); err != nil {
		t.Errorf("removeStale on a missing node = %v, want nil", err)
	}

	// A node that does exist is still removed.
	present := filepath.Join(dir, "stale.sock")
	if err := os.WriteFile(present, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeStale(present); err != nil {
		t.Fatalf("removeStale on an existing node = %v, want nil", err)
	}
	if _, err := os.Stat(present); !os.IsNotExist(err) {
		t.Error("stale node still present after removeStale")
	}

	// A genuine failure still surfaces: a non-empty directory cannot be
	// unlinked, standing in for the permission/IO errors worth reporting.
	stubborn := filepath.Join(dir, "notasocket")
	if err := os.MkdirAll(filepath.Join(stubborn, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := removeStale(stubborn); err == nil {
		t.Error("removeStale on an undeletable node = nil, want error")
	}
}

// TestConcurrentListenYieldsOneWinner exercises the cold-start race end to
// end: several processes racing for the same stale path must resolve to
// exactly one listener, and every loser must report it as "already
// listening" rather than as a raw bind or unlink error an operator would read
// as a dotvault bug.
func TestConcurrentListenYieldsOneWinner(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "api.sock")
	// Seed a stale node so every racer takes the probe-then-remove path.
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	const racers = 8
	var wg sync.WaitGroup
	lns := make([]net.Listener, racers)
	errs := make([]error, racers)
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			lns[i], errs[i] = Listen(sock)
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	for i := range racers {
		if errs[i] == nil {
			winners++
			lns[i].Close()
			continue
		}
		if !errors.Is(errs[i], ErrAlreadyListening) {
			t.Errorf("racer %d: err = %v, want ErrAlreadyListening", i, errs[i])
		}
	}
	if winners != 1 {
		t.Errorf("winners = %d, want exactly 1", winners)
	}
}
