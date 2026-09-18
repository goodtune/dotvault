package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/paths"
)

// The three places the volume-plugin socket path is written down, which must
// agree or the packaged .spec file registers a socket nothing is listening on:
//
//  1. paths.DefaultDockerSocket()            — what the daemon self-binds
//  2. dotvault-docker.socket ListenStream=   — what systemd binds under activation
//  3. dotvault-docker.tmpfiles.conf          — what the .spec file tells the engine
//
// Under activation (2) wins over the configured socket, so (3) is only correct
// while (1), (2) and (3) name the same path. Nothing at run time compares them —
// a divergence shows up as "plugin not found" on a user's machine — so it is
// pinned here instead.
const (
	tmpfilesConf      = "dotvault-docker.tmpfiles.conf"
	tmpfilesInstalled = "/usr/share/user-tmpfiles.d/dotvault-docker.conf"
	specFileName      = "dotvault.spec"
)

func packagingFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "packaging", "linux", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// directives returns the non-comment, non-blank lines of a packaging file.
func directives(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// dockerSocketFor renders paths.DefaultDockerSocket() with runtimeDir standing
// in for systemd's %t specifier.
func dockerSocketFor(t *testing.T, runtimeDir string) string {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	return paths.DefaultDockerSocket()
}

func TestTmpfilesSpecMatchesDefaultDockerSocket(t *testing.T) {
	const runtimeDir = "/run/user/1000"

	var arg string
	for _, line := range directives(packagingFile(t, tmpfilesConf)) {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "f" {
			continue
		}
		// type path mode user group age argument...
		if len(fields) < 7 {
			t.Fatalf("tmpfiles f line has too few fields: %q", line)
		}
		if !strings.HasSuffix(fields[1], "/"+specFileName) {
			t.Fatalf("tmpfiles f line does not write %s: %q", specFileName, line)
		}
		arg = strings.Join(fields[6:], " ")
	}
	if arg == "" {
		t.Fatalf("no f line found in %s", tmpfilesConf)
	}

	want := "unix://" + dockerSocketFor(t, runtimeDir)
	got := strings.ReplaceAll(arg, "%t", runtimeDir)
	if got != want {
		t.Errorf("tmpfiles spec body = %q, want %q (paths.DefaultDockerSocket)", got, want)
	}
}

func TestTmpfilesSpecMatchesSocketUnitListenStream(t *testing.T) {
	const runtimeDir = "/run/user/1000"

	var listen string
	for _, line := range directives(packagingFile(t, "dotvault-docker.socket")) {
		if v, ok := strings.CutPrefix(line, "ListenStream="); ok {
			listen = v
		}
	}
	if listen == "" {
		t.Fatal("no ListenStream= in dotvault-docker.socket")
	}

	want := "unix://" + strings.ReplaceAll(listen, "%t", runtimeDir)
	if want != "unix://"+dockerSocketFor(t, runtimeDir) {
		t.Fatalf("ListenStream=%s does not match paths.DefaultDockerSocket", listen)
	}

	var arg string
	for _, line := range directives(packagingFile(t, tmpfilesConf)) {
		if fields := strings.Fields(line); len(fields) >= 7 && fields[0] == "f" {
			arg = strings.Join(fields[6:], " ")
		}
	}
	if got := strings.ReplaceAll(arg, "%t", runtimeDir); got != want {
		t.Errorf("tmpfiles spec body = %q, want %q (socket unit ListenStream=)", got, want)
	}
}

// The `f` type writes its argument only when creating the file. `f+` truncates
// and rewrites on every login, which would overwrite a spec an operator wrote
// by hand for a customised socket path — the whole reason this drop-in is safe
// to ship. See the file's own header.
func TestTmpfilesNeverTruncatesExistingSpec(t *testing.T) {
	for _, line := range directives(packagingFile(t, tmpfilesConf)) {
		switch strings.Fields(line)[0] {
		case "f", "d":
		default:
			t.Errorf("unexpected tmpfiles type in %q; only f and d are intended here", line)
		}
	}
}

// The installed basename is the user's opt-out handle (a same-named symlink to
// /dev/null in a higher-precedence user-tmpfiles.d directory), so renaming it
// silently breaks every opt-out already in place. Pin the destination, and pin
// that all three packagers get it.
func TestGoreleaserShipsTmpfilesDropIn(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", ".goreleaser.yml"))
	if err != nil {
		t.Fatalf("read .goreleaser.yml: %v", err)
	}
	s := string(b)
	if n := strings.Count(s, "dst: "+tmpfilesInstalled); n != 3 {
		t.Errorf("%s appears as an nfpm dst %d times, want 3 (rpm, deb, apk)", tmpfilesInstalled, n)
	}
	if !strings.Contains(s, "src: packaging/linux/"+tmpfilesConf) {
		t.Errorf(".goreleaser.yml does not ship packaging/linux/%s", tmpfilesConf)
	}
}
