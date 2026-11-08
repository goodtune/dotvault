package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/goodtune/dotvault/internal/paths"
)

// Packaging-consistency tests. They assert about files two directories up
// rather than about a symbol in this package, which is unusual — they live
// here because cmd/dotvault is where the product-level view already is (it is
// what prints the registration hint in `dotvault status`), and because the
// invariant is precisely that a Go constant and a shipped data file agree.
//
// What they pin is the Docker volume plugin's socket path, which is written
// down in three places that nothing at run time compares:
//
//  1. paths.DefaultDockerSocket()            — what the daemon self-binds
//  2. dotvault-docker.socket ListenStream=   — what systemd binds under activation
//  3. dotvault-docker.tmpfiles.conf          — what the .spec file tells the engine
//
// Under activation (2) wins over the configured socket, so (3) is only correct
// while all three agree. A divergence surfaces only as "plugin not found" on a
// user's machine, which is why it is pinned here. The spec file's own path is
// pinned the same way, against paths.DefaultDockerSpecPath.
const (
	tmpfilesConf      = "dotvault-docker.tmpfiles.conf"
	tmpfilesInstalled = "/usr/share/user-tmpfiles.d/dotvault-docker.conf"
	socketUnit        = "dotvault-docker.socket"

	// runtimeDir stands in for systemd's %t specifier.
	runtimeDir = "/run/user/1000"
	// homeDir stands in for systemd's %h specifier.
	homeDir = "/home/someone"
)

func packagingFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "packaging", "linux", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// tmpfilesLine returns the fields of the drop-in's single line of the given
// type, failing if there is not exactly one. Exactly-one matters: both earlier
// versions of these tests kept the *last* match in a loop, so a correct line
// masked by a later broken one would have passed.
func tmpfilesLine(t *testing.T, typ string) []string {
	t.Helper()
	var found [][]string
	for _, line := range strings.Split(packagingFile(t, tmpfilesConf), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "f", "d":
			if fields[0] == typ {
				found = append(found, fields)
			}
		default:
			t.Fatalf("unexpected tmpfiles type %q in %q; only f and d are intended here", fields[0], line)
		}
	}
	if len(found) != 1 {
		t.Fatalf("found %d %q lines in %s, want exactly 1", len(found), typ, tmpfilesConf)
	}
	return found[0]
}

// expand renders systemd's %h and %t specifiers.
func expand(s string) string {
	return strings.NewReplacer("%h", homeDir, "%t", runtimeDir).Replace(s)
}

// The spec body the drop-in writes must name the socket the daemon binds.
func TestTmpfilesSpecMatchesDefaultDockerSocket(t *testing.T) {
	f := tmpfilesLine(t, "f")
	if len(f) < 7 {
		t.Fatalf("tmpfiles f line has too few fields: %v", f)
	}
	got := expand(strings.Join(f[6:], " "))

	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	if want := "unix://" + filepath.ToSlash(paths.DefaultDockerSocket()); got != want {
		t.Errorf("tmpfiles spec body = %q, want %q (paths.DefaultDockerSocket)", got, want)
	}
}

// ...and so must the socket unit's ListenStream=, since under activation that
// path wins over the configured one. This is the assertion the previous
// version of this test only reached transitively.
func TestSocketUnitListenStreamMatchesDefaultDockerSocket(t *testing.T) {
	var listen string
	for _, line := range strings.Split(packagingFile(t, socketUnit), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ListenStream="); ok {
			listen = v
		}
	}
	if listen == "" {
		t.Fatalf("no ListenStream= in %s", socketUnit)
	}

	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	if want := filepath.ToSlash(paths.DefaultDockerSocket()); expand(listen) != want {
		t.Errorf("ListenStream= expands to %q, want %q (paths.DefaultDockerSocket)", expand(listen), want)
	}
}

// The file the drop-in creates must be the file `dotvault status` reports on
// and the engine reads. Without this the conf and paths.DefaultDockerSpecPath
// can diverge silently, which is the same class of failure as the socket path.
func TestTmpfilesSpecPathMatchesDefaultDockerSpecPath(t *testing.T) {
	t.Setenv("HOME", homeDir)
	want := filepath.ToSlash(paths.DefaultDockerSpecPath())

	f := tmpfilesLine(t, "f")
	if got := expand(f[1]); got != want {
		t.Errorf("tmpfiles writes %q, want %q (paths.DefaultDockerSpecPath)", got, want)
	}
	// The d line must create the directory that file lives in, or a fresh
	// home gets a spec the `f` line cannot place.
	d := tmpfilesLine(t, "d")
	if got, wantDir := expand(d[1]), filepath.ToSlash(filepath.Dir(paths.DefaultDockerSpecPath())); got != wantDir {
		t.Errorf("tmpfiles creates directory %q, want %q", got, wantDir)
	}
}

// The modes must be ':'-prefixed. A bare MODE is re-applied on every run, so
// the drop-in would chmod a spec an operator had tightened to 0600 back to
// 0644 at each login — `f` protects the file's contents, not its mode.
// Verified against systemd 255: without the colon an existing 0700/0600 pair
// came back 0755/0644.
func TestTmpfilesModesAreCreateOnly(t *testing.T) {
	for _, tc := range []struct{ typ, want string }{
		{"d", ":0755"},
		{"f", ":0644"},
	} {
		if got := tmpfilesLine(t, tc.typ)[2]; got != tc.want {
			t.Errorf("tmpfiles %q line mode = %q, want %q", tc.typ, got, tc.want)
		}
	}
}

// The installed basename is the user's opt-out handle (a same-named symlink to
// /dev/null in a higher-precedence user-tmpfiles.d directory), so renaming it
// silently breaks every opt-out already in place. Pin the destination, that it
// comes from the file in this repo, and that all three packagers ship it.
func TestGoreleaserShipsTmpfilesDropIn(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", ".goreleaser.yml"))
	if err != nil {
		t.Fatalf("read .goreleaser.yml: %v", err)
	}
	var cfg struct {
		NFPMs []struct {
			Contents []struct {
				Src      string `yaml:"src"`
				Dst      string `yaml:"dst"`
				Packager string `yaml:"packager"`
				FileInfo struct {
					Mode int `yaml:"mode"`
				} `yaml:"file_info"`
			} `yaml:"contents"`
		} `yaml:"nfpms"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("parse .goreleaser.yml: %v", err)
	}
	if len(cfg.NFPMs) == 0 {
		t.Fatal("no nfpms block in .goreleaser.yml")
	}

	got := map[string]bool{}
	for _, c := range cfg.NFPMs[0].Contents {
		if c.Dst != tmpfilesInstalled {
			continue
		}
		if c.Src != "packaging/linux/"+tmpfilesConf {
			t.Errorf("%s is shipped from %q, want packaging/linux/%s", tmpfilesInstalled, c.Src, tmpfilesConf)
		}
		// YAML reads the unquoted 0644 as octal, so this is 0o644 —
		// matching the sibling socket-unit entries. Pinned because a
		// mode dropped here is a mode nfpm defaults, not one that fails.
		if c.FileInfo.Mode != 0o644 {
			t.Errorf("%s (%s) mode = %#o, want 0644 like the sibling unit entries", tmpfilesInstalled, c.Packager, c.FileInfo.Mode)
		}
		got[c.Packager] = true
	}
	for _, pkg := range []string{"rpm", "deb", "apk"} {
		if !got[pkg] {
			t.Errorf(".goreleaser.yml does not ship %s for packager %q", tmpfilesInstalled, pkg)
		}
	}
}

// pinnedUnits records, for each file .goreleaser.yml ships from
// packaging/linux, the content its pinned mtime was chosen for. The mtime is
// pinned so an upgrade that leaves a unit's bytes alone does not make every
// user manager report it changed on disk. The pin fails the other way too: an
// edited unit still carrying the old mtime is never reported, so users run
// the old unit until something else reloads. This table is what notices.
//
// When a file changes, give its entries in .goreleaser.yml a new fixed
// file_info.mtime later than the old one (the commit time of the change is
// the natural choice), then update its row here: the new SHA-256 and mtime.
var pinnedUnits = map[string]struct{ sha256, mtime string }{
	"dotvault.service":              {"cb450adae17651f2a0b9692fe08829e442bca073183ccb2f3aa332f526b48e6a", "2026-11-07T00:38:05Z"},
	"dotvault-api.socket":           {"fccbef8b2a98288fa1a1b6ad301b4dc7efd84d4c2a4b27cbe27b6e6728bb58b3", "2026-11-07T00:38:05Z"},
	"dotvault-agent.socket":         {"e82832d615ad2ea61cde7363ecd7f3d93a0b11617c36f19e007349d18c3b5c3a", "2026-11-07T00:38:05Z"},
	"dotvault-docker.socket":        {"726c3d1d712b75d893a65b6aa6e60c547c9ed750109f1a1cf372d957c9337bda", "2026-11-07T00:38:05Z"},
	"dotvault-docker.tmpfiles.conf": {"6a9c65befb5539996f2cc85691087dfd956357547ffbcc6a6dc7558eea69e261", "2026-11-07T00:38:05Z"},
}

func TestPackagedUnitMtimesArePinnedToTheirContent(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", ".goreleaser.yml"))
	if err != nil {
		t.Fatalf("read .goreleaser.yml: %v", err)
	}
	var cfg struct {
		NFPMs []struct {
			Contents []struct {
				Src      string `yaml:"src"`
				Packager string `yaml:"packager"`
				FileInfo struct {
					MTime string `yaml:"mtime"`
				} `yaml:"file_info"`
			} `yaml:"contents"`
		} `yaml:"nfpms"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("parse .goreleaser.yml: %v", err)
	}
	if len(cfg.NFPMs) == 0 {
		t.Fatal("no nfpms block in .goreleaser.yml")
	}

	shipped := map[string]bool{}
	for _, c := range cfg.NFPMs[0].Contents {
		name, ok := strings.CutPrefix(c.Src, "packaging/linux/")
		if !ok {
			continue
		}
		shipped[name] = true
		pin, ok := pinnedUnits[name]
		if !ok {
			t.Errorf("%s (%s) is shipped but has no row in pinnedUnits; pin its mtime to its commit time and add one", c.Src, c.Packager)
			continue
		}
		if c.FileInfo.MTime == "" {
			t.Errorf("%s (%s) has no file_info.mtime, so it would carry the build time", c.Src, c.Packager)
		} else if c.FileInfo.MTime != pin.mtime {
			t.Errorf("%s (%s) mtime = %s, pinnedUnits says %s", c.Src, c.Packager, c.FileInfo.MTime, pin.mtime)
		}
	}
	for name, pin := range pinnedUnits {
		if !shipped[name] {
			t.Errorf("pinnedUnits has %s, which .goreleaser.yml no longer ships", name)
			continue
		}
		// Normalise line endings so a CRLF checkout hashes the same bytes.
		content := strings.ReplaceAll(packagingFile(t, name), "\r\n", "\n")
		sum := sha256.Sum256([]byte(content))
		if got := hex.EncodeToString(sum[:]); got != pin.sha256 {
			t.Errorf("packaging/linux/%s changed since its mtime was pinned to %s: give its file_info.mtime "+
				"entries a new fixed time later than that (e.g. git log -1 --format=%%cI -- packaging/linux/%s), "+
				"then update its pinnedUnits row to that mtime and sha256 %s", name, pin.mtime, name, got)
		}
	}
}
