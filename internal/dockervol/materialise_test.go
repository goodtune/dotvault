package dockervol

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/vaultfs"
)

func readTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			out[rel+"/"] = ""
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[rel] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}

func TestMaterialiseJSONLayoutMatchesTheMount(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"oauth_token": "gho_x", "user": "gary"})
	store.put("databricks/prod", map[string]any{"token": "t"})
	dir := filepath.Join(t.TempDir(), "vol")

	n, err := materialise(context.Background(), store, dir, Spec{Layout: LayoutJSON, Mode: 0o400, TTL: time.Minute})
	if err != nil {
		t.Fatalf("materialise: %v", err)
	}
	if n != 2 {
		t.Errorf("secrets = %d, want 2", n)
	}
	got := readTree(t, dir)
	secret, _ := store.Read(context.Background(), "gh")
	doc, _ := vaultfs.RenderDocument(secret)
	if got["gh.json"] != string(doc.Bytes) {
		t.Errorf("gh.json = %q, want the mount's rendering %q", got["gh.json"], doc.Bytes)
	}
	if _, ok := got["databricks/prod.json"]; !ok {
		t.Errorf("missing databricks/prod.json in %v", got)
	}
	info, _ := os.Stat(filepath.Join(dir, "gh.json"))
	if info.Mode().Perm() != 0o400 {
		t.Errorf("mode = %o, want 0400", info.Mode().Perm())
	}
	if !info.ModTime().Equal(doc.ModTime) {
		t.Errorf("mtime = %v, want the version's created_time %v", info.ModTime(), doc.ModTime)
	}
	dinfo, _ := os.Stat(filepath.Join(dir, "databricks"))
	if dinfo.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %o, want 0700", dinfo.Mode().Perm())
	}
}

func TestMaterialiseFieldsLayout(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"oauth_token": "gho_x\n", "count": 3, "bad/name": "x"})
	dir := filepath.Join(t.TempDir(), "vol")

	if _, err := materialise(context.Background(), store, dir, Spec{Layout: LayoutFields, Mode: 0o444, TTL: time.Minute}); err != nil {
		t.Fatalf("materialise: %v", err)
	}
	got := readTree(t, dir)
	if got["gh/oauth_token"] != "gho_x\n" {
		t.Errorf("oauth_token = %q, want the value byte-for-byte", got["gh/oauth_token"])
	}
	if got["gh/count"] != "3" {
		t.Errorf("count = %q, want JSON for a non-string", got["gh/count"])
	}
	for name := range got {
		if strings.Contains(name, "bad") {
			t.Errorf("a field whose name cannot be a filename was written: %s", name)
		}
	}
	info, _ := os.Stat(filepath.Join(dir, "gh"))
	if info.Mode().Perm() != 0o755 {
		t.Errorf("dir mode = %o, want 0755 when files are 0444", info.Mode().Perm())
	}
}

func TestMaterialiseSelection(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	store.put("jfrog", map[string]any{"a": "1"})
	store.put("databricks/prod", map[string]any{"a": "1"})
	store.put("databricks/dev", map[string]any{"a": "1"})
	store.put("missing-folder-neighbour", map[string]any{"a": "1"})
	dir := filepath.Join(t.TempDir(), "vol")

	spec, err := ParseOptions(map[string]string{OptSecrets: "gh,databricks/,not-enrolled-yet"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	n, err := materialise(context.Background(), store, dir, spec)
	if err != nil {
		t.Fatalf("materialise: %v", err)
	}
	if n != 3 {
		t.Errorf("secrets = %d, want 3 (a selected secret that does not exist yet renders nothing and is not an error)", n)
	}
	got := readTree(t, dir)
	for _, want := range []string{"gh.json", "databricks/prod.json", "databricks/dev.json"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	for _, absent := range []string{"jfrog.json", "missing-folder-neighbour.json"} {
		if _, ok := got[absent]; ok {
			t.Errorf("%s was written but not selected", absent)
		}
	}
}

// A refresh converges the directory on the store: a removed secret's file
// goes, an emptied folder goes, a stray file goes, and an unchanged file
// keeps its inode so a reader is not switched mid-read for nothing.
func TestMaterialiseRefreshPrunesAndPreservesUnchanged(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	store.put("old/one", map[string]any{"a": "1"})
	dir := filepath.Join(t.TempDir(), "vol")
	spec := Spec{Layout: LayoutJSON, Mode: 0o400, TTL: time.Minute}
	if _, err := materialise(context.Background(), store, dir, spec); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(filepath.Join(dir, "gh.json"))
	if err := os.WriteFile(filepath.Join(dir, "stray"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	store.remove("old/one")

	if _, err := materialise(context.Background(), store, dir, spec); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	got := readTree(t, dir)
	if len(got) != 1 {
		t.Errorf("after refresh the directory holds %v, want only gh.json", got)
	}
	after, _ := os.Stat(filepath.Join(dir, "gh.json"))
	if !os.SameFile(before, after) {
		t.Error("an unchanged file was rewritten")
	}

	store.put("gh", map[string]any{"a": "2"})
	if _, err := materialise(context.Background(), store, dir, spec); err != nil {
		t.Fatal(err)
	}
	changed, _ := os.Stat(filepath.Join(dir, "gh.json"))
	if os.SameFile(before, changed) {
		t.Error("a changed secret must land in a new inode (atomic replace)")
	}
	if !strings.Contains(readTree(t, dir)["gh.json"], `"2"`) {
		t.Error("changed content not written")
	}
}

// A Vault failure aborts the refresh before anything is pruned: half a
// volume with the other half deleted is worse than the previous rendering.
func TestMaterialiseFailureLeavesDiskUntouched(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	dir := filepath.Join(t.TempDir(), "vol")
	spec := Spec{Layout: LayoutJSON, Mode: 0o400, TTL: time.Minute}
	if _, err := materialise(context.Background(), store, dir, spec); err != nil {
		t.Fatal(err)
	}
	store.setErr(errors.New("vault is sealed"))
	if _, err := materialise(context.Background(), store, dir, spec); err == nil {
		t.Fatal("materialise succeeded against a failing store")
	}
	if _, ok := readTree(t, dir)["gh.json"]; !ok {
		t.Error("the previous rendering was removed on a failed refresh")
	}
}

// The one filename collision the extension does not remove: a KV folder
// literally named "x.json" beside the secret "x". The directory wins, as in
// the mount.
func TestMaterialiseDirectoryWinsCollision(t *testing.T) {
	store := newMemStore()
	store.put("x", map[string]any{"a": "1"})
	store.put("x.json/child", map[string]any{"a": "1"})
	dir := filepath.Join(t.TempDir(), "vol")
	if _, err := materialise(context.Background(), store, dir, Spec{Layout: LayoutJSON, Mode: 0o400, TTL: time.Minute}); err != nil {
		t.Fatal(err)
	}
	got := readTree(t, dir)
	if _, ok := got["x.json/"]; !ok {
		t.Errorf("directory lost the collision: %v", got)
	}
	if _, ok := got["x.json/child.json"]; !ok {
		t.Errorf("child secret unreachable: %v", got)
	}
}

// Switching a name from directory to file or back (layout change on
// re-create) must not fail or nest the new file inside the old directory.
func TestMaterialiseLayoutChangeReplacesEntries(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	dir := filepath.Join(t.TempDir(), "vol")
	if _, err := materialise(context.Background(), store, dir, Spec{Layout: LayoutFields, Mode: 0o400, TTL: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if _, err := materialise(context.Background(), store, dir, Spec{Layout: LayoutJSON, Mode: 0o400, TTL: time.Minute}); err != nil {
		t.Fatalf("fields -> json: %v", err)
	}
	got := readTree(t, dir)
	if _, ok := got["gh.json"]; !ok || len(got) != 1 {
		t.Errorf("after switching to json: %v", got)
	}
	if _, err := materialise(context.Background(), store, dir, Spec{Layout: LayoutFields, Mode: 0o400, TTL: time.Minute}); err != nil {
		t.Fatalf("json -> fields: %v", err)
	}
	got = readTree(t, dir)
	if _, ok := got["gh/a"]; !ok {
		t.Errorf("after switching to fields: %v", got)
	}
	if _, ok := got["gh.json"]; ok {
		t.Errorf("stale json file survived the switch: %v", got)
	}
}
