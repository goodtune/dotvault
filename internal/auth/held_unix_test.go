//go:build unix

package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The envelope is written by temp file and rename, so a rotation always
// lands as a new inode. On a filesystem with a coarse mtime a rotation that
// keeps the size and lands in the same tick looks identical by mtime and
// size; the file identity is what still tells the two apart.
func TestStatCredentialSeesSameSizeSameTickRename(t *testing.T) {
	dir := t.TempDir()
	path := credentialPath(dir)
	tick := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.WriteFile(path, []byte(`{"v":"aaaa"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, tick, tick); err != nil {
		t.Fatal(err)
	}
	before, err := StatCredential(dir)
	if err != nil {
		t.Fatal(err)
	}

	tmp := filepath.Join(dir, "credential.json.tmp")
	if err := os.WriteFile(tmp, []byte(`{"v":"bbbb"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmp, tick, tick); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	after, err := StatCredential(dir)
	if err != nil {
		t.Fatal(err)
	}
	if after.ModTime != before.ModTime || after.Size != before.Size {
		t.Fatalf("test setup: mtime/size differ (%+v vs %+v)", after, before)
	}
	if after == before {
		t.Fatal("a rename-replaced envelope with the same size and mtime reads as the same version")
	}
}
