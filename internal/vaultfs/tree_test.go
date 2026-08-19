package vaultfs

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func testTree(t *testing.T, store Store, rw bool, ttl time.Duration) *Tree {
	t.Helper()
	return NewTree(store, rw, ttl)
}

func TestReaddirClassifiesSecretsAndFolders(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	store.put("databricks/prod", map[string]any{"a": "1"})
	store.put("databricks/dev", map[string]any{"a": "1"})
	tree := testTree(t, store, false, 0)

	entries, err := tree.Readdir(context.Background(), "")
	if err != nil {
		t.Fatalf("Readdir: %v", err)
	}
	want := []Entry{
		{Name: "databricks", Kind: KindDir},
		{Name: "gh", Kind: KindFile},
	}
	if len(entries) != len(want) {
		t.Fatalf("entries = %v, want %v", entries, want)
	}
	for i := range want {
		if entries[i] != want[i] {
			t.Errorf("entries[%d] = %v, want %v", i, entries[i], want[i])
		}
	}

	nested, err := tree.Readdir(context.Background(), "databricks")
	if err != nil {
		t.Fatalf("Readdir nested: %v", err)
	}
	if len(nested) != 2 || nested[0].Name != "dev" || nested[1].Name != "prod" {
		t.Errorf("nested = %v, want dev and prod as files", nested)
	}
}

// A KV path that is both a secret and a folder is unsupported (see the package
// doc). The behaviour still has to be deterministic, and the direction matters:
// the folder wins so the grouped keys underneath stay reachable.
func TestReaddirFolderWinsOverColliderSecret(t *testing.T) {
	store := newMemStore()
	store.put("databricks", map[string]any{"a": "1"})
	store.put("databricks/prod", map[string]any{"a": "1"})
	tree := testTree(t, store, false, 0)

	entries, err := tree.Readdir(context.Background(), "")
	if err != nil {
		t.Fatalf("Readdir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %v, want a single entry", entries)
	}
	if entries[0].Name != "databricks" || entries[0].Kind != KindDir {
		t.Errorf("entries[0] = %v, want databricks as a directory", entries[0])
	}
}

func TestLookupUsesTheParentListing(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	tree := testTree(t, store, false, 0)

	kind, err := tree.Lookup(context.Background(), "", "gh")
	if err != nil || kind != KindFile {
		t.Fatalf("Lookup(gh) = %v, %v; want file", kind, err)
	}

	// A name a successful listing does not mention does not exist, and
	// answering that from the listing must not cost a read.
	_, readsBefore, _, _ := store.counts()
	kind, err = tree.Lookup(context.Background(), "", "missing")
	if err != nil || kind != KindNone {
		t.Fatalf("Lookup(missing) = %v, %v; want none", kind, err)
	}
	if _, readsAfter, _, _ := store.counts(); readsAfter != readsBefore {
		t.Errorf("a miss against a successful listing issued %d reads, want 0", readsAfter-readsBefore)
	}
}

// A policy can grant read on a known path without granting list on its parent.
// The listing then fails and the lookup has to fall back to reading the path,
// so a caller who knows the name can still open the file.
func TestLookupFallsBackToReadWhenListFails(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	store.listErr = errDenied
	tree := testTree(t, store, false, 0)

	kind, err := tree.Lookup(context.Background(), "", "gh")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if kind != KindFile {
		t.Errorf("kind = %v, want file", kind)
	}

	// A name the fallback read successfully finds nothing at really is
	// absent — the read answered, it just answered "no" — so this reports
	// not-found rather than the listing's failure. `ls` still surfaces the
	// listing error, because Readdir returns it unchanged.
	kind, err = tree.Lookup(context.Background(), "", "missing")
	if err != nil || kind != KindNone {
		t.Errorf("Lookup(missing) = %v, %v; want none with no error", kind, err)
	}
}

// When neither the listing nor the fallback read can answer, the listing's
// error is the one reported: the read was only a fallback, and reporting both
// would make one permission failure read as two unrelated ones.
func TestLookupReportsListErrorWhenTheFallbackAlsoFails(t *testing.T) {
	store := newMemStore()
	store.listErr = errDenied
	store.readErr = errDenied
	tree := testTree(t, store, false, 0)

	_, err := tree.Lookup(context.Background(), "", "gh")
	if err == nil {
		t.Fatal("Lookup returned no error when both list and read failed")
	}
	if !errors.Is(err, errDenied) {
		t.Errorf("error = %v, want it to wrap the denial", err)
	}
}

func TestDocumentRendersDataAsIndentedJSON(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"oauth_token": "gho_x", "user": "gary"})
	tree := testTree(t, store, false, 0)

	doc, err := tree.Document(context.Background(), "gh")
	if err != nil {
		t.Fatalf("Document: %v", err)
	}
	if doc == nil {
		t.Fatal("Document returned nil for an existing secret")
	}
	var back map[string]any
	if err := json.Unmarshal(doc.Bytes, &back); err != nil {
		t.Fatalf("rendered document is not JSON: %v", err)
	}
	if back["oauth_token"] != "gho_x" {
		t.Errorf("oauth_token = %v, want gho_x", back["oauth_token"])
	}
	if doc.Size() != int64(len(doc.Bytes)) {
		t.Errorf("Size() = %d, want %d", doc.Size(), len(doc.Bytes))
	}
	if doc.ModTime.IsZero() {
		t.Error("ModTime is zero; the version's created_time should carry through")
	}
}

func TestDocumentMissingSecretIsNotAnError(t *testing.T) {
	tree := testTree(t, newMemStore(), false, 0)
	doc, err := tree.Document(context.Background(), "nope")
	if err != nil {
		t.Fatalf("Document: %v", err)
	}
	if doc != nil {
		t.Errorf("doc = %v, want nil for a missing secret", doc)
	}
}

func TestReadOnlyTreeRefusesMutations(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	tree := testTree(t, store, false, 0)

	if err := tree.Put(context.Background(), "gh", []byte(`{"a":"2"}`)); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Put error = %v, want ErrReadOnly", err)
	}
	if err := tree.Remove(context.Background(), "gh"); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Remove error = %v, want ErrReadOnly", err)
	}
	// The guard must stop the call before it reaches Vault, not merely
	// report an error after the write landed.
	if _, _, writes, deletes := store.counts(); writes != 0 || deletes != 0 {
		t.Errorf("read-only tree reached the store: %d writes, %d deletes", writes, deletes)
	}
}

// The read-only check must run before the document is parsed, so a read-only
// mount reports EROFS rather than complaining about the content it was never
// going to write.
func TestReadOnlyTreeRefusesBeforeParsing(t *testing.T) {
	tree := testTree(t, newMemStore(), false, 0)
	if err := tree.Put(context.Background(), "gh", []byte("not json")); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Put error = %v, want ErrReadOnly", err)
	}
}

func TestPutWritesAndInvalidatesCache(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	tree := testTree(t, store, true, time.Hour)

	// Warm the cache so a stale answer is possible if invalidation is missed.
	if _, err := tree.Document(context.Background(), "gh"); err != nil {
		t.Fatalf("warm: %v", err)
	}
	if err := tree.Put(context.Background(), "gh", []byte(`{"a":"2"}`)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	doc, err := tree.Document(context.Background(), "gh")
	if err != nil {
		t.Fatalf("Document: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(doc.Bytes, &back); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if back["a"] != "2" {
		t.Errorf("a = %v, want 2 — the cache was not invalidated by the write", back["a"])
	}
}

func TestRemoveDeletesAndInvalidatesListing(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	store.put("other", map[string]any{"a": "1"})
	tree := testTree(t, store, true, time.Hour)

	if _, err := tree.Readdir(context.Background(), ""); err != nil {
		t.Fatalf("warm: %v", err)
	}
	if err := tree.Remove(context.Background(), "gh"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	entries, err := tree.Readdir(context.Background(), "")
	if err != nil {
		t.Fatalf("Readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "other" {
		t.Errorf("entries = %v, want only 'other' — the parent listing was not invalidated", entries)
	}
}

func TestCleanPathRejectsTraversal(t *testing.T) {
	// Vault treats path segments literally and does not collapse "..", so
	// the tree must reject rather than clean: "a/../b" naming a different
	// Vault path than the caller wrote is exactly the confusion to avoid.
	for _, p := range []string{"..", "a/../b", "a//b", "a/./b", "a/\x00b"} {
		if _, err := cleanPath(p); !errors.Is(err, ErrInvalidName) {
			t.Errorf("cleanPath(%q) error = %v, want ErrInvalidName", p, err)
		}
	}
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"/", ""},
		{"gh", "gh"},
		{"/gh/", "gh"},
		{"databricks/prod", "databricks/prod"},
	} {
		got, err := cleanPath(tc.in)
		if err != nil {
			t.Errorf("cleanPath(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("cleanPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPutRejectsTheRoot(t *testing.T) {
	tree := testTree(t, newMemStore(), true, 0)
	if err := tree.Put(context.Background(), "", []byte(`{"a":"1"}`)); !errors.Is(err, ErrInvalidName) {
		t.Errorf("Put on the root = %v, want ErrInvalidName", err)
	}
	if err := tree.Remove(context.Background(), "/"); !errors.Is(err, ErrInvalidName) {
		t.Errorf("Remove of the root = %v, want ErrInvalidName", err)
	}
}
