package vaultfs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/clientcert"
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
		{Name: "gh.json", Kind: KindFile},
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
	if len(nested) != 2 || nested[0].Name != "dev.json" || nested[1].Name != "prod.json" {
		t.Errorf("nested = %v, want dev.json and prod.json as files", nested)
	}
}

// A secret and a folder sharing a KV name used to be an unsupported collision:
// one filesystem name could not be both. The extension removes it — they
// become two different filenames, and both stay reachable.
func TestReaddirSecretAndFolderOfTheSameNameCoexist(t *testing.T) {
	store := newMemStore()
	store.put("databricks", map[string]any{"a": "1"})
	store.put("databricks/prod", map[string]any{"a": "1"})
	tree := testTree(t, store, false, 0)

	entries, err := tree.Readdir(context.Background(), "")
	if err != nil {
		t.Fatalf("Readdir: %v", err)
	}
	want := []Entry{
		{Name: "databricks", Kind: KindDir},
		{Name: "databricks.json", Kind: KindFile},
	}
	if len(entries) != len(want) {
		t.Fatalf("entries = %v, want %v", entries, want)
	}
	for i := range want {
		if entries[i] != want[i] {
			t.Errorf("entries[%d] = %v, want %v", i, entries[i], want[i])
		}
	}

	// Both are genuinely readable, which is the whole point.
	if doc, err := tree.Document(context.Background(), "databricks.json"); err != nil || doc == nil {
		t.Errorf("Document(databricks.json) = %v, %v; want the shadowed secret to be reachable", doc, err)
	}
	nested, err := tree.Readdir(context.Background(), "databricks")
	if err != nil || len(nested) != 1 || nested[0].Name != "prod.json" {
		t.Errorf("Readdir(databricks) = %v, %v; want prod.json", nested, err)
	}
}

// What the extension does not remove: a KV folder whose name already ends in
// it collides with the secret of the same stem. The directory wins, so the
// secrets underneath stay reachable, and the daemon warns.
func TestReaddirFolderNamedWithTheExtensionShadowsTheSecret(t *testing.T) {
	store := newMemStore()
	store.put("report", map[string]any{"a": "1"})            // displays as report.json
	store.put("report.json/child", map[string]any{"a": "1"}) // folder named report.json
	tree := testTree(t, store, false, 0)

	entries, err := tree.Readdir(context.Background(), "")
	if err != nil {
		t.Fatalf("Readdir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %v, want a single entry", entries)
	}
	if entries[0].Name != "report.json" || entries[0].Kind != KindDir {
		t.Errorf("entries[0] = %v, want report.json as a directory", entries[0])
	}
}

func TestLookupUsesTheParentListing(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	tree := testTree(t, store, false, 0)

	kind, err := tree.Lookup(context.Background(), "", "gh.json")
	if err != nil || kind != KindFile {
		t.Fatalf("Lookup(gh.json) = %v, %v; want file", kind, err)
	}

	// A name a successful listing does not mention does not exist, and
	// answering that from the listing must not cost a read.
	_, readsBefore, _, _ := store.counts()
	kind, err = tree.Lookup(context.Background(), "", "missing.json")
	if err != nil || kind != KindNone {
		t.Fatalf("Lookup(missing.json) = %v, %v; want none", kind, err)
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

	kind, err := tree.Lookup(context.Background(), "", "gh.json")
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
	kind, err = tree.Lookup(context.Background(), "", "missing.json")
	if err != nil || kind != KindNone {
		t.Errorf("Lookup(missing.json) = %v, %v; want none with no error", kind, err)
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

	_, err := tree.Lookup(context.Background(), "", "gh.json")
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

	doc, err := tree.Document(context.Background(), "gh.json")
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
	doc, err := tree.Document(context.Background(), "nope.json")
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

	if err := tree.Put(context.Background(), "gh.json", []byte(`{"a":"2"}`)); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Put error = %v, want ErrReadOnly", err)
	}
	if err := tree.Remove(context.Background(), "gh.json"); !errors.Is(err, ErrReadOnly) {
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
	if err := tree.Put(context.Background(), "gh.json", []byte("not json")); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Put error = %v, want ErrReadOnly", err)
	}
}

func TestPutWritesAndInvalidatesCache(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	tree := testTree(t, store, true, time.Hour)

	// Warm the cache so a stale answer is possible if invalidation is missed.
	if _, err := tree.Document(context.Background(), "gh.json"); err != nil {
		t.Fatalf("warm: %v", err)
	}
	if err := tree.Put(context.Background(), "gh.json", []byte(`{"a":"2"}`)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	doc, err := tree.Document(context.Background(), "gh.json")
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
	if err := tree.Remove(context.Background(), "gh.json"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	entries, err := tree.Readdir(context.Background(), "")
	if err != nil {
		t.Fatalf("Readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "other.json" {
		t.Errorf("entries = %v, want only other.json — the parent listing was not invalidated", entries)
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

// The prefix is what makes "a mounted filesystem cannot address another user's
// secrets" structural, so the values it is composed from are validated rather
// than assumed.
func TestNewStoreRejectsAnEscapingIdentity(t *testing.T) {
	for _, tc := range []struct{ name, username, prefix string }{
		{"username with a slash", "gary/../root", "users/"},
		{"username is dotdot", "..", "users/"},
		{"username with a NUL", "gary\x00", "users/"},
		{"prefix with a traversal", "gary", "users/../"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewStore(stubKVClient{}, "kv", tc.prefix, tc.username); err == nil {
				t.Error("NewStore accepted an identity that escapes the user's prefix")
			}
		})
	}
}

// fakeCertSource is a clientcert.Source whose pair (or error) a test swaps at
// will, counting how often it was asked.
type fakeCertSource struct {
	mu    sync.Mutex
	pair  *clientcert.Pair
	err   error
	calls int
}

func (f *fakeCertSource) Current(context.Context) (*clientcert.Pair, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.pair, nil
}

func (f *fakeCertSource) set(p *clientcert.Pair, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pair, f.err = p, err
}

func (f *fakeCertSource) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// testPair builds a pair whose PEM bytes are recognisable by tag, so a test
// can tell which pair a file came from. The bytes are not real certificates:
// the tree never parses them.
func testPair(tag string) *clientcert.Pair {
	nb := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	return &clientcert.Pair{
		CertPEM:    []byte("-----BEGIN CERTIFICATE-----\n" + tag + "-cert\n-----END CERTIFICATE-----\n"),
		KeyPEM:     []byte("-----BEGIN PRIVATE KEY-----\n" + tag + "-key\n-----END PRIVATE KEY-----\n"),
		NotBefore:  nb,
		NotAfter:   nb.Add(5 * time.Minute),
		RefreshAt:  nb.Add(150 * time.Second),
		Serial:     tag,
		CommonName: "gary",
		Source:     clientcert.SourceEphemeral,
	}
}

func certTree(t *testing.T, store Store, rw bool, ttl time.Duration, src clientcert.Source) *Tree {
	t.Helper()
	tree := NewTree(store, rw, ttl)
	tree.SetClientCert(src)
	return tree
}

func TestIsClientCertPath(t *testing.T) {
	for p, want := range map[string]bool{
		ClientCertFile:          true,
		ClientKeyFile:           true,
		ClientPEMFile:           true,
		"sub/" + ClientCertFile: false,
		"client.crt.json":       false,
		"client":                false,
		"":                      false,
	} {
		if got := IsClientCertPath(p); got != want {
			t.Errorf("IsClientCertPath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestTreeRootListsClientCertFiles(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	src := &fakeCertSource{pair: testPair("A")}
	tree := certTree(t, store, false, 0, src)

	entries, err := tree.Readdir(context.Background(), "")
	if err != nil {
		t.Fatalf("Readdir: %v", err)
	}
	want := []Entry{
		{Name: ClientCertFile, Kind: KindFile},
		{Name: ClientKeyFile, Kind: KindFile},
		{Name: ClientPEMFile, Kind: KindFile},
		{Name: "gh.json", Kind: KindFile},
	}
	if len(entries) != len(want) {
		t.Fatalf("entries = %v, want %v", entries, want)
	}
	for i := range want {
		if entries[i] != want[i] {
			t.Errorf("entries[%d] = %v, want %v", i, entries[i], want[i])
		}
	}
	// Listing must not sign anything: an `ls` is not a reason to reach PKI.
	if n := src.count(); n != 0 {
		t.Errorf("Readdir asked the source %d times, want 0", n)
	}

	// Lookup answers the certificate names before any Vault call, so they
	// resolve even when the root cannot be listed.
	store.mu.Lock()
	store.listErr = errors.New("permission denied")
	store.mu.Unlock()
	tree.InvalidateAll()
	listsBefore, readsBefore, _, _ := store.counts()
	for _, name := range []string{ClientCertFile, ClientKeyFile, ClientPEMFile} {
		kind, err := tree.Lookup(context.Background(), "", name)
		if err != nil || kind != KindFile {
			t.Errorf("Lookup(%s) = %v, %v; want file", name, kind, err)
		}
	}
	if lists, reads, _, _ := store.counts(); lists != listsBefore || reads != readsBefore {
		t.Errorf("Lookup of certificate names reached the store: %d lists, %d reads", lists-listsBefore, reads-readsBefore)
	}
}

func TestTreeClientCertAbsentWithoutSource(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	tree := testTree(t, store, true, 0)

	entries, err := tree.Readdir(context.Background(), "")
	if err != nil {
		t.Fatalf("Readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "gh.json" {
		t.Errorf("entries = %v, want only gh.json", entries)
	}
	for _, name := range []string{ClientCertFile, ClientKeyFile, ClientPEMFile} {
		if kind, err := tree.Lookup(context.Background(), "", name); err != nil || kind != KindNone {
			t.Errorf("Lookup(%s) = %v, %v; want none", name, kind, err)
		}
		if doc, err := tree.Document(context.Background(), name); err != nil || doc != nil {
			t.Errorf("Document(%s) = %v, %v; want nil, nil", name, doc, err)
		}
	}
}

func TestTreeClientCertDocumentsShareOnePair(t *testing.T) {
	pair := testPair("A")
	tree := certTree(t, newMemStore(), false, 0, &fakeCertSource{pair: pair})
	ctx := context.Background()

	crt, err := tree.Document(ctx, ClientCertFile)
	if err != nil || crt == nil {
		t.Fatalf("Document(crt) = %v, %v", crt, err)
	}
	key, err := tree.Document(ctx, ClientKeyFile)
	if err != nil || key == nil {
		t.Fatalf("Document(key) = %v, %v", key, err)
	}
	pem, err := tree.Document(ctx, ClientPEMFile)
	if err != nil || pem == nil {
		t.Fatalf("Document(pem) = %v, %v", pem, err)
	}

	if !bytes.Equal(crt.Bytes, pair.CertPEM) {
		t.Errorf("client.crt = %q, want the pair's CertPEM", crt.Bytes)
	}
	if !bytes.Equal(key.Bytes, pair.KeyPEM) {
		t.Errorf("client.key = %q, want the pair's KeyPEM", key.Bytes)
	}
	if want := append(append([]byte(nil), crt.Bytes...), key.Bytes...); !bytes.Equal(pem.Bytes, want) {
		t.Errorf("client.pem = %q, want crt followed by key", pem.Bytes)
	}
	for name, doc := range map[string]*Document{"crt": crt, "key": key, "pem": pem} {
		if !doc.ModTime.Equal(pair.NotBefore) {
			t.Errorf("%s ModTime = %s, want NotBefore %s", name, doc.ModTime, pair.NotBefore)
		}
		if doc.Version != 0 {
			t.Errorf("%s Version = %d, want 0", name, doc.Version)
		}
	}

	// The documents must not alias the shared pair: a consumer mutating its
	// bytes would otherwise corrupt every other reader's view.
	crt.Bytes[0] = 'X'
	if pair.CertPEM[0] == 'X' {
		t.Error("client.crt document aliases the pair's CertPEM")
	}
}

func TestTreeClientCertBypassesCache(t *testing.T) {
	store := newMemStore()
	src := &fakeCertSource{pair: testPair("A")}
	tree := certTree(t, store, false, 30*time.Second, src)
	ctx := context.Background()

	first, err := tree.Document(ctx, ClientPEMFile)
	if err != nil || first == nil {
		t.Fatalf("Document #1 = %v, %v", first, err)
	}
	src.set(testPair("BB"), nil)
	second, err := tree.Document(ctx, ClientPEMFile)
	if err != nil || second == nil {
		t.Fatalf("Document #2 = %v, %v", second, err)
	}

	if !bytes.Contains(first.Bytes, []byte("A-cert")) {
		t.Errorf("first read = %q, want pair A", first.Bytes)
	}
	if !bytes.Contains(second.Bytes, []byte("BB-cert")) {
		t.Errorf("second read = %q, want pair B despite a 30s cache", second.Bytes)
	}
	if n := src.count(); n != 2 {
		t.Errorf("source asked %d times, want 2 (once per Document)", n)
	}
	if _, reads, _, _ := store.counts(); reads != 0 {
		t.Errorf("certificate reads reached the store %d times, want 0", reads)
	}
}

func TestTreeClientCertReadOnlyOnReadWriteMount(t *testing.T) {
	store := newMemStore()
	tree := certTree(t, store, true, 0, &fakeCertSource{pair: testPair("A")})
	ctx := context.Background()

	for _, name := range []string{ClientCertFile, ClientKeyFile, ClientPEMFile} {
		if err := tree.Put(ctx, name, []byte(`{"a":"1"}`)); !errors.Is(err, ErrReadOnly) {
			t.Errorf("Put(%s) error = %v, want ErrReadOnly", name, err)
		}
		if err := tree.Remove(ctx, name); !errors.Is(err, ErrReadOnly) {
			t.Errorf("Remove(%s) error = %v, want ErrReadOnly", name, err)
		}
	}
	if _, _, writes, deletes := store.counts(); writes != 0 || deletes != 0 {
		t.Errorf("certificate mutations reached the store: %d writes, %d deletes", writes, deletes)
	}
}

func TestTreeClientCertWinsCollision(t *testing.T) {
	store := newMemStore()
	store.put("client.crt/child", map[string]any{"a": "1"})
	store.put("gh", map[string]any{"a": "1"})
	tree := certTree(t, store, false, 0, &fakeCertSource{pair: testPair("A")})

	entries, err := tree.Readdir(context.Background(), "")
	if err != nil {
		t.Fatalf("Readdir: %v", err)
	}
	var found int
	for _, e := range entries {
		if e.Name == ClientCertFile {
			found++
			if e.Kind != KindFile {
				t.Errorf("%s listed as %v, want the certificate file", e.Name, e.Kind)
			}
		}
	}
	if found != 1 {
		t.Errorf("%s appears %d times in %v, want once", ClientCertFile, found, entries)
	}
	if kind, err := tree.Lookup(context.Background(), "", ClientCertFile); err != nil || kind != KindFile {
		t.Errorf("Lookup(%s) = %v, %v; want file", ClientCertFile, kind, err)
	}
}

func TestTreeClientCertNotAtDepth(t *testing.T) {
	store := newMemStore()
	store.put("sub/gh", map[string]any{"a": "1"})
	src := &fakeCertSource{pair: testPair("A")}
	tree := certTree(t, store, true, 0, src)
	ctx := context.Background()

	entries, err := tree.Readdir(ctx, "sub")
	if err != nil {
		t.Fatalf("Readdir(sub): %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "gh.json" {
		t.Errorf("Readdir(sub) = %v, want only gh.json", entries)
	}
	if kind, err := tree.Lookup(ctx, "sub", ClientCertFile); err != nil || kind != KindNone {
		t.Errorf("Lookup(sub, %s) = %v, %v; want none", ClientCertFile, kind, err)
	}
	if doc, err := tree.Document(ctx, "sub/"+ClientCertFile); err != nil || doc != nil {
		t.Errorf("Document(sub/%s) = %v, %v; want nil, nil", ClientCertFile, doc, err)
	}
	// At depth the name is ordinary: a mutation is refused for its missing
	// extension, not for being a certificate.
	if err := tree.Put(ctx, "sub/"+ClientCertFile, []byte(`{"a":"1"}`)); !errors.Is(err, ErrInvalidName) {
		t.Errorf("Put(sub/%s) error = %v, want ErrInvalidName", ClientCertFile, err)
	}
	if n := src.count(); n != 0 {
		t.Errorf("source asked %d times for paths below the root, want 0", n)
	}
}

func TestTreeClientCertSourceError(t *testing.T) {
	src := &fakeCertSource{pair: testPair("A")}
	tree := certTree(t, newMemStore(), false, 0, src)
	ctx := context.Background()

	// A successful read first, so a message that leaked a previously served
	// pair would have something to leak.
	if _, err := tree.Document(ctx, ClientPEMFile); err != nil {
		t.Fatalf("Document: %v", err)
	}
	src.set(nil, clientcert.ErrNoToken)
	doc, err := tree.Document(ctx, ClientPEMFile)
	if doc != nil {
		t.Errorf("doc = %v, want nil on a source error", doc)
	}
	if !errors.Is(err, clientcert.ErrNoToken) {
		t.Fatalf("error = %v, want it to wrap clientcert.ErrNoToken", err)
	}
	if strings.Contains(err.Error(), "BEGIN") {
		t.Errorf("error %q carries PEM", err)
	}

	// A source that returns neither a pair nor an error is a bug in the
	// source, reported as an error rather than a nil dereference.
	src.set(nil, nil)
	if _, err := tree.Document(ctx, ClientCertFile); err == nil {
		t.Error("Document with a nil pair returned no error")
	}
}
