package remoteconfig

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/paths"
)

const testDoc = `rules:
  - name: aws
    vault_key: aws
    target:
      path: ~/.aws/credentials
      format: ini
`

func newTestFetcher(t *testing.T, rc config.RemoteConfig) *Fetcher {
	t.Helper()
	f, err := New(rc, "test-version", WithCachePath(filepath.Join(t.TempDir(), "remote-config.json")))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f
}

func TestFetchFreshAndNotModified(t *testing.T) {
	const etag = `"abc123"`
	var requests int
	var lastIfNoneMatch string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		lastIfNoneMatch = r.Header.Get("If-None-Match")
		if lastIfNoneMatch == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", "application/yaml")
		w.Write([]byte(testDoc))
	}))
	defer srv.Close()

	f := newTestFetcher(t, config.RemoteConfig{URL: srv.URL})

	p, err := f.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if p == nil || len(p.Rules) != 1 || p.Rules[0].Name != "aws" {
		t.Fatalf("first fetch partial = %+v", p)
	}
	if st := f.Status(); st.Source != "remote" || st.ETag != etag || st.LastError != "" {
		t.Errorf("status after fresh fetch = %+v", st)
	}

	// Second fetch must revalidate with If-None-Match and serve the cache.
	p, err = f.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch (revalidate): %v", err)
	}
	if p == nil || len(p.Rules) != 1 {
		t.Fatalf("revalidated partial = %+v", p)
	}
	if lastIfNoneMatch != etag {
		t.Errorf("If-None-Match = %q, want %q", lastIfNoneMatch, etag)
	}
	if st := f.Status(); st.Source != "remote" || st.ETag != etag {
		t.Errorf("status after 304 = %+v", st)
	}
	if requests != 2 {
		t.Errorf("requests = %d, want 2", requests)
	}
}

func TestFetchSendsIdentityHeaders(t *testing.T) {
	username, err := paths.Username()
	if err != nil {
		t.Fatalf("Username: %v", err)
	}
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Write([]byte(testDoc))
	}))
	defer srv.Close()

	f := newTestFetcher(t, config.RemoteConfig{
		URL:     srv.URL,
		Headers: map[string]string{"X-Dotvault-Env": "production"},
	})
	if _, err := f.Fetch(t.Context()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	want := map[string]string{
		"X-Dotvault-Os":      runtime.GOOS,
		"X-Dotvault-User":    username,
		"X-Dotvault-Arch":    runtime.GOARCH,
		"X-Dotvault-Version": "test-version",
		"X-Dotvault-Env":     "production",
	}
	for name, value := range want {
		if got.Get(name) != value {
			t.Errorf("header %s = %q, want %q", name, got.Get(name), value)
		}
	}
}

// TestFetchExtrasCannotOverrideBuiltins is belt-and-braces below the config
// validation that already rejects the collision: even on a config that
// skipped validation, the built-in identity header wins.
func TestFetchExtrasCannotOverrideBuiltins(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Write([]byte(testDoc))
	}))
	defer srv.Close()

	f := newTestFetcher(t, config.RemoteConfig{
		URL:     srv.URL,
		Headers: map[string]string{"X-Dotvault-OS": "spoofed"},
	})
	if _, err := f.Fetch(t.Context()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.Get("X-Dotvault-OS") != runtime.GOOS {
		t.Errorf("X-Dotvault-OS = %q, want built-in %q", got.Get("X-Dotvault-OS"), runtime.GOOS)
	}
}

func TestFetchServerErrorFallsBackToCache(t *testing.T) {
	var fail bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte(testDoc))
	}))
	defer srv.Close()

	f := newTestFetcher(t, config.RemoteConfig{URL: srv.URL})
	if _, err := f.Fetch(t.Context()); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}

	fail = true
	p, err := f.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch with failing server: %v", err)
	}
	if p == nil || len(p.Rules) != 1 {
		t.Fatalf("expected cached document, got %+v", p)
	}
	st := f.Status()
	if st.Source != "cache" || st.ETag != `"v1"` || st.LastError == "" {
		t.Errorf("status after fallback = %+v", st)
	}
}

func TestFetchUnreachableNoCacheReturnsNil(t *testing.T) {
	// Bind-then-close so the port is known-refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	f := newTestFetcher(t, config.RemoteConfig{URL: url})
	p, err := f.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if p != nil {
		t.Fatalf("expected nil partial, got %+v", p)
	}
	st := f.Status()
	if st.Source != "none" || st.LastError == "" {
		t.Errorf("status = %+v", st)
	}
}

func TestFetchCacheSurvivesProcessRestart(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte(testDoc))
	}))
	cachePath := filepath.Join(t.TempDir(), "remote-config.json")

	f1, err := New(config.RemoteConfig{URL: srv.URL}, "test-version", WithCachePath(cachePath))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := f1.Fetch(t.Context()); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}
	srv.Close()

	// A new fetcher (same identity, same cache path) simulates a process
	// restart while the service is down: the cache must carry it.
	f2, err := New(config.RemoteConfig{URL: srv.URL}, "test-version", WithCachePath(cachePath))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p, err := f2.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch after restart: %v", err)
	}
	if p == nil || len(p.Rules) != 1 {
		t.Fatalf("expected cached document after restart, got %+v", p)
	}
	if st := f2.Status(); st.Source != "cache" {
		t.Errorf("Source = %q, want cache", st.Source)
	}
}

func TestFetchCacheIdentityMismatchIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(testDoc))
	}))
	cachePath := filepath.Join(t.TempDir(), "remote-config.json")

	f1, err := New(config.RemoteConfig{URL: srv.URL}, "test-version", WithCachePath(cachePath))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := f1.Fetch(t.Context()); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}
	srv.Close()

	// Different extra headers ⇒ different request identity ⇒ the cached
	// document must not be replayed.
	f2, err := New(config.RemoteConfig{
		URL:     srv.URL,
		Headers: map[string]string{"X-Dotvault-Env": "other"},
	}, "test-version", WithCachePath(cachePath))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p, err := f2.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if p != nil {
		t.Fatalf("identity-mismatched cache was replayed: %+v", p)
	}
	if st := f2.Status(); st.Source != "none" {
		t.Errorf("Source = %q, want none", st.Source)
	}
}

func TestFetchCacheFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode bits not meaningful on Windows")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(testDoc))
	}))
	defer srv.Close()

	cachePath := filepath.Join(t.TempDir(), "remote-config.json")
	f, err := New(config.RemoteConfig{URL: srv.URL}, "test-version", WithCachePath(cachePath))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := f.Fetch(t.Context()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	info, err := os.Stat(cachePath)
	if err != nil {
		t.Fatalf("stat cache: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("cache mode = %o, want 0600", info.Mode().Perm())
	}

	var env envelope
	data, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("parse cache: %v", err)
	}
	if env.Schema != cacheSchema || env.URL != srv.URL || env.Body != testDoc {
		t.Errorf("envelope = %+v", env)
	}
}

func TestFetchOversizeDocumentRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# " + strings.Repeat("x", maxDocumentBytes) + "\n"))
	}))
	defer srv.Close()

	f := newTestFetcher(t, config.RemoteConfig{URL: srv.URL})
	p, err := f.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if p != nil {
		t.Fatalf("oversize document accepted: %+v", p)
	}
	if st := f.Status(); !strings.Contains(st.LastError, "exceeds") {
		t.Errorf("LastError = %q, want size complaint", st.LastError)
	}
}

func TestFetchStaticSectionRejectedFallsBack(t *testing.T) {
	var serveBad bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveBad {
			w.Write([]byte("vault:\n  address: https://evil.example.com\n"))
			return
		}
		w.Write([]byte(testDoc))
	}))
	defer srv.Close()

	f := newTestFetcher(t, config.RemoteConfig{URL: srv.URL})
	if _, err := f.Fetch(t.Context()); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}

	serveBad = true
	p, err := f.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if p == nil || len(p.Rules) != 1 {
		t.Fatalf("expected cache fallback for static-section document, got %+v", p)
	}
	st := f.Status()
	if st.Source != "cache" || !strings.Contains(st.LastError, "local-only") {
		t.Errorf("status = %+v", st)
	}
}

func TestNewRejectsUnreadableCACert(t *testing.T) {
	_, err := New(config.RemoteConfig{
		URL:    "https://config.example.com",
		CACert: filepath.Join(t.TempDir(), "missing.pem"),
	}, "test-version")
	if err == nil {
		t.Fatal("expected error for missing ca_cert, got nil")
	}
}
