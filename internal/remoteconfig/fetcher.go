// Package remoteconfig fetches the partial configuration document served by a
// dotvault-config service and caches the last-known-good copy beside the sync
// state, so the overlay degrades to "frozen at last-known-good" rather than
// "absent" when the service is unreachable. Fetching always fails open: the
// resolution ladder is fresh document → cached document → nothing (the caller
// continues on its local base config), with the outcome recorded in Status
// and the metrics counter rather than surfaced as a hard error.
package remoteconfig

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/httpproxy"
	"github.com/goodtune/dotvault/internal/observability"
	"github.com/goodtune/dotvault/internal/paths"
)

// maxDocumentBytes caps the response body read. A composed partial config is
// a few KiB in practice; anything approaching the cap is a misconfigured or
// hostile endpoint, not a bigger config.
const maxDocumentBytes = 1 << 20 // 1 MiB

// fetchTimeout bounds a single fetch end-to-end via the HTTP client. The
// loader path runs synchronously in CLI startup, so this is deliberately
// short: a slow service degrades to the cache, not to a hung command.
const fetchTimeout = 10 * time.Second

// cacheFileName is the envelope file under paths.CacheDir(), next to the
// sync engine's state.json.
const cacheFileName = "remote-config.json"

// Status describes the fetcher's most recent attempt, for `dotvault status`
// and the web UI's /api/v1/status. LastSuccess records the last successful
// *contact with the remote service* (a 200, or a 304 revalidating the
// cache) — deliberately not set by a cache fallback, so "unreachable since
// X" stays observable. When the document came from the cache, CachedAt
// carries the time the served body was originally fetched, answering "how
// stale is the config I'm running" directly (including after a process
// restart, where LastSuccess is legitimately zero).
type Status struct {
	URL         string    `json:"url"`
	Source      string    `json:"source"` // "remote", "cache", or "none"
	ETag        string    `json:"etag,omitempty"`
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success"`
	CachedAt    time.Time `json:"cached_at,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
}

// Fetcher retrieves the remote partial document with ETag-conditional GETs
// and maintains the on-disk last-known-good cache. One Fetcher persists for
// the life of a daemon (across reload ticks) so the conditional-GET state
// survives; it is safe for concurrent use.
type Fetcher struct {
	rc        config.RemoteConfig
	client    *http.Client
	headers   http.Header
	identity  string
	cachePath string

	// fetchMu serialises in-flight fetches (held across the network
	// round-trip and cache I/O). statusMu guards only the status snapshot
	// and is never held across I/O, so Status() — served on the web
	// /api/v1/status path — never blocks behind a slow fetch.
	fetchMu  sync.Mutex
	statusMu sync.Mutex
	status   Status
}

// Option customises a Fetcher.
type Option func(*Fetcher)

// WithCachePath overrides the default cache location
// ({cache_dir}/remote-config.json). Primarily a test seam.
func WithCachePath(path string) Option {
	return func(f *Fetcher) { f.cachePath = path }
}

// New builds a Fetcher for the given remote_config section. version is the
// build version sent as X-Dotvault-Version. Construction fails on local
// misconfiguration (unreadable ca_cert, unresolvable username) — unlike fetch
// failures, those are loud because integrity or identity cannot be
// established at all.
func New(rc config.RemoteConfig, version string, opts ...Option) (*Fetcher, error) {
	client := httpproxy.NewClient(nil, fetchTimeout)

	if rc.CACert != "" {
		pem, err := os.ReadFile(rc.CACert)
		if err != nil {
			return nil, fmt.Errorf("read remote_config.ca_cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("remote_config.ca_cert %s: no certificates found", rc.CACert)
		}
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			return nil, fmt.Errorf("unexpected transport type %T", client.Transport)
		}
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		}
		tr.TLSClientConfig.RootCAs = pool
	}

	username, err := paths.Username()
	if err != nil {
		return nil, fmt.Errorf("resolve username for remote config identity: %w", err)
	}

	// The dimension headers. X-Dotvault-OS and X-Dotvault-User are the
	// selection dimensions the service composes layers on; the rest are
	// informational (and available to future layer kinds). Configured extras
	// are added last and cannot displace a built-in — config validation
	// rejects collisions, and the Set-before-extras order here is the
	// belt-and-braces for a config that skipped validation.
	h := http.Header{}
	h.Set("X-Dotvault-OS", runtime.GOOS)
	h.Set("X-Dotvault-User", username)
	h.Set("X-Dotvault-Arch", runtime.GOARCH)
	if hostname, herr := os.Hostname(); herr == nil && hostname != "" {
		h.Set("X-Dotvault-Hostname", hostname)
	}
	if version != "" {
		h.Set("X-Dotvault-Version", version)
	}
	for k, v := range rc.Headers {
		if h.Get(k) != "" {
			continue
		}
		h.Set(k, v)
	}

	f := &Fetcher{
		rc:        rc,
		client:    client,
		headers:   h,
		identity:  identityHash(rc.URL, h),
		cachePath: filepath.Join(paths.CacheDir(), cacheFileName),
		status:    Status{URL: rc.URL, Source: "none"},
	}
	for _, opt := range opts {
		opt(f)
	}
	return f, nil
}

// Config returns the remote_config section this Fetcher was built from, so
// callers re-reading the base config can detect that the section changed and
// rebuild the Fetcher.
func (f *Fetcher) Config() config.RemoteConfig {
	return f.rc
}

// Status returns a snapshot of the most recent fetch outcome. It never
// blocks behind an in-flight fetch.
func (f *Fetcher) Status() Status {
	f.statusMu.Lock()
	defer f.statusMu.Unlock()
	return f.status
}

// setStatus applies a mutation to the status snapshot under statusMu.
func (f *Fetcher) setStatus(update func(*Status)) {
	f.statusMu.Lock()
	defer f.statusMu.Unlock()
	update(&f.status)
}

// Fetch retrieves the partial document, resolving failure down the fail-open
// ladder: fresh remote → cached last-known-good → nil (caller continues with
// its base config alone). The returned error is reserved for future
// fail-closed modes and is always nil today; outcomes are recorded in Status,
// the logs, and the dotvault.remoteconfig.fetches counter.
func (f *Fetcher) Fetch(ctx context.Context) (*config.Partial, error) {
	f.fetchMu.Lock()
	defer f.fetchMu.Unlock()

	now := time.Now()
	f.setStatus(func(s *Status) { s.LastAttempt = now })

	cached, err := readCache(f.cachePath, f.identity)
	if err != nil {
		// An unreadable cache only matters if the fetch also fails; note it
		// and carry on as if absent.
		slog.Debug("remote config: cache unreadable", "path", f.cachePath, "error", err)
		cached = nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.rc.URL, nil)
	if err != nil {
		return f.fallback(ctx, cached, now, fmt.Errorf("build request: %w", err))
	}
	for k, vs := range f.headers {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
	if cached != nil && cached.ETag != "" {
		req.Header.Set("If-None-Match", cached.ETag)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return f.fallback(ctx, cached, now, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotModified && cached != nil:
		p, perr := config.ParsePartial([]byte(cached.Body))
		if perr != nil {
			// The cached body no longer parses (e.g. it predates a contract
			// change). It cannot serve as a fallback either — drop it.
			return f.fallback(ctx, nil, now, fmt.Errorf("parse cached document after 304: %w", perr))
		}
		f.recordSuccess(now, "remote", cached.ETag)
		observability.RecordRemoteConfigFetch(ctx, "not_modified")
		return p, nil

	case resp.StatusCode == http.StatusOK:
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes+1))
		if rerr != nil {
			return f.fallback(ctx, cached, now, fmt.Errorf("read response: %w", rerr))
		}
		if len(body) > maxDocumentBytes {
			return f.fallback(ctx, cached, now, fmt.Errorf("document exceeds %d bytes", maxDocumentBytes))
		}
		p, perr := config.ParsePartial(body)
		if perr != nil {
			return f.fallback(ctx, cached, now, perr)
		}
		etag := resp.Header.Get("ETag")
		env := envelope{
			Schema:    cacheSchema,
			URL:       f.rc.URL,
			Identity:  f.identity,
			ETag:      etag,
			FetchedAt: now.UTC(),
			Body:      string(body),
		}
		if werr := writeCache(f.cachePath, env); werr != nil {
			slog.Warn("remote config: failed to write cache", "path", f.cachePath, "error", werr)
		}
		f.recordSuccess(now, "remote", etag)
		observability.RecordRemoteConfigFetch(ctx, "fresh")
		return p, nil

	default:
		return f.fallback(ctx, cached, now, fmt.Errorf("unexpected status %s", resp.Status))
	}
}

func (f *Fetcher) recordSuccess(now time.Time, source, etag string) {
	f.setStatus(func(s *Status) {
		s.Source = source
		s.ETag = etag
		s.LastSuccess = now
		s.CachedAt = time.Time{}
		s.LastError = ""
	})
}

// fallback resolves a failed fetch down the ladder: cached last-known-good,
// else nothing. It always returns a nil error — the overlay fails open and
// the daemon retries on its next refresh tick.
func (f *Fetcher) fallback(ctx context.Context, cached *envelope, now time.Time, cause error) (*config.Partial, error) {
	if cached != nil {
		p, perr := config.ParsePartial([]byte(cached.Body))
		if perr == nil {
			f.setStatus(func(s *Status) {
				s.LastError = cause.Error()
				s.Source = "cache"
				s.ETag = cached.ETag
				s.CachedAt = cached.FetchedAt
			})
			slog.Warn("remote config: fetch failed; using cached document",
				"url", f.rc.URL, "fetched_at", cached.FetchedAt, "error", cause)
			observability.RecordRemoteConfigFetch(ctx, "cache_fallback")
			return p, nil
		}
		slog.Warn("remote config: cached document unusable", "path", f.cachePath, "error", perr)
	}
	f.setStatus(func(s *Status) {
		s.LastError = cause.Error()
		s.Source = "none"
		s.ETag = ""
		s.CachedAt = time.Time{}
	})
	slog.Warn("remote config: fetch failed and no usable cache; continuing with local base config only",
		"url", f.rc.URL, "error", cause)
	observability.RecordRemoteConfigFetch(ctx, "base_only")
	return nil, nil
}

// identityHash binds a cache entry to the request identity that produced it:
// the URL plus every dimension header. A cached document fetched as one
// (os, user, extras) tuple must never be replayed for another.
func identityHash(url string, h http.Header) string {
	var b strings.Builder
	b.WriteString(url)
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("\n")
		b.WriteString(k)
		b.WriteString(":")
		b.WriteString(strings.Join(h[k], ","))
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
