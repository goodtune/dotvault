package configsvc

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/configsvc/groups"
	"github.com/goodtune/dotvault/internal/configsvc/store"
)

func newTestServer(t *testing.T) (store.Store, *httptest.Server) {
	t.Helper()
	st := newTestStore(t)
	ts := httptest.NewServer(NewServer(st, groups.NewStatic(st)).Handler())
	t.Cleanup(ts.Close)
	return st, ts
}

func get(t *testing.T, url string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

var identityHeaders = map[string]string{
	"X-Dotvault-OS":   "linux",
	"X-Dotvault-User": "alice",
}

func TestConfigRequiresIdentityHeaders(t *testing.T) {
	_, ts := newTestServer(t)
	tests := []map[string]string{
		{},
		{"X-Dotvault-OS": "linux"},
		{"X-Dotvault-User": "alice"},
		{"X-Dotvault-OS": "  ", "X-Dotvault-User": "alice"},
	}
	for _, headers := range tests {
		if resp := get(t, ts.URL+"/v1/config", headers); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("GET with headers %v = %d, want 400", headers, resp.StatusCode)
		}
	}
}

func TestConfigServesComposedDocument(t *testing.T) {
	st, ts := newTestServer(t)
	ctx := context.Background()
	putLayer(t, st, "global", "rules:\n  - name: g\n    vault_key: k\n    target: {path: ~/g.txt, format: text}\n")
	putLayer(t, st, "group/sydney", "enrolments:\n  syd: {engine: github}\n")
	if err := st.PutGroups(ctx, "alice", []string{"sydney"}); err != nil {
		t.Fatalf("PutGroups: %v", err)
	}

	resp := get(t, ts.URL+"/v1/config", identityHeaders)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/config = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/yaml" {
		t.Fatalf("Content-Type = %q, want application/yaml", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("Cache-Control = %q, want no-cache", cc)
	}
	etag := resp.Header.Get("ETag")
	if !strings.HasPrefix(etag, `"`) {
		t.Fatalf("ETag = %q, want quoted strong validator", etag)
	}

	body, _ := io.ReadAll(resp.Body)
	p, err := config.ParsePartial(body)
	if err != nil {
		t.Fatalf("response is not a valid partial: %v\n%s", err, body)
	}
	if len(p.Rules) != 1 || p.Rules[0].Name != "g" {
		t.Fatalf("rules = %+v, want the global rule", p.Rules)
	}
	if _, ok := p.Enrolments["syd"]; !ok {
		t.Fatalf("enrolments = %+v, want the sydney group enrolment", p.Enrolments)
	}
}

func TestConfigETagRoundTrip(t *testing.T) {
	st, ts := newTestServer(t)
	putLayer(t, st, "global", "sync:\n  interval: 5m\n")

	first := get(t, ts.URL+"/v1/config", identityHeaders)
	etag := first.Header.Get("ETag")

	withETag := map[string]string{}
	for k, v := range identityHeaders {
		withETag[k] = v
	}
	withETag["If-None-Match"] = etag
	second := get(t, ts.URL+"/v1/config", withETag)
	if second.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional GET = %d, want 304", second.StatusCode)
	}
	if got := second.Header.Get("ETag"); got != etag {
		t.Fatalf("304 ETag = %q, want %q", got, etag)
	}

	// A changed store invalidates: the same If-None-Match now misses.
	putLayer(t, st, "global", "sync:\n  interval: 10m\n")
	third := get(t, ts.URL+"/v1/config", withETag)
	if third.StatusCode != http.StatusOK {
		t.Fatalf("conditional GET after change = %d, want 200", third.StatusCode)
	}
	if got := third.Header.Get("ETag"); got == etag {
		t.Fatal("ETag did not change with the document")
	}
}

func TestConfigLowercasesOS(t *testing.T) {
	st, ts := newTestServer(t)
	putLayer(t, st, "os/linux", "sync:\n  interval: 7m\n")

	resp := get(t, ts.URL+"/v1/config", map[string]string{
		"X-Dotvault-OS":   "Linux",
		"X-Dotvault-User": "alice",
	})
	body, _ := io.ReadAll(resp.Body)
	p, err := config.ParsePartial(body)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if p.Sync == nil || p.Sync.RawInterval != "7m" {
		t.Fatalf("os layer not applied for mixed-case header: %s", body)
	}
}

func TestConfigCorruptLayerIs500NamingKey(t *testing.T) {
	st, ts := newTestServer(t)
	putLayer(t, st, "user/alice", "web:\n  enabled: true\n")

	resp := get(t, ts.URL+"/v1/config", identityHeaders)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("GET with corrupt layer = %d, want 500", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"user/alice"`) {
		t.Fatalf("500 body %q does not name the corrupt layer", body)
	}
}

// failingResolver simulates a directory outage.
type failingResolver struct{}

func (failingResolver) Groups(context.Context, string) ([]string, error) {
	return nil, errors.New("directory unreachable")
}

func TestConfigResolverFailureIs500(t *testing.T) {
	st := newTestStore(t)
	ts := httptest.NewServer(NewServer(st, failingResolver{}).Handler())
	t.Cleanup(ts.Close)
	if resp := get(t, ts.URL+"/v1/config", identityHeaders); resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("GET with failing resolver = %d, want 500", resp.StatusCode)
	}
}

func TestHealthAndReadiness(t *testing.T) {
	st, ts := newTestServer(t)
	if resp := get(t, ts.URL+"/healthz", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200", resp.StatusCode)
	}
	if resp := get(t, ts.URL+"/readyz", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /readyz = %d, want 200", resp.StatusCode)
	}
	// A closed store fails Ping, so readiness flips while liveness holds.
	st.Close()
	if resp := get(t, ts.URL+"/readyz", nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz with dead store = %d, want 503", resp.StatusCode)
	}
	if resp := get(t, ts.URL+"/healthz", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz with dead store = %d, want 200", resp.StatusCode)
	}
}

func TestIfNoneMatchVariants(t *testing.T) {
	etag := `"abc"`
	tests := []struct {
		header string
		want   bool
	}{
		{"", false},
		{`"abc"`, true},
		{`W/"abc"`, true},
		{`"zzz", "abc"`, true},
		{`*`, true},
		{`"zzz"`, false},
	}
	for _, tt := range tests {
		if got := ifNoneMatchHit(tt.header, etag); got != tt.want {
			t.Errorf("ifNoneMatchHit(%q) = %v, want %v", tt.header, got, tt.want)
		}
	}
}
