package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// postBrowse builds the form POST the documented curl invocation sends:
//
//	curl --unix-socket ... http://localhost/api/v1/remote/browse -d url=...
func postBrowse(target string) *http.Request {
	form := url.Values{"url": {target}}
	req := httptest.NewRequest("POST", "/api/v1/remote/browse", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestHandleRemoteBrowse_OpensURL(t *testing.T) {
	s := testServer(t)
	var opened string
	s.openBrowser = func(u string) error {
		opened = u
		return nil
	}

	w := httptest.NewRecorder()
	s.handleRemoteBrowse(w, postBrowse("https://example.com/path?q=1"))

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if opened != "https://example.com/path?q=1" {
		t.Errorf("opened = %q, want the posted URL", opened)
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if resp["status"] != "browser opened" {
		t.Errorf("status = %q, want %q", resp["status"], "browser opened")
	}
}

func TestHandleRemoteBrowse_NoCSRFRequired(t *testing.T) {
	// The endpoint is deliberately exempt from the CSRF handshake so a bare
	// curl over a forwarded socket works. Drive the request through the real
	// mux so a future CSRF-wrapping regression fails this test.
	s := testServer(t)
	var opened string
	s.openBrowser = func(u string) error {
		opened = u
		return nil
	}
	s.registerRoutes()

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, postBrowse("https://example.com"))

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200 without a CSRF token; body = %s", w.Code, w.Body.String())
	}
	if opened != "https://example.com" {
		t.Errorf("opened = %q, want %q", opened, "https://example.com")
	}
}

func TestHandleRemoteBrowse_RejectsBadURLs(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"empty", ""},
		{"file scheme", "file:///etc/passwd"},
		{"custom protocol handler", "vscode://open?path=/etc"},
		{"javascript", "javascript:alert(1)"},
		{"no host", "https:///nohost"},
		{"port but no hostname", "http://:80"},
		{"embedded credentials", "https://user:pass@example.com/"},
		{"bare path", "/relative/path"},
		{"bare hostname", "example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			called := false
			s.openBrowser = func(string) error {
				called = true
				return nil
			}

			w := httptest.NewRecorder()
			s.handleRemoteBrowse(w, postBrowse(tc.url))

			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body = %s", w.Code, w.Body.String())
			}
			if called {
				t.Error("openBrowser was called for a rejected URL")
			}
		})
	}
}

func TestHandleRemoteBrowse_OpenerFailure(t *testing.T) {
	s := testServer(t)
	s.openBrowser = func(string) error {
		return errors.New("no display")
	}

	w := httptest.NewRecorder()
	s.handleRemoteBrowse(w, postBrowse("https://example.com"))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body = %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if !strings.Contains(resp["error"], "no display") {
		t.Errorf("error = %q, want it to carry the opener failure", resp["error"])
	}
}

func TestHandleRemoteBrowse_NilOpener(t *testing.T) {
	// testServer constructs the struct directly, so openBrowser is nil unless
	// set — the handler must degrade to 503, not panic. NewServer always
	// defaults the opener, so this only guards hand-rolled construction.
	s := testServer(t)

	w := httptest.NewRecorder()
	s.handleRemoteBrowse(w, postBrowse("https://example.com"))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body = %s", w.Code, w.Body.String())
	}
}

func TestValidateBrowseURL_Normalises(t *testing.T) {
	// net/url lowercases the scheme on parse, so re-serialising yields the
	// canonical form; the surrounding whitespace must be trimmed.
	u, err := ValidateBrowseURL("  HTTPS://example.com/x  ")
	if err != nil {
		t.Fatalf("ValidateBrowseURL: %v", err)
	}
	if got := u.String(); got != "https://example.com/x" {
		t.Errorf("got %q, want %q", got, "https://example.com/x")
	}
}

func TestHandleRemoteBrowse_SingleFlight(t *testing.T) {
	// Only one opener call may be in flight: a hung launcher is abandoned
	// (not killed) by the bounded wait, so concurrent requests must fail
	// fast rather than stack goroutines behind it.
	s := testServer(t)
	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan struct{})
	first := true
	s.openBrowser = func(string) error {
		// Only the first call blocks; the post-release call below must
		// succeed immediately.
		if first {
			first = false
			close(started)
			<-release
		}
		return nil
	}

	go func() {
		defer close(firstDone)
		s.handleRemoteBrowse(httptest.NewRecorder(), postBrowse("https://example.com/first"))
	}()
	<-started

	w := httptest.NewRecorder()
	s.handleRemoteBrowse(w, postBrowse("https://example.com/second"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 while an open is in flight; body = %s", w.Code, w.Body.String())
	}

	close(release)
	<-firstDone

	// Once the opener returns, the gate is released and requests succeed.
	w = httptest.NewRecorder()
	s.handleRemoteBrowse(w, postBrowse("https://example.com/third"))
	if w.Code != 200 {
		t.Errorf("status = %d, want 200 after the in-flight open finished; body = %s", w.Code, w.Body.String())
	}
}

func TestHandleRemoteBrowse_RejectsCrossSiteOrigin(t *testing.T) {
	// A hostile page's form/fetch POST is a CORS "simple request" that
	// passes the loopback Host check, but browsers always attach the
	// attacker's Origin to cross-origin POSTs — the handler must reject it
	// (including the literal "null" from sandboxed iframes).
	for _, origin := range []string{"https://evil.example", "null", "http://rebound.attacker.test"} {
		t.Run(origin, func(t *testing.T) {
			s := testServer(t)
			called := false
			s.openBrowser = func(string) error {
				called = true
				return nil
			}

			req := postBrowse("https://example.com")
			req.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			s.handleRemoteBrowse(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403 for Origin %q; body = %s", w.Code, origin, w.Body.String())
			}
			if called {
				t.Error("openBrowser was called for a cross-site request")
			}
		})
	}
}

func TestHandleRemoteBrowse_AllowsLoopbackOrigin(t *testing.T) {
	// The SPA's own origin (loopback) must still be able to use the
	// endpoint.
	s := testServer(t)
	var opened string
	s.openBrowser = func(u string) error {
		opened = u
		return nil
	}

	req := postBrowse("https://example.com")
	req.Header.Set("Origin", "http://127.0.0.1:9000")
	w := httptest.NewRecorder()
	s.handleRemoteBrowse(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200 for a loopback Origin; body = %s", w.Code, w.Body.String())
	}
	if opened != "https://example.com" {
		t.Errorf("opened = %q, want %q", opened, "https://example.com")
	}
}

func TestHandleRemoteBrowse_OversizeBody(t *testing.T) {
	// A body past the 64 KiB limit must produce a 400 via
	// MaxBytesReader + ParseForm, not a hang or a success.
	s := testServer(t)
	called := false
	s.openBrowser = func(string) error {
		called = true
		return nil
	}

	big := "url=" + strings.Repeat("a", browseBodyLimit+1)
	req := httptest.NewRequest("POST", "/api/v1/remote/browse", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleRemoteBrowse(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an oversize body", w.Code)
	}
	if called {
		t.Error("openBrowser was called for an oversize body")
	}
}

func TestHandleRemoteBrowse_IgnoresQueryString(t *testing.T) {
	// The contract is a form POST: a url smuggled into the query string
	// with an empty body must be ignored (PostFormValue), yielding the
	// missing-value 400.
	s := testServer(t)
	called := false
	s.openBrowser = func(string) error {
		called = true
		return nil
	}

	req := httptest.NewRequest("POST", "/api/v1/remote/browse?url=https%3A%2F%2Fexample.com", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleRemoteBrowse(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 when the url is only in the query string", w.Code)
	}
	if called {
		t.Error("openBrowser was called from a query-string url")
	}
}
