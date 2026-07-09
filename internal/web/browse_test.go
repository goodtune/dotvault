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
	got, err := ValidateBrowseURL("  HTTPS://example.com/x  ")
	if err != nil {
		t.Fatalf("ValidateBrowseURL: %v", err)
	}
	if got != "HTTPS://example.com/x" && got != "https://example.com/x" {
		t.Errorf("got %q, want trimmed URL", got)
	}
}
