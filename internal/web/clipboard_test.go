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

// postClipboard builds the form POST the documented curl invocation sends.
func postClipboard(text string) *http.Request {
	form := url.Values{"text": {text}}
	req := httptest.NewRequest("POST", "/api/v1/remote/clipboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestHandleRemoteClipboard_SetsText(t *testing.T) {
	s := testServer(t)
	var got string
	s.setClipboard = func(text string) error {
		got = text
		return nil
	}

	w := httptest.NewRecorder()
	s.handleRemoteClipboard(w, postClipboard("s3cr3t token\nline two"))

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if got != "s3cr3t token\nline two" {
		t.Errorf("clipboard got %q, want the posted text verbatim", got)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "clipboard set" {
		t.Errorf("status = %q, want %q", resp["status"], "clipboard set")
	}
}

func TestHandleRemoteClipboard_NoCSRFRequired(t *testing.T) {
	// Exempt from CSRF like remote/browse and remote/notify — drive the real
	// mux so a future CSRF-wrapping regression fails this test.
	s := testServer(t)
	set := false
	s.setClipboard = func(string) error {
		set = true
		return nil
	}
	s.registerRoutes()

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, postClipboard("t0ken"))

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200 without a CSRF token; body = %s", w.Code, w.Body.String())
	}
	if !set {
		t.Error("clipboard was not set through the mux")
	}
}

func TestHandleRemoteClipboard_RejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"empty", ""},
		{"interior NUL", "abc\x00def"},
		{"invalid utf-8", "abc\xff\xfe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			called := false
			s.setClipboard = func(string) error {
				called = true
				return nil
			}
			w := httptest.NewRecorder()
			s.handleRemoteClipboard(w, postClipboard(tc.text))
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body = %s", w.Code, w.Body.String())
			}
			if called {
				t.Error("setClipboard was called for invalid input")
			}
		})
	}
}

func TestHandleRemoteClipboard_RejectsCrossSiteOrigin(t *testing.T) {
	for _, origin := range []string{"https://evil.example", "null", "http://127.0.0.1:12345"} {
		t.Run(origin, func(t *testing.T) {
			s := testServer(t)
			s.cfg.Listen = "127.0.0.1:9000"
			called := false
			s.setClipboard = func(string) error {
				called = true
				return nil
			}
			req := postClipboard("t")
			req.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			s.handleRemoteClipboard(w, req)
			if w.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403 for Origin %q", w.Code, origin)
			}
			if called {
				t.Error("setClipboard was called for a cross-site request")
			}
		})
	}
}

func TestHandleRemoteClipboard_AllowsOwnOrigin(t *testing.T) {
	s := testServer(t)
	s.cfg.Listen = "127.0.0.1:9000"
	set := false
	s.setClipboard = func(string) error {
		set = true
		return nil
	}
	req := postClipboard("t")
	req.Header.Set("Origin", "http://localhost:9000")
	w := httptest.NewRecorder()
	s.handleRemoteClipboard(w, req)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200 for the daemon's own Origin; body = %s", w.Code, w.Body.String())
	}
	if !set {
		t.Error("clipboard was not set for a same-origin request")
	}
}

func TestHandleRemoteClipboard_WriterFailureScrubsText(t *testing.T) {
	// The 502 error must carry the writer failure but NEVER the text — a
	// clipboard value is a credential, and an exec-based writer could embed
	// its stdin in an error.
	s := testServer(t)
	s.setClipboard = func(text string) error {
		return errors.New("xclip: cannot open display while copying " + text)
	}
	w := httptest.NewRecorder()
	s.handleRemoteClipboard(w, postClipboard("SECRETVALUE"))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body = %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if !strings.Contains(resp["error"], "cannot open display") {
		t.Errorf("error = %q, want it to carry the writer failure", resp["error"])
	}
	if strings.Contains(resp["error"], "SECRETVALUE") {
		t.Errorf("error = %q, must not echo the clipboard text", resp["error"])
	}
}

func TestHandleRemoteClipboard_BusyReturns503(t *testing.T) {
	// Exercise the handler's errLauncherBusy → 503 arm: hold the gate so
	// guardedLaunch fails fast without touching the writer.
	s := testServer(t)
	called := false
	s.setClipboard = func(string) error {
		called = true
		return nil
	}
	s.clipboardMu.Lock() // simulate an in-flight write
	w := httptest.NewRecorder()
	s.handleRemoteClipboard(w, postClipboard("t"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 while a write is in flight; body = %s", w.Code, w.Body.String())
	}
	if called {
		t.Error("writer was called while the gate was held")
	}
}

func TestHandleRemoteClipboard_NilWriter(t *testing.T) {
	// testServer builds the struct directly, so setClipboard is nil unless
	// set — the handler must degrade to 503, not panic.
	s := testServer(t)
	w := httptest.NewRecorder()
	s.handleRemoteClipboard(w, postClipboard("t"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body = %s", w.Code, w.Body.String())
	}
}

func TestHandleRemoteClipboard_OversizeBody(t *testing.T) {
	s := testServer(t)
	called := false
	s.setClipboard = func(string) error {
		called = true
		return nil
	}
	big := "text=" + strings.Repeat("a", clipboardBodyLimit+1)
	req := httptest.NewRequest("POST", "/api/v1/remote/clipboard", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleRemoteClipboard(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an oversize body", w.Code)
	}
	if called {
		t.Error("setClipboard was called for an oversize body")
	}
}

func TestHandleRemoteClipboard_OversizeTextWithinBody(t *testing.T) {
	// A body under the transport cap but with text over clipboard.MaxTextLen
	// must be rejected by validation, never truncated (a truncated credential
	// is corrupt).
	s := testServer(t)
	called := false
	s.setClipboard = func(string) error {
		called = true
		return nil
	}
	w := httptest.NewRecorder()
	s.handleRemoteClipboard(w, postClipboard(strings.Repeat("a", 1<<16+1)))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for over-limit text; body = %s", w.Code, w.Body.String())
	}
	if called {
		t.Error("setClipboard was called for over-limit text")
	}
}

func TestHandleRemoteClipboard_IgnoresQueryString(t *testing.T) {
	// Text must come from the body, not the query string (PostFormValue) — a
	// URL is the last place a secret should travel.
	s := testServer(t)
	called := false
	s.setClipboard = func(string) error {
		called = true
		return nil
	}
	req := httptest.NewRequest("POST", "/api/v1/remote/clipboard?text=x", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleRemoteClipboard(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 when text is only in the query string", w.Code)
	}
	if called {
		t.Error("setClipboard was called from a query-string field")
	}
}
