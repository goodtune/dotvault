package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/notify"
)

// postNotify builds the form POST the documented curl invocation sends.
func postNotify(level, title, body string) *http.Request {
	form := url.Values{"level": {level}, "title": {title}, "body": {body}}
	req := httptest.NewRequest("POST", "/api/v1/remote/notify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestHandleRemoteNotify_Delivers(t *testing.T) {
	s := testServer(t)
	var got notify.Message
	s.sendNotification = func(m notify.Message) error {
		got = m
		return nil
	}

	w := httptest.NewRecorder()
	s.handleRemoteNotify(w, postNotify("error", "Backup failed", "see the logs"))

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if got.Level != notify.LevelError || got.Title != "Backup failed" || got.Body != "see the logs" {
		t.Errorf("delivered %+v, want the posted fields", got)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "notification delivered" {
		t.Errorf("status = %q, want %q", resp["status"], "notification delivered")
	}
}

func TestHandleRemoteNotify_NoCSRFRequired(t *testing.T) {
	// Exempt from CSRF like remote/browse — drive the real mux so a future
	// CSRF-wrapping regression fails this test.
	s := testServer(t)
	delivered := false
	s.sendNotification = func(notify.Message) error {
		delivered = true
		return nil
	}
	s.registerRoutes()

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, postNotify("info", "hi", ""))

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200 without a CSRF token; body = %s", w.Code, w.Body.String())
	}
	if !delivered {
		t.Error("notification was not delivered through the mux")
	}
}

func TestHandleRemoteNotify_RejectsBadInput(t *testing.T) {
	cases := []struct {
		name         string
		level, title string
	}{
		{"unknown level", "critical", "t"},
		{"empty level", "", "t"},
		{"empty title", "info", "   "},
		{"control-only title", "info", "\x00\x07"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			called := false
			s.sendNotification = func(notify.Message) error {
				called = true
				return nil
			}
			w := httptest.NewRecorder()
			s.handleRemoteNotify(w, postNotify(tc.level, tc.title, "b"))
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body = %s", w.Code, w.Body.String())
			}
			if called {
				t.Error("sendNotification was called for invalid input")
			}
		})
	}
}

func TestHandleRemoteNotify_RejectsCrossSiteOrigin(t *testing.T) {
	for _, origin := range []string{"https://evil.example", "null", "http://127.0.0.1:12345"} {
		t.Run(origin, func(t *testing.T) {
			s := testServer(t)
			s.cfg.Listen = "127.0.0.1:9000"
			called := false
			s.sendNotification = func(notify.Message) error {
				called = true
				return nil
			}
			req := postNotify("info", "t", "b")
			req.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			s.handleRemoteNotify(w, req)
			if w.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403 for Origin %q", w.Code, origin)
			}
			if called {
				t.Error("sendNotification was called for a cross-site request")
			}
		})
	}
}

func TestHandleRemoteNotify_AllowsOwnOrigin(t *testing.T) {
	s := testServer(t)
	s.cfg.Listen = "127.0.0.1:9000"
	delivered := false
	s.sendNotification = func(notify.Message) error {
		delivered = true
		return nil
	}
	req := postNotify("info", "t", "b")
	req.Header.Set("Origin", "http://localhost:9000")
	w := httptest.NewRecorder()
	s.handleRemoteNotify(w, req)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200 for the daemon's own Origin; body = %s", w.Code, w.Body.String())
	}
	if !delivered {
		t.Error("notification was not delivered for a same-origin request")
	}
}

func TestHandleRemoteNotify_SenderFailure(t *testing.T) {
	s := testServer(t)
	s.sendNotification = func(notify.Message) error {
		return errors.New("no notification daemon")
	}
	w := httptest.NewRecorder()
	s.handleRemoteNotify(w, postNotify("warning", "t", "b"))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body = %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if !strings.Contains(resp["error"], "no notification daemon") {
		t.Errorf("error = %q, want it to carry the sender failure", resp["error"])
	}
}

func TestHandleRemoteNotify_NilSender(t *testing.T) {
	// testServer builds the struct directly, so sendNotification is nil
	// unless set — the handler must degrade to 503, not panic.
	s := testServer(t)
	w := httptest.NewRecorder()
	s.handleRemoteNotify(w, postNotify("info", "t", "b"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body = %s", w.Code, w.Body.String())
	}
}

func TestHandleRemoteNotify_OversizeBody(t *testing.T) {
	s := testServer(t)
	called := false
	s.sendNotification = func(notify.Message) error {
		called = true
		return nil
	}
	big := "title=" + strings.Repeat("a", notifyBodyLimit+1)
	req := httptest.NewRequest("POST", "/api/v1/remote/notify", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleRemoteNotify(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an oversize body", w.Code)
	}
	if called {
		t.Error("sendNotification was called for an oversize body")
	}
}

func TestHandleRemoteNotify_IgnoresQueryString(t *testing.T) {
	// Fields must come from the body, not the query string (PostFormValue).
	s := testServer(t)
	called := false
	s.sendNotification = func(notify.Message) error {
		called = true
		return nil
	}
	req := httptest.NewRequest("POST", "/api/v1/remote/notify?level=info&title=x", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleRemoteNotify(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 when fields are only in the query string", w.Code)
	}
	if called {
		t.Error("sendNotification was called from query-string fields")
	}
}
