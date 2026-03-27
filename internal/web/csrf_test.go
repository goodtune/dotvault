package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSRFToken_Issue(t *testing.T) {
	cs := NewCSRFStore()

	req := httptest.NewRequest("GET", "/api/v1/csrf", nil)
	w := httptest.NewRecorder()
	cs.IssueHandler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "token") {
		t.Errorf("response missing token field: %s", body)
	}
}

func TestCSRFToken_ValidateValid(t *testing.T) {
	cs := NewCSRFStore()

	// Issue a token
	req := httptest.NewRequest("GET", "/api/v1/csrf", nil)
	w := httptest.NewRecorder()
	cs.IssueHandler().ServeHTTP(w, req)

	// Extract token from response
	body := w.Body.String()
	token := extractToken(body)
	if token == "" {
		t.Fatal("could not extract token from response")
	}

	// POST with valid token
	postReq := httptest.NewRequest("POST", "/api/v1/sync", nil)
	postReq.Header.Set("X-CSRF-Token", token)

	valid := cs.Validate(postReq)
	if !valid {
		t.Error("Validate() = false for valid token")
	}
}

func TestCSRFToken_ValidateInvalid(t *testing.T) {
	cs := NewCSRFStore()

	req := httptest.NewRequest("POST", "/api/v1/sync", nil)
	req.Header.Set("X-CSRF-Token", "bogus-token")

	valid := cs.Validate(req)
	if valid {
		t.Error("Validate() = true for bogus token")
	}
}

func TestCSRFToken_ValidateMissing(t *testing.T) {
	cs := NewCSRFStore()

	req := httptest.NewRequest("POST", "/api/v1/sync", nil)
	valid := cs.Validate(req)
	if valid {
		t.Error("Validate() = true for missing token")
	}
}

func extractToken(body string) string {
	// Simple extraction from {"token":"..."}
	i := strings.Index(body, `"token":"`)
	if i < 0 {
		return ""
	}
	start := i + len(`"token":"`)
	end := strings.Index(body[start:], `"`)
	if end < 0 {
		return ""
	}
	return body[start : start+end]
}
