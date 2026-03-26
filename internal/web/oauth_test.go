package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOAuthManager_StateValidation(t *testing.T) {
	om := NewOAuthManager()

	// Generate state
	state := om.CreateState("test-rule")

	// Valid state
	rule, ok := om.ValidateState(state)
	if !ok {
		t.Error("ValidateState() = false for valid state")
	}
	if rule != "test-rule" {
		t.Errorf("rule = %q, want 'test-rule'", rule)
	}

	// State consumed — second validation fails
	_, ok = om.ValidateState(state)
	if ok {
		t.Error("ValidateState() = true for consumed state")
	}
}

func TestOAuthManager_InvalidState(t *testing.T) {
	om := NewOAuthManager()

	_, ok := om.ValidateState("bogus-state")
	if ok {
		t.Error("ValidateState() = true for bogus state")
	}
}

func TestHandleOAuthCallback_InvalidState(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest("GET", "/api/v1/oauth/callback?code=abc&state=bogus", nil)
	w := httptest.NewRecorder()

	s.handleOAuthCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for invalid state", w.Code)
	}
}
