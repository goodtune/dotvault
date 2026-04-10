package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/enrol"
)

func TestHandleEnrolStart(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{
		name:   "Mock",
		fields: []string{"token"},
		creds:  map[string]string{"token": "abc"},
	})
	defer enrol.UnregisterEngine("mock")

	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.enrolRunner = NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	})

	req := httptest.NewRequest("POST", "/api/v1/enrol/svc/start", nil)
	req.SetPathValue("key", "svc")
	w := httptest.NewRecorder()

	s.handleEnrolStart(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "running" {
		t.Errorf("status = %v, want %q", resp["status"], "running")
	}
}

func TestHandleEnrolStart_NotFound(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.enrolRunner = NewEnrolmentRunner(nil)

	req := httptest.NewRequest("POST", "/api/v1/enrol/bogus/start", nil)
	req.SetPathValue("key", "bogus")
	w := httptest.NewRecorder()

	s.handleEnrolStart(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleEnrolSkip(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{name: "Mock", fields: []string{"token"}})
	defer enrol.UnregisterEngine("mock")

	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.enrolRunner = NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	})

	req := httptest.NewRequest("POST", "/api/v1/enrol/svc/skip", nil)
	req.SetPathValue("key", "svc")
	w := httptest.NewRecorder()

	s.handleEnrolSkip(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "skipped" {
		t.Errorf("status = %v, want %q", resp["status"], "skipped")
	}
}

func TestHandleEnrolStatus(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{name: "Mock", fields: []string{"token"}})
	defer enrol.UnregisterEngine("mock")

	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.enrolRunner = NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	})

	req := httptest.NewRequest("GET", "/api/v1/enrol/svc/status", nil)
	req.SetPathValue("key", "svc")
	w := httptest.NewRecorder()

	s.handleEnrolStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "pending" {
		t.Errorf("status = %v, want %q", resp["status"], "pending")
	}
}

func TestHandleEnrolComplete(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.enrolRunner = NewEnrolmentRunner(nil)

	req := httptest.NewRequest("POST", "/api/v1/enrol/complete", nil)
	w := httptest.NewRecorder()

	s.handleEnrolComplete(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	// Verify done channel was signalled.
	select {
	case <-s.enrolRunner.done:
	default:
		t.Error("done channel not signalled")
	}
}

func TestHandleStatus_IncludesEnrolments(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{name: "Mock", fields: []string{"token"}})
	defer enrol.UnregisterEngine("mock")

	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.enrolRunner = NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	})

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()

	s.handleStatus(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	enrolments, ok := resp["enrolments"].([]any)
	if !ok {
		t.Fatalf("enrolments is %T, want []any", resp["enrolments"])
	}
	if len(enrolments) != 1 {
		t.Fatalf("len(enrolments) = %d, want 1", len(enrolments))
	}
	first := enrolments[0].(map[string]any)
	if first["key"] != "svc" {
		t.Errorf("key = %v, want %q", first["key"], "svc")
	}
	if first["status"] != "pending" {
		t.Errorf("status = %v, want %q", first["status"], "pending")
	}
}
