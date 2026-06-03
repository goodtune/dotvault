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

func TestEnrolKeyFromRequest(t *testing.T) {
	// Flat key via the single {key} segment.
	r := httptest.NewRequest("GET", "/api/v1/enrol/gh/status", nil)
	r.SetPathValue("key", "gh")
	if got := enrolKeyFromRequest(r); got != "gh" {
		t.Errorf("flat key = %q, want gh", got)
	}
	// Grouped key via the two {group}/{name} segments.
	r = httptest.NewRequest("GET", "/api/v1/enrol/databricks/prod/status", nil)
	r.SetPathValue("group", "databricks")
	r.SetPathValue("name", "prod")
	if got := enrolKeyFromRequest(r); got != "databricks/prod" {
		t.Errorf("grouped key = %q, want databricks/prod", got)
	}
}

func TestHandleEnrolStatus_GroupedKey(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{name: "Mock", fields: []string{"token"}})
	defer enrol.UnregisterEngine("mock")

	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.enrolRunner = NewEnrolmentRunner(map[string]config.Enrolment{
		"databricks/prod": {Engine: "mock"},
	})

	req := httptest.NewRequest("GET", "/api/v1/enrol/databricks/prod/status", nil)
	req.SetPathValue("group", "databricks")
	req.SetPathValue("name", "prod")
	w := httptest.NewRecorder()

	s.handleEnrolStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	var info map[string]any
	json.NewDecoder(w.Body).Decode(&info)
	if info["key"] != "databricks/prod" {
		t.Errorf("key = %v, want databricks/prod", info["key"])
	}
}

// TestEnrolRouting_GroupedKey exercises the real mux to prove a grouped key
// resolves through both URL shapes the frontend and CLI might produce: the
// percent-encoded single segment ("databricks%2Fprod") and the two literal
// segments ("databricks/prod"). Status is a GET, so no CSRF token is needed.
func TestEnrolRouting_GroupedKey(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{name: "Mock", fields: []string{"token"}})
	defer enrol.UnregisterEngine("mock")

	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.enrolRunner = NewEnrolmentRunner(map[string]config.Enrolment{
		"databricks/prod": {Engine: "mock"},
	})
	s.registerRoutes()

	for _, path := range []string{
		"/api/v1/enrol/databricks%2Fprod/status",
		"/api/v1/enrol/databricks/prod/status",
	} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200; body = %s", path, w.Code, w.Body.String())
		}
		var info map[string]any
		json.NewDecoder(w.Body).Decode(&info)
		if info["key"] != "databricks/prod" {
			t.Errorf("%s: key = %v, want databricks/prod", path, info["key"])
		}
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

func TestHandleEnrolReset(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{name: "Mock", fields: []string{"token"}})
	defer enrol.UnregisterEngine("mock")

	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.enrolRunner = NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	})
	s.enrolRunner.MarkComplete("svc")

	req := httptest.NewRequest("POST", "/api/v1/enrol/svc/reset", nil)
	req.SetPathValue("key", "svc")
	w := httptest.NewRecorder()

	s.handleEnrolReset(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "pending" {
		t.Errorf("status = %v, want %q", resp["status"], "pending")
	}

	info, _ := s.enrolRunner.GetState("svc")
	if info.Status != "pending" {
		t.Errorf("runner state = %q, want %q", info.Status, "pending")
	}
}

func TestHandleEnrolReset_NotFound(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.enrolRunner = NewEnrolmentRunner(nil)

	req := httptest.NewRequest("POST", "/api/v1/enrol/bogus/reset", nil)
	req.SetPathValue("key", "bogus")
	w := httptest.NewRecorder()

	s.handleEnrolReset(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleEnrolReset_Conflict(t *testing.T) {
	enrol.RegisterEngine("mock", &mockEngine{name: "Mock", fields: []string{"token"}})
	defer enrol.UnregisterEngine("mock")

	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.enrolRunner = NewEnrolmentRunner(map[string]config.Enrolment{
		"svc": {Engine: "mock"},
	})
	// Pending is not resettable.

	req := httptest.NewRequest("POST", "/api/v1/enrol/svc/reset", nil)
	req.SetPathValue("key", "svc")
	w := httptest.NewRecorder()

	s.handleEnrolReset(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

func TestHandleEnrolReset_NoRunner(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	// Intentionally leave s.enrolRunner nil.

	req := httptest.NewRequest("POST", "/api/v1/enrol/svc/reset", nil)
	req.SetPathValue("key", "svc")
	w := httptest.NewRecorder()

	s.handleEnrolReset(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestHandleEnrolResetRequiresCSRF(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.enrolRunner = NewEnrolmentRunner(nil)

	req := httptest.NewRequest("POST", "/api/v1/enrol/svc/reset", nil)
	req.SetPathValue("key", "svc")
	w := httptest.NewRecorder()

	s.requireCSRF(s.handleEnrolReset)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for missing CSRF", w.Code)
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

func TestHandleEnrolStartRequiresCSRF(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.enrolRunner = NewEnrolmentRunner(nil)

	req := httptest.NewRequest("POST", "/api/v1/enrol/svc/start", nil)
	req.SetPathValue("key", "svc")
	w := httptest.NewRecorder()

	s.requireCSRF(s.handleEnrolStart)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for missing CSRF", w.Code)
	}
}

func TestHandleEnrolSkipRequiresCSRF(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.enrolRunner = NewEnrolmentRunner(nil)

	req := httptest.NewRequest("POST", "/api/v1/enrol/svc/skip", nil)
	req.SetPathValue("key", "svc")
	w := httptest.NewRecorder()

	s.requireCSRF(s.handleEnrolSkip)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for missing CSRF", w.Code)
	}
}

func TestHandleEnrolCompleteRequiresCSRF(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.enrolRunner = NewEnrolmentRunner(nil)

	req := httptest.NewRequest("POST", "/api/v1/enrol/complete", nil)
	w := httptest.NewRecorder()

	s.requireCSRF(s.handleEnrolComplete)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for missing CSRF", w.Code)
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
