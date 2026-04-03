package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/dotvault/internal/enrol"
)

func TestHandleEnrolmentStatus_NotFound(t *testing.T) {
	s := testServer(t)
	s.enrolTracker = enrol.NewTracker()

	req := httptest.NewRequest("GET", "/api/v1/enrolments/nokey/status", nil)
	req.SetPathValue("key", "nokey")
	w := httptest.NewRecorder()

	s.handleEnrolmentStatus(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleEnrolmentStart_RequiresCSRF(t *testing.T) {
	s := testServer(t)
	s.enrolMgr = nil // not needed for CSRF check
	s.enrolTracker = enrol.NewTracker()

	req := httptest.NewRequest("POST", "/api/v1/enrolments/mykey/start", nil)
	req.SetPathValue("key", "mykey")
	w := httptest.NewRecorder()

	s.requireCSRF(s.handleEnrolmentStart)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for missing CSRF", w.Code)
	}
}

func TestHandleEnrolmentStatus_ReturnsStatus(t *testing.T) {
	s := testServer(t)
	tracker := enrol.NewTracker()
	s.enrolTracker = tracker

	// Manually set a status for testing.
	tracker.SetForTest("testkey", &enrol.EnrolmentStatus{
		State: enrol.StateAwaitingUser,
		DeviceCode: &enrol.DeviceCodeInfo{
			UserCode:        "ABCD-1234",
			VerificationURI: "https://example.com/device",
		},
	})

	req := httptest.NewRequest("GET", "/api/v1/enrolments/testkey/status", nil)
	req.SetPathValue("key", "testkey")
	w := httptest.NewRecorder()

	s.handleEnrolmentStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp enrol.EnrolmentStatus
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.State != enrol.StateAwaitingUser {
		t.Errorf("state = %q, want %q", resp.State, enrol.StateAwaitingUser)
	}
	if resp.DeviceCode == nil || resp.DeviceCode.UserCode != "ABCD-1234" {
		t.Errorf("device_code = %v, want user_code ABCD-1234", resp.DeviceCode)
	}
}
