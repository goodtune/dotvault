package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
)

func testVaultClient(t *testing.T, handler http.HandlerFunc) *vault.Client {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	c, err := vault.NewClient(vault.Config{Address: ts.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestLoginTracker_NoMFA(t *testing.T) {
	vc := testVaultClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"request_id": "req-1",
			"auth": map[string]any{
				"client_token":   "hvs.test-token",
				"lease_duration": 3600,
				"renewable":      true,
			},
		})
	})

	lt := NewLoginTracker(vc)
	lt.StartLogin("sess-1", "ldap", "testuser", "password123")

	deadline := time.After(5 * time.Second)
	for {
		status := lt.GetStatus("sess-1")
		if status == nil {
			t.Fatal("GetStatus returned nil")
		}
		if status.State == "authenticated" {
			if status.Token != "hvs.test-token" {
				t.Errorf("Token = %q, want %q", status.Token, "hvs.test-token")
			}
			break
		}
		if status.State == "failed" {
			t.Fatalf("login failed: %s", status.Error)
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for auth, state = %s", status.State)
		case <-time.After(50 * time.Millisecond):
		}
	}

	lt.Clear("sess-1")
	if s := lt.GetStatus("sess-1"); s != nil {
		t.Error("GetStatus after Clear should return nil")
	}
}

func TestLoginTracker_PushMFA(t *testing.T) {
	callCount := 0
	vc := testVaultClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		callCount++
		if callCount == 1 {
			json.NewEncoder(w).Encode(map[string]any{
				"request_id": "req-1",
				"auth": map[string]any{
					"client_token": "",
					"mfa_requirement": map[string]any{
						"mfa_request_id": "mfa-req-123",
						"mfa_constraints": map[string]any{
							"duo": map[string]any{
								"any": []map[string]any{
									{"type": "duo", "id": "method-456", "uses_passcode": false},
								},
							},
						},
					},
				},
			})
		} else {
			// Simulate Duo push delay so the poller can observe mfa_required.
			time.Sleep(200 * time.Millisecond)
			json.NewEncoder(w).Encode(map[string]any{
				"request_id": "req-2",
				"auth": map[string]any{
					"client_token":   "hvs.mfa-token",
					"lease_duration": 3600,
					"renewable":      true,
				},
			})
		}
	})

	lt := NewLoginTracker(vc)
	lt.StartLogin("sess-1", "ldap", "testuser", "password123")

	deadline := time.After(5 * time.Second)
	sawMFARequired := false
	for {
		status := lt.GetStatus("sess-1")
		if status.State == "mfa_required" {
			sawMFARequired = true
		}
		if status.State == "authenticated" {
			if status.Token != "hvs.mfa-token" {
				t.Errorf("Token = %q, want %q", status.Token, "hvs.mfa-token")
			}
			break
		}
		if status.State == "failed" {
			t.Fatalf("login failed: %s", status.Error)
		}
		select {
		case <-deadline:
			t.Fatalf("timed out, state = %s", status.State)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !sawMFARequired {
		t.Error("never saw mfa_required state")
	}
}

func TestLoginTracker_TOTPMFA(t *testing.T) {
	callCount := 0
	vc := testVaultClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		callCount++
		if callCount == 1 {
			json.NewEncoder(w).Encode(map[string]any{
				"request_id": "req-1",
				"auth": map[string]any{
					"client_token": "",
					"mfa_requirement": map[string]any{
						"mfa_request_id": "mfa-req-789",
						"mfa_constraints": map[string]any{
							"totp": map[string]any{
								"any": []map[string]any{
									{"type": "totp", "id": "method-totp-1", "uses_passcode": true},
								},
							},
						},
					},
				},
			})
		} else {
			json.NewEncoder(w).Encode(map[string]any{
				"request_id": "req-2",
				"auth": map[string]any{
					"client_token":   "hvs.totp-token",
					"lease_duration": 3600,
					"renewable":      true,
				},
			})
		}
	})

	lt := NewLoginTracker(vc)
	lt.StartLogin("sess-1", "ldap", "testuser", "password123")

	deadline := time.After(5 * time.Second)
	for {
		status := lt.GetStatus("sess-1")
		if status.State == "mfa_required" {
			if len(status.MFAMethods) != 1 || !status.MFAMethods[0].UsesPasscode {
				t.Fatalf("expected TOTP method, got %+v", status.MFAMethods)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for mfa_required, state = %s", status.State)
		case <-time.After(50 * time.Millisecond):
		}
	}

	lt.SubmitTOTP("sess-1", "123456")

	for {
		status := lt.GetStatus("sess-1")
		if status.State == "authenticated" {
			if status.Token != "hvs.totp-token" {
				t.Errorf("Token = %q, want %q", status.Token, "hvs.totp-token")
			}
			break
		}
		if status.State == "failed" {
			t.Fatalf("login failed: %s", status.Error)
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for authenticated, state = %s", status.State)
		case <-time.After(50 * time.Millisecond):
		}
	}
}
