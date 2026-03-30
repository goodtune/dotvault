package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
)

func skipIfNoVault(t *testing.T) {
	t.Helper()
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:8200"
	}
	// Quick check: try to reach Vault
	cmd := exec.Command("curl", "-sf", addr+"/v1/sys/health")
	if err := cmd.Run(); err != nil {
		t.Skip("Vault dev server not available, skipping integration test")
	}
}

func testClient(t *testing.T) *Client {
	t.Helper()
	skipIfNoVault(t)
	c, err := NewClient(Config{
		Address: "http://127.0.0.1:8200",
		Token:   "dev-root-token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestNewClient(t *testing.T) {
	skipIfNoVault(t)
	c, err := NewClient(Config{
		Address: "http://127.0.0.1:8200",
		Token:   "dev-root-token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c == nil {
		t.Fatal("client is nil")
	}
}

func TestReadKVv2(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Seed test data — enable kv-v2 at "secret/" and write a secret
	seedTestSecret(t, c)

	secret, err := c.ReadKVv2(ctx, "secret", "users/testuser/gh")
	if err != nil {
		t.Fatalf("ReadKVv2: %v", err)
	}
	if secret == nil {
		t.Fatal("secret is nil")
	}
	if secret.Data["token"] != "test-gh-token" {
		t.Errorf("token = %v, want 'test-gh-token'", secret.Data["token"])
	}
	if secret.Version < 1 {
		t.Errorf("version = %d, want >= 1", secret.Version)
	}
}

func TestReadKVv2NotFound(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	secret, err := c.ReadKVv2(ctx, "secret", "users/testuser/nonexistent")
	if err != nil {
		t.Fatalf("ReadKVv2: %v", err)
	}
	if secret != nil {
		t.Errorf("expected nil secret for nonexistent path, got %+v", secret)
	}
}

func TestListKVv2(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	seedTestSecret(t, c)

	keys, err := c.ListKVv2(ctx, "secret", "users/testuser/")
	if err != nil {
		t.Fatalf("ListKVv2: %v", err)
	}
	if len(keys) == 0 {
		t.Error("ListKVv2 returned empty list")
	}

	found := false
	for _, k := range keys {
		if k == "gh" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListKVv2 keys = %v, want to contain 'gh'", keys)
	}
}

func TestLoginLDAP_NoMFA(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/ldap/login/testuser" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"request_id": "req-1",
			"auth": map[string]any{
				"client_token":   "hvs.test-token",
				"lease_duration": 3600,
				"renewable":      true,
				"policies":       []string{"default"},
			},
		})
	}))
	defer ts.Close()

	c, err := NewClient(Config{Address: ts.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := c.LoginLDAP(context.Background(), "ldap", "testuser", "password123")
	if err != nil {
		t.Fatalf("LoginLDAP: %v", err)
	}
	if result.MFARequired {
		t.Error("MFARequired = true, want false")
	}
	if result.Token != "hvs.test-token" {
		t.Errorf("Token = %q, want %q", result.Token, "hvs.test-token")
	}
}

func TestLoginLDAP_MFARequired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"request_id": "req-2",
			"auth": map[string]any{
				"client_token": "",
				"mfa_requirement": map[string]any{
					"mfa_request_id": "mfa-req-123",
					"mfa_constraints": map[string]any{
						"duo_constraint": map[string]any{
							"any": []map[string]any{
								{
									"type":          "duo",
									"id":            "method-456",
									"uses_passcode": false,
								},
							},
						},
					},
				},
			},
		})
	}))
	defer ts.Close()

	c, err := NewClient(Config{Address: ts.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := c.LoginLDAP(context.Background(), "ldap", "testuser", "password123")
	if err != nil {
		t.Fatalf("LoginLDAP: %v", err)
	}
	if !result.MFARequired {
		t.Fatal("MFARequired = false, want true")
	}
	if result.MFARequestID != "mfa-req-123" {
		t.Errorf("MFARequestID = %q, want %q", result.MFARequestID, "mfa-req-123")
	}
	if len(result.MFAMethods) != 1 {
		t.Fatalf("len(MFAMethods) = %d, want 1", len(result.MFAMethods))
	}
	if result.MFAMethods[0].Type != "duo" {
		t.Errorf("MFAMethods[0].Type = %q, want %q", result.MFAMethods[0].Type, "duo")
	}
	if result.MFAMethods[0].ID != "method-456" {
		t.Errorf("MFAMethods[0].ID = %q, want %q", result.MFAMethods[0].ID, "method-456")
	}
	if result.MFAMethods[0].UsesPasscode {
		t.Error("MFAMethods[0].UsesPasscode = true, want false")
	}
}

func TestValidateMFA(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/mfa/validate" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}

		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)

		if body["mfa_request_id"] != "mfa-req-123" {
			t.Errorf("mfa_request_id = %v, want %q", body["mfa_request_id"], "mfa-req-123")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"request_id": "req-3",
			"auth": map[string]any{
				"client_token":   "hvs.mfa-validated-token",
				"lease_duration": 3600,
				"renewable":      true,
			},
		})
	}))
	defer ts.Close()

	c, err := NewClient(Config{Address: ts.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	token, err := c.ValidateMFA(context.Background(), "mfa-req-123", "method-456", "")
	if err != nil {
		t.Fatalf("ValidateMFA: %v", err)
	}
	if token != "hvs.mfa-validated-token" {
		t.Errorf("token = %q, want %q", token, "hvs.mfa-validated-token")
	}
}

func TestIsForbidden(t *testing.T) {
	t.Run("direct ResponseError 403", func(t *testing.T) {
		err := &vaultapi.ResponseError{StatusCode: http.StatusForbidden}
		if !IsForbidden(err) {
			t.Error("IsForbidden = false, want true for 403 ResponseError")
		}
	})

	t.Run("wrapped ResponseError 403", func(t *testing.T) {
		inner := &vaultapi.ResponseError{StatusCode: http.StatusForbidden}
		wrapped := fmt.Errorf("token lookup-self: %w", inner)
		if !IsForbidden(wrapped) {
			t.Error("IsForbidden = false, want true for wrapped 403 ResponseError")
		}
	})

	t.Run("ResponseError non-403", func(t *testing.T) {
		err := &vaultapi.ResponseError{StatusCode: http.StatusNotFound}
		if IsForbidden(err) {
			t.Error("IsForbidden = true, want false for 404 ResponseError")
		}
	})

	t.Run("plain error", func(t *testing.T) {
		err := fmt.Errorf("connection refused")
		if IsForbidden(err) {
			t.Error("IsForbidden = true, want false for non-ResponseError")
		}
	})

	t.Run("via LookupSelf mock server", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/auth/token/lookup-self" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			if r.Method != http.MethodGet {
				t.Errorf("unexpected method: %s", r.Method)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string][]string{
				"errors": {"permission denied"},
			})
		}))
		defer ts.Close()

		c, err := NewClient(Config{Address: ts.URL, Token: "bad-token"})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}

		_, lookupErr := c.LookupSelf(context.Background())
		if lookupErr == nil {
			t.Fatal("LookupSelf: expected error, got nil")
		}
		if !IsForbidden(lookupErr) {
			t.Errorf("IsForbidden = false, want true for LookupSelf 403 response; err = %v", lookupErr)
		}
	})
}

func seedTestSecret(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()

	// Enable KVv2 at "secret/" if not already
	err := c.EnableKVv2(ctx, "secret")
	if err != nil {
		// May already be enabled — that's fine
		t.Logf("EnableKVv2: %v (may already exist)", err)
	}

	// Write test secret
	err = c.WriteKVv2(ctx, "secret", "users/testuser/gh", map[string]any{
		"token": "test-gh-token",
		"user":  "testuser",
	})
	if err != nil {
		t.Fatalf("WriteKVv2: %v", err)
	}
}
