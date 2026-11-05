package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestTokenBoundCallsUseTheGivenToken proves LookupSelfWithToken and
// SignCSRWithToken authenticate with the token they are handed, not whatever
// the receiver holds, and leave the receiver's token alone. That is what lets
// a caller that read the token once make every call of one operation under
// that same token while another goroutine swaps the shared client's token.
func TestTokenBoundCallsUseTheGivenToken(t *testing.T) {
	t.Setenv("VAULT_MAX_RETRIES", "0")
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.Header.Get("X-Vault-Token"); got != "bound" {
			t.Errorf("%s X-Vault-Token = %q, want bound", r.URL.Path, got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "bound"}})
		case "/v1/pki/sign/role":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"certificate":   "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----",
				"serial_number": "01",
			}})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer ts.Close()

	c, err := NewClient(Config{Address: ts.URL, Token: "receiver"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.LookupSelfWithToken(ctx, "bound"); err != nil {
		t.Fatalf("LookupSelfWithToken: %v", err)
	}
	if _, err := c.SignCSRWithToken(ctx, "bound", "pki", "role", "csr", "cn", "5m"); err != nil {
		t.Fatalf("SignCSRWithToken: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
	if got := c.Token(); got != "receiver" {
		t.Errorf("receiver token = %q, want receiver (must be untouched)", got)
	}
}

// TestTokenBoundCallsRefuseEmptyToken proves an empty token is refused before
// any request: sending one would let the SDK fall back to nothing and ask
// Vault anonymously.
func TestTokenBoundCallsRefuseEmptyToken(t *testing.T) {
	c, err := NewClient(Config{Address: "http://127.0.0.1:1", Token: "receiver"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LookupSelfWithToken(context.Background(), ""); err == nil {
		t.Error("LookupSelfWithToken accepted an empty token")
	}
	if _, err := c.SignCSRWithToken(context.Background(), "", "pki", "role", "csr", "cn", "5m"); err == nil {
		t.Error("SignCSRWithToken accepted an empty token")
	}
}
