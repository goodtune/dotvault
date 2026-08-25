package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRevokeCertificate covers the endpoint, path shape, and body the PKI
// revoke call must produce. The certificate lives at the CA under its serial
// alone, so a wrong path or field name fails silently from the caller's
// perspective — the rotation reports success and the superseded certificate
// keeps authenticating.
func TestRevokeCertificate(t *testing.T) {
	t.Run("posts the serial to <mount>/revoke", func(t *testing.T) {
		var gotPath string
		var gotBody map[string]any
		var gotToken string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotToken = r.Header.Get("X-Vault-Token")
			json.NewDecoder(r.Body).Decode(&gotBody)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"revocation_time": 1700000000},
			})
		}))
		defer ts.Close()

		c, err := NewClient(Config{Address: ts.URL, Token: "operational-token"})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if err := c.RevokeCertificate(context.Background(), "pki", "aa:bb:cc"); err != nil {
			t.Fatalf("RevokeCertificate: %v", err)
		}
		if gotPath != "/v1/pki/revoke" {
			t.Errorf("path = %q, want /v1/pki/revoke", gotPath)
		}
		if got := gotBody["serial_number"]; got != "aa:bb:cc" {
			t.Errorf("serial_number = %v, want aa:bb:cc", got)
		}
		if gotToken != "operational-token" {
			t.Errorf("X-Vault-Token = %q, want the client's token", gotToken)
		}
	})

	t.Run("trims mount slashes", func(t *testing.T) {
		var gotPath string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
		}))
		defer ts.Close()

		c, _ := NewClient(Config{Address: ts.URL, Token: "t"})
		if err := c.RevokeCertificate(context.Background(), "/pki-int/", "01"); err != nil {
			t.Fatalf("RevokeCertificate: %v", err)
		}
		if gotPath != "/v1/pki-int/revoke" {
			t.Errorf("path = %q, want /v1/pki-int/revoke", gotPath)
		}
	})

	t.Run("empty serial never reaches Vault", func(t *testing.T) {
		called := false
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		defer ts.Close()

		c, _ := NewClient(Config{Address: ts.URL, Token: "t"})
		if err := c.RevokeCertificate(context.Background(), "pki", ""); err == nil {
			t.Error("RevokeCertificate with no serial = nil, want an error")
		}
		if called {
			t.Error("an empty serial must not be sent to Vault")
		}
	})

	t.Run("a denied revoke is an error", func(t *testing.T) {
		// The common misconfiguration: the downscoped operational token's
		// policies omit update on pki/revoke. The caller logs this rather than
		// failing the rotation, but it must be able to tell.
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		}))
		defer ts.Close()

		c, _ := NewClient(Config{Address: ts.URL, Token: "t"})
		err := c.RevokeCertificate(context.Background(), "pki", "aa:bb:cc")
		if err == nil {
			t.Fatal("RevokeCertificate against a 403 = nil, want an error")
		}
		if !strings.Contains(err.Error(), "pki/revoke") {
			t.Errorf("error = %v, want it to name the path", err)
		}
	})
}
