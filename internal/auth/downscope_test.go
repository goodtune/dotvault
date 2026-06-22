package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/dotvault/internal/vault"
)

func TestPolicyConstraintActive(t *testing.T) {
	tests := []struct {
		name string
		c    PolicyConstraint
		want bool
	}{
		{"zero value", PolicyConstraint{}, false},
		{"policies set", PolicyConstraint{Policies: []string{"dotvault"}}, true},
		{"empty policies slice", PolicyConstraint{Policies: []string{}}, false},
		{"no default only", PolicyConstraint{NoDefaultPolicy: true}, true},
		{"both", PolicyConstraint{Policies: []string{"x"}, NoDefaultPolicy: true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.Active(); got != tt.want {
				t.Errorf("Active() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDownscopeInactive proves an unconfigured constraint returns the login
// token verbatim and makes no Vault call — the historical behaviour. The
// server fails the test if it is ever dialed.
func TestDownscopeInactive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("Downscope must not contact Vault when no constraint is configured; got %s", r.URL.Path)
	}))
	defer ts.Close()

	c, err := vault.NewClient(vault.Config{Address: ts.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	got, err := Downscope(context.Background(), c, "login-token", PolicyConstraint{})
	if err != nil {
		t.Fatalf("Downscope: %v", err)
	}
	if got != "login-token" {
		t.Errorf("Downscope returned %q, want the unchanged login-token", got)
	}
}

// TestDownscopeActive proves a configured constraint exchanges the broad login
// token for a child token via auth/token/create, presenting the login token as
// the parent.
func TestDownscopeActive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/create" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("X-Vault-Token"); got != "login-token" {
			t.Errorf("parent token = %q, want login-token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "child-token"},
		})
	}))
	defer ts.Close()

	c, err := vault.NewClient(vault.Config{Address: ts.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	got, err := Downscope(context.Background(), c, "login-token", PolicyConstraint{
		Policies:        []string{"dotvault"},
		NoDefaultPolicy: true,
	})
	if err != nil {
		t.Fatalf("Downscope: %v", err)
	}
	if got != "child-token" {
		t.Errorf("Downscope returned %q, want child-token", got)
	}
}

// TestDownscopeFailsClosed proves a downscoping failure surfaces as an error
// rather than silently falling back to the broad token.
func TestDownscopeFailsClosed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
	}))
	defer ts.Close()

	c, err := vault.NewClient(vault.Config{Address: ts.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := Downscope(context.Background(), c, "login-token", PolicyConstraint{Policies: []string{"x"}}); err == nil {
		t.Fatal("Downscope must fail closed when the child token cannot be minted")
	}
}

// TestDownscopeNeverMutatesSharedClient is the regression test for the leak
// where a failed (or in-progress) downscope left the broad login token
// installed on the shared Vault client — observable via the web auth gate and
// /api/v1/token. Downscope must mint the child on an isolated client and leave
// the caller's client's token exactly as it found it, on both the success and
// failure paths.
func TestDownscopeNeverMutatesSharedClient(t *testing.T) {
	t.Run("on success", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "child-token"}})
		}))
		defer ts.Close()
		c, err := vault.NewClient(vault.Config{Address: ts.URL})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if _, err := Downscope(context.Background(), c, "broad-token", PolicyConstraint{Policies: []string{"x"}}); err != nil {
			t.Fatalf("Downscope: %v", err)
		}
		if got := c.Token(); got != "" {
			t.Errorf("shared client token = %q, want empty — Downscope must not install the broad or child token on the caller's client", got)
		}
	})

	t.Run("on failure", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		}))
		defer ts.Close()
		c, err := vault.NewClient(vault.Config{Address: ts.URL})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if _, err := Downscope(context.Background(), c, "broad-token", PolicyConstraint{Policies: []string{"x"}}); err == nil {
			t.Fatal("expected error")
		}
		if got := c.Token(); got != "" {
			t.Errorf("shared client token = %q, want empty — a failed downscope must not leave the broad token installed", got)
		}
	})
}
