package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/vault"
)

func TestValidateLoopback(t *testing.T) {
	tests := []struct {
		addr    string
		wantErr bool
	}{
		{"127.0.0.1:8200", false},
		{"[::1]:8200", false},
		{"localhost:8200", false},
		{"0.0.0.0:8200", true},
		{"192.168.1.1:8200", true},
		{"example.com:8200", true},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			err := paths.ValidateLoopback(tt.addr)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateLoopback(%q) = nil, want error", tt.addr)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateLoopback(%q) = %v, want nil", tt.addr, err)
			}
		})
	}
}

func TestServerIntegration(t *testing.T) {
	s := testServer(t)
	vc, err := vault.NewClient(vault.Config{Address: "http://127.0.0.1:8200"})
	if err != nil {
		t.Fatalf("failed to create vault client: %v", err)
	}
	s.login = auth.NewLoginTracker(vc)
	t.Cleanup(s.login.Close)
	s.mux = http.NewServeMux()
	s.registerRoutes()

	ts := httptest.NewServer(s.middleware(s.mux))
	defer ts.Close()

	// Test CSP header
	resp, err := http.Get(ts.URL + "/api/v1/status")
	if err != nil {
		t.Fatalf("GET /api/v1/status: %v", err)
	}
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	if csp != "default-src 'self'" {
		t.Errorf("CSP header = %q, want %q", csp, "default-src 'self'")
	}

	xcto := resp.Header.Get("X-Content-Type-Options")
	if xcto != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want 'nosniff'", xcto)
	}
}
