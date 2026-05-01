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

// TestHostAllowed pins the DNS-rebinding defence in the middleware: only
// loopback aliases (and the configured listen hostname) are accepted as
// the Host header. A name that resolves to 127.0.0.1 in the wider DNS
// is not enough — the Host string itself must be loopback.
func TestHostAllowed(t *testing.T) {
	s := testServer(t)
	// Use a non-alias hostname so the "configured listen hostname"
	// branch is genuinely exercised; pinning to "localhost" (which is
	// a hard-coded alias) would mask any regression in that branch.
	s.cfg.Listen = "my-loopback-alias:9000"

	cases := []struct {
		host string
		ok   bool
	}{
		{"127.0.0.1:9000", true},
		{"127.0.0.1", true},
		{"[::1]:9000", true},
		{"localhost:9000", true},
		{"localhost", true},
		// Configured listen hostname (not one of the hard-coded
		// aliases) is accepted on any port — the check is on the
		// hostname, not the port pairing.
		{"my-loopback-alias:9000", true},
		{"my-loopback-alias:1234", true},
		{"my-loopback-alias", true},
		// Other arbitrary names — including rebound DNS that resolves
		// to 127.0.0.1 in the wild — must be rejected.
		{"rebound.example.com:9000", false},
		{"attacker.test", false},
		{"some-other-name:9000", false},
		{"", false},
		// Malformed/lone-bracket pairs that are NOT in the
		// `[host]:port` form must stay bracketed. unwrapIPv6 only
		// strips brackets when the inner content parses as a real
		// IPv6 literal, so a tampered Host like "[localhost]" without
		// a port can't be silently normalised into the "localhost"
		// alias. (When the form IS [host]:port, net.SplitHostPort
		// itself unbrackets the host before we ever see it; that is
		// the standard URL syntax for an IPv6 literal in a URL and
		// reflects the underlying hostname rather than disguising it.)
		{"[localhost", false},
		{"localhost]", false},
		{"[localhost]", false},
		{"[127.0.0.1]", false},
	}

	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.Host = tc.host
			if got := s.hostAllowed(r); got != tc.ok {
				t.Errorf("hostAllowed(%q) = %v, want %v", tc.host, got, tc.ok)
			}
		})
	}
}

// TestMiddlewareRejectsBadHost confirms the host check actually rejects
// requests at the HTTP layer rather than just informing later handlers.
func TestMiddlewareRejectsBadHost(t *testing.T) {
	s := testServer(t)
	s.cfg.Listen = "127.0.0.1:0"

	handler := s.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not run for forbidden host")
	}))

	r := httptest.NewRequest("GET", "/api/v1/status", nil)
	r.Host = "rebound.attacker.test"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for forbidden host", w.Code)
	}
	// Security headers must apply to error responses too — without
	// nosniff a 403 error page could be MIME-sniffed, and without CSP
	// it could be framed by an attacker.
	if csp := w.Header().Get("Content-Security-Policy"); csp != "default-src 'self'" {
		t.Errorf("Content-Security-Policy on 403 = %q, want default-src 'self'", csp)
	}
	if xcto := w.Header().Get("X-Content-Type-Options"); xcto != "nosniff" {
		t.Errorf("X-Content-Type-Options on 403 = %q, want nosniff", xcto)
	}
}
