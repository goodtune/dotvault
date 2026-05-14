package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
		// Other loopback IP forms — accepted via net.IP.IsLoopback so
		// equivalent textual representations don't trip the allowlist.
		{"127.0.0.5", true},                           // anywhere in 127.0.0.0/8
		{"[0:0:0:0:0:0:0:1]:9000", true},              // long-form IPv6 loopback
		{"0:0:0:0:0:0:0:1", true},                     // same, no port/brackets
		{"[::ffff:127.0.0.1]:9000", true},             // IPv4-mapped IPv6 loopback
		{"[::ffff:127.0.0.1]", true},                  // same, no port (regression: To4-aware unwrap)
		// Non-loopback IPs must still be rejected.
		{"8.8.8.8:9000", false},
		{"[2001:db8::1]:9000", false},
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
		// Empty Host renders as Go's auto-generated "#00" subtest
		// name, which is unhelpful when scanning failures. Substitute
		// a readable label only for that case so other rows continue
		// to show the actual Host string.
		name := tc.host
		if name == "" {
			name = "<empty>"
		}
		t.Run(name, func(t *testing.T) {
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
	// Forbidden Host on /api/ must use the JSON error envelope so the
	// SPA fetch wrapper and tests get a structured response. Plain
	// http.Error would give text/plain and a generic StatusText body.
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type on /api/ 403 = %q, want application/json", ct)
	}
	// Cache invariant: the API's no-store policy from
	// handleConfigDownload should apply uniformly to the middleware
	// rejection too.
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control on /api/ 403 = %q, want no-store", cc)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("403 body is not JSON: %v", err)
	}
	if body["error"] != "forbidden host" {
		t.Errorf("error field = %q, want %q", body["error"], "forbidden host")
	}
}

// TestForceReauth verifies the two behaviours that keep the SPA and
// WaitForAuth state consistent when the lifecycle manager declares the
// cached Vault token unusable:
//
//  1. The in-memory Vault token is cleared, so a follow-up GET
//     /api/v1/status reports authenticated=false and the SPA bounces
//     to its login screen.
//  2. Any signal previously queued on authDone is drained so a fresh
//     WaitForAuth (e.g. from a re-entry into the startup auth flow)
//     blocks until the user completes the *new* login rather than
//     immediately satisfying on the stale signal.
func TestForceReauth(t *testing.T) {
	s := testServer(t)
	vc, err := vault.NewClient(vault.Config{Address: "http://127.0.0.1:8200", Token: "stale-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	s.vault = vc
	s.authDone = make(chan struct{}, 1)

	// Simulate the previous successful auth that left a signal queued.
	s.authDone <- struct{}{}

	s.ForceReauth()

	if got := s.vault.Token(); got != "" {
		t.Errorf("vault token after ForceReauth = %q, want \"\"", got)
	}

	// authDone must have been drained — a non-blocking read should
	// observe an empty channel.
	select {
	case <-s.authDone:
		t.Error("authDone still has a queued signal after ForceReauth; WaitForAuth would fire immediately")
	default:
	}

	// A second invocation must be a no-op (idempotent) even with no
	// token and no pending signal — exercises the empty-state branches.
	s.ForceReauth()
	if got := s.vault.Token(); got != "" {
		t.Errorf("vault token after idempotent ForceReauth = %q, want \"\"", got)
	}
}

// TestMiddlewareForbiddenHostNonAPIPlainText pins that requests outside
// /api/ and /auth/ still get the human-readable text/plain 403 — useful
// when a misconfigured browser hits `/` directly.
func TestMiddlewareForbiddenHostNonAPIPlainText(t *testing.T) {
	s := testServer(t)
	s.cfg.Listen = "127.0.0.1:0"

	handler := s.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not run for forbidden host")
	}))

	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "rebound.attacker.test"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type on / 403 = %q, want text/plain", ct)
	}
}
