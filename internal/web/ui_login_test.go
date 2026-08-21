package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/config"
)

// loginOrigin is the Origin every browser-driven POST in these tests carries;
// it must match authTestServer's listenAddr for requireSameOrigin to pass.
const loginOrigin = "http://127.0.0.1:8250"

// postForm builds a same-origin form POST, the shape a server-rendered form
// submit actually has.
func postForm(t *testing.T, path string, form url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", loginOrigin)
	return req
}

// startLDAPLogin submits credentials to the login form and returns the
// session id the handler set as a cookie.
func startLDAPLogin(t *testing.T, s *Server) string {
	t.Helper()
	req := postForm(t, "/login/ldap", url.Values{"username": {"u"}, "password": {"p"}})
	w := httptest.NewRecorder()
	s.handleLoginLDAP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("ldap login status = %d, want 303; body = %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == loginCookieName && c.Value != "" {
			return c.Value
		}
	}
	t.Fatal("login did not set a session cookie")
	return ""
}

// pollLDAPProgress drives the progress page until the login reaches a
// terminal state — a redirect (authenticated) or a re-rendered login card
// carrying the failure — and returns that final recorder.
func pollLDAPProgress(t *testing.T, s *Server, sessionID string) *httptest.ResponseRecorder {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		req := httptest.NewRequest("GET", "/login/ldap", nil)
		req.AddCookie(&http.Cookie{Name: loginCookieName, Value: sessionID})
		w := httptest.NewRecorder()
		s.handleLoginLDAPProgress(w, req)
		if w.Code == http.StatusSeeOther || strings.Contains(w.Body.String(), "login-error") {
			return w
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("LDAP login never reached a terminal state")
	return nil
}

// uiTestAuthedServer is an authenticated server with a fake Vault, for the
// entry-point routing tests.
func uiTestAuthedServer(t *testing.T) *Server {
	t.Helper()
	s := testServerWithVault(t, uiTestVaultHandler(t))
	s.cfg.Listen = "127.0.0.1:9000"
	return s
}

func TestLoginPage_RendersConfiguredMethod(t *testing.T) {
	cases := []struct {
		method string
		want   string
	}{
		{"oidc", `href="/auth/oidc/start"`},
		{"ldap", `action="/login/ldap"`},
		{"token", `action="/login/token"`},
		// Certificate auth needs no credential: the card explains the wait
		// rather than prompting for one.
		{"mtls", "Signing in with your client certificate"},
	}
	for _, tc := range cases {
		s := authTestServer(t, nil)
		s.authMethod = tc.method
		w := httptest.NewRecorder()
		s.renderLogin(w, httptest.NewRequest("GET", "/", nil), "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", tc.method, w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, tc.want) {
			t.Errorf("%s login card missing %q", tc.method, tc.want)
		}
		// The login surface must not depend on scripting.
		if strings.Contains(body, "datastar.js") {
			t.Errorf("%s login card loads datastar; the login view is script-free by design", tc.method)
		}
	}
}

// TestLoginPage_MTLSBootstrapBorrowsCredentialCard pins the one interactive
// moment certificate auth has: while a BootstrapLogin waits, the card becomes
// the bootstrap method's credential prompt, framed as a one-time enrolment.
func TestLoginPage_MTLSBootstrapBorrowsCredentialCard(t *testing.T) {
	s := authTestServer(t, nil)
	s.authMethod = "mtls"
	s.bootstrapMethod = "ldap"
	s.bootstrapCh = make(chan string, 1)

	w := httptest.NewRecorder()
	s.renderLogin(w, httptest.NewRequest("GET", "/", nil), "")
	body := w.Body.String()
	if !strings.Contains(body, `action="/login/ldap"`) {
		t.Errorf("bootstrap card missing the LDAP form")
	}
	if !strings.Contains(body, "One-time certificate enrolment") {
		t.Errorf("bootstrap card missing the enrolment framing")
	}

	// With no bootstrap waiting it reverts to the waiting card.
	s.bootstrapCh = nil
	w = httptest.NewRecorder()
	s.renderLogin(w, httptest.NewRequest("GET", "/?issuing=1", nil), "")
	if body := w.Body.String(); !strings.Contains(body, "Issuing your certificate") {
		t.Errorf("post-credential card should report issuance; got %s", body)
	}
}

func TestLoginPOSTs_RequireSameOrigin(t *testing.T) {
	for _, path := range []string{"/login/ldap", "/login/token", "/login/ldap/totp"} {
		s := authTestServer(t, nil)
		req := httptest.NewRequest("POST", path, strings.NewReader("token=x&username=u&password=p&passcode=1"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// No Origin at all, then a cross-site one.
		for _, origin := range []string{"", "http://evil.example.com"} {
			r := req.Clone(req.Context())
			if origin != "" {
				r.Header.Set("Origin", origin)
			}
			w := httptest.NewRecorder()
			switch path {
			case "/login/ldap":
				s.handleLoginLDAP(w, r)
			case "/login/token":
				s.handleLoginToken(w, r)
			case "/login/ldap/totp":
				s.handleLoginLDAPTOTP(w, r)
			}
			if w.Code != http.StatusForbidden {
				t.Errorf("%s with origin %q: status = %d, want 403", path, origin, w.Code)
			}
		}
	}
}

func TestHandleLoginToken_AdoptsAndSignals(t *testing.T) {
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"ttl": 3600, "renewable": true},
		})
	})
	s := authTestServer(t, vc)
	s.tokenFilePath = filepath.Join(t.TempDir(), "vault-token")

	w := httptest.NewRecorder()
	s.handleLoginToken(w, postForm(t, "/login/token", url.Values{"token": {"hvs.test-token"}}))

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body = %s", w.Code, w.Body.String())
	}
	if got := s.vault.Token(); got != "hvs.test-token" {
		t.Errorf("adopted token = %q", got)
	}
	select {
	case <-s.authDone:
	default:
		t.Error("authDone was not signalled")
	}
}

func TestHandleLoginToken_InvalidTokenRerendersCard(t *testing.T) {
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
	})
	s := authTestServer(t, vc)
	s.authMethod = "token"

	w := httptest.NewRecorder()
	s.handleLoginToken(w, postForm(t, "/login/token", url.Values{"token": {"bad"}}))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want the login card re-rendered", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid token") {
		t.Errorf("card missing the error; body = %s", w.Body.String())
	}
	// A rejected token must not be left installed on the client.
	if got := s.vault.Token(); got == "bad" {
		t.Error("invalid token was left on the vault client")
	}
}

// TestHandleLoginToken_RefusedUnderCertAuth keeps the certificate-auth
// invariant: the operational token comes from the certificate login alone, so
// a pasted one must be refused even by direct POST.
func TestHandleLoginToken_RefusedUnderCertAuth(t *testing.T) {
	s := authTestServer(t, nil)
	s.bootstrapMethod = "oidc" // non-empty exactly under certificate auth

	w := httptest.NewRecorder()
	s.handleLoginToken(w, postForm(t, "/login/token", url.Values{"token": {"hvs.x"}}))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 under certificate auth", w.Code)
	}
}

// TestHandleRoot_RoutesByState pins the entry point's three outcomes.
func TestHandleRoot_RoutesByState(t *testing.T) {
	if err := uiInitTemplates(); err != nil {
		t.Fatal(err)
	}

	// Unauthenticated: the login card, not a redirect.
	s := authTestServer(t, nil)
	s.authMethod = "oidc"
	w := httptest.NewRecorder()
	s.handleRoot(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/auth/oidc/start") {
		t.Fatalf("unauthenticated root: status = %d, body = %s", w.Code, w.Body.String())
	}

	// Authenticated with nothing enrolled: the first-run wizard.
	s = uiTestAuthedServer(t)
	s.InitEnrolments(t.Context(), map[string]config.Enrolment{"ssh": {Engine: "ssh"}})
	w = httptest.NewRecorder()
	s.handleRoot(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup/" {
		t.Fatalf("wizard-needed root: status = %d, location = %q", w.Code, w.Header().Get("Location"))
	}

	// Authenticated with an enrolment already complete: straight to the site.
	s.getEnrolRunner().MarkComplete("ssh")
	w = httptest.NewRecorder()
	s.handleRoot(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/" {
		t.Fatalf("enrolled root: status = %d, location = %q", w.Code, w.Header().Get("Location"))
	}
}
