package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/config"
)

// waitBootstrapActive spins until a BootstrapLogin has registered itself, so
// tests never race the goroutine that calls it.
func waitBootstrapActive(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.bootstrapActive() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("BootstrapLogin never became active")
}

// --- OIDC callback in bootstrap mode ---

// TestBootstrapLogin_OIDCReturnsRawTokenWithoutAdopting is the core security
// assertion: the bootstrap token reaches the caller verbatim and touches
// nothing else. Without the bootstrap branch the handler would downscope it
// (auth/token/create), install it on s.vault, and write it to disk.
func TestBootstrapLogin_OIDCReturnsRawTokenWithoutAdopting(t *testing.T) {
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/create" {
			t.Error("auth/token/create called — a bootstrap token must not be downscoped")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "bootstrap-token", "policies": []string{"pki-sign"}},
		})
	})

	s := authTestServer(t, vc)
	// Policies are configured, so a non-bootstrap login WOULD downscope.
	s.vaultCfg = config.VaultConfig{Policies: []string{"dotvault"}}
	tokenFile := filepath.Join(t.TempDir(), "vault-token")
	s.tokenFilePath = tokenFile

	type result struct {
		token string
		err   error
	}
	resCh := make(chan result, 1)
	go func() {
		tok, err := s.BootstrapLogin(context.Background())
		resCh <- result{tok, err}
	}()
	waitBootstrapActive(t, s)

	req := httptest.NewRequest("GET", "/auth/oidc/callback?code=c&state=st", nil)
	w := httptest.NewRecorder()
	s.handleAuthCallback(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("BootstrapLogin() error = %v, want nil", res.err)
		}
		if res.token != "bootstrap-token" {
			t.Errorf("BootstrapLogin() token = %q, want the RAW bootstrap-token", res.token)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("BootstrapLogin did not return after a successful callback")
	}

	if got := s.vault.Token(); got != "" {
		t.Errorf("s.vault token = %q, want empty — the bootstrap token must never be adopted", got)
	}
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Errorf("token file %s exists (stat err %v) — the bootstrap token must never be written", tokenFile, err)
	}
	select {
	case <-s.authDone:
		t.Error("authDone signalled — a bootstrap login is not an operational login")
	default:
	}
	if s.bootstrapActive() {
		t.Error("bootstrap mode still active after the token was delivered")
	}
}

// --- LDAP status in bootstrap mode ---

// ldapBootstrapServer drives an LDAP login to the authenticated state through
// the real LoginTracker and returns the server plus the session ID.
func ldapBootstrapServer(t *testing.T, token string) (*Server, string) {
	t.Helper()
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/create" {
			t.Error("auth/token/create called — a bootstrap token must not be downscoped")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{
				"client_token":   token,
				"lease_duration": 3600,
				"renewable":      true,
			},
		})
	})

	s := authTestServer(t, vc)
	s.authMethod = "ldap"
	s.authMount = "ldap"
	s.vaultCfg = config.VaultConfig{Policies: []string{"dotvault"}}

	body := strings.NewReader(`{"username":"u","password":"p"}`)
	req := httptest.NewRequest("POST", "/auth/ldap/login", body)
	w := httptest.NewRecorder()
	s.handleLDAPLogin(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("ldap login status = %d, want 202", w.Code)
	}
	var resp struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	return s, resp.SessionID
}

// pollLDAPStatus polls handleLDAPStatus until the login reaches a terminal
// state, mirroring what the SPA does, and returns the final recorder.
func pollLDAPStatus(t *testing.T, s *Server, sessionID string) *httptest.ResponseRecorder {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		req := httptest.NewRequest("GET", "/auth/ldap/status?session="+sessionID, nil)
		w := httptest.NewRecorder()
		s.handleLDAPStatus(w, req)
		var st struct {
			State string `json:"state"`
		}
		json.Unmarshal(w.Body.Bytes(), &st)
		if st.State == "authenticated" || st.State == "failed" {
			return w
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("LDAP login never reached a terminal state")
	return nil
}

func TestBootstrapLogin_LDAPReturnsRawTokenWithoutAdopting(t *testing.T) {
	s, sessionID := ldapBootstrapServer(t, "ldap-bootstrap-token")
	tokenFile := filepath.Join(t.TempDir(), "vault-token")
	s.tokenFilePath = tokenFile

	resCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		tok, err := s.BootstrapLogin(context.Background())
		resCh <- tok
		errCh <- err
	}()
	waitBootstrapActive(t, s)

	w := pollLDAPStatus(t, s, sessionID)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// The token must not appear in the response body.
	if strings.Contains(w.Body.String(), "ldap-bootstrap-token") {
		t.Error("response body leaked the bootstrap token")
	}

	select {
	case tok := <-resCh:
		if err := <-errCh; err != nil {
			t.Fatalf("BootstrapLogin() error = %v", err)
		}
		if tok != "ldap-bootstrap-token" {
			t.Errorf("BootstrapLogin() token = %q, want the RAW ldap-bootstrap-token", tok)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("BootstrapLogin did not return after the LDAP login authenticated")
	}

	if got := s.vault.Token(); got != "" {
		t.Errorf("s.vault token = %q, want empty", got)
	}
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Errorf("token file %s exists (stat err %v) — must not be written in bootstrap mode", tokenFile, err)
	}
	select {
	case <-s.authDone:
		t.Error("authDone signalled during a bootstrap login")
	default:
	}
}

// TestHandleLDAPStatus_NonBootstrapStillAdopts guards the other half of the
// contract: with no BootstrapLogin waiting, the handler behaves exactly as it
// did before — downscope, adopt, persist, signal.
func TestHandleLDAPStatus_NonBootstrapStillAdopts(t *testing.T) {
	var createCalled bool
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/token/create":
			createCalled = true
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{"client_token": "child-token"},
			})
		default:
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{
					"client_token":   "broad-token",
					"lease_duration": 3600,
					"renewable":      true,
				},
			})
		}
	})

	s := authTestServer(t, vc)
	s.authMethod = "ldap"
	s.authMount = "ldap"
	s.vaultCfg = config.VaultConfig{Policies: []string{"dotvault"}}
	tokenFile := filepath.Join(t.TempDir(), "vault-token")
	s.tokenFilePath = tokenFile

	body := strings.NewReader(`{"username":"u","password":"p"}`)
	req := httptest.NewRequest("POST", "/auth/ldap/login", body)
	w := httptest.NewRecorder()
	s.handleLDAPLogin(w, req)
	var resp struct {
		SessionID string `json:"session_id"`
	}
	json.NewDecoder(w.Body).Decode(&resp)

	pollLDAPStatus(t, s, resp.SessionID)

	if !createCalled {
		t.Error("auth/token/create not called — non-bootstrap login must still downscope")
	}
	if got := s.vault.Token(); got != "child-token" {
		t.Errorf("adopted token = %q, want child-token", got)
	}
	if _, err := os.Stat(tokenFile); err != nil {
		t.Errorf("token file not written in non-bootstrap mode: %v", err)
	}
	select {
	case <-s.authDone:
	default:
		t.Error("authDone not signalled for a non-bootstrap login")
	}
}

// --- BootstrapLogin lifecycle ---

func TestBootstrapLogin_ContextCancelled(t *testing.T) {
	s := &Server{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tok, err := s.BootstrapLogin(ctx)
	if err == nil {
		t.Fatal("BootstrapLogin() = nil error, want cancellation error")
	}
	if tok != "" {
		t.Errorf("BootstrapLogin() token = %q, want empty on cancellation", tok)
	}
	if s.bootstrapActive() {
		t.Error("bootstrap mode still active after cancellation")
	}
}

func TestBootstrapLogin_ConcurrentCallRejected(t *testing.T) {
	s := &Server{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { s.BootstrapLogin(ctx) }()
	waitBootstrapActive(t, s)

	if _, err := s.BootstrapLogin(context.Background()); err == nil {
		t.Error("second concurrent BootstrapLogin() = nil error, want rejection")
	}
}

// TestBootstrapLogin_RepeatAfterCompletion proves the mode is fully reset, so
// a retried bootstrap (e.g. the first cert mint failed) works.
func TestBootstrapLogin_RepeatAfterCompletion(t *testing.T) {
	s := &Server{}
	for _, want := range []string{"first", "second"} {
		done := make(chan string, 1)
		go func() {
			tok, err := s.BootstrapLogin(context.Background())
			if err != nil {
				t.Errorf("BootstrapLogin() error = %v", err)
			}
			done <- tok
		}()
		waitBootstrapActive(t, s)
		if !s.deliverBootstrapToken(want) {
			t.Fatalf("deliverBootstrapToken(%q) = false, want true", want)
		}
		if got := <-done; got != want {
			t.Errorf("BootstrapLogin() = %q, want %q", got, want)
		}
	}
}

// TestDeliverBootstrapToken_InactiveReturnsFalse pins the fall-through that
// keeps non-bootstrap adoption byte-for-byte unchanged.
func TestDeliverBootstrapToken_InactiveReturnsFalse(t *testing.T) {
	s := &Server{}
	if s.deliverBootstrapToken("tok") {
		t.Error("deliverBootstrapToken() = true with no BootstrapLogin waiting")
	}
}

// --- /api/v1/status shape ---

func TestHandleStatus_BootstrapField(t *testing.T) {
	decode := func(t *testing.T, s *Server) map[string]any {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/v1/status", nil)
		w := httptest.NewRecorder()
		s.handleStatus(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode status: %v", err)
		}
		bs, ok := body["bootstrap"].(map[string]any)
		if !ok {
			t.Fatalf("status has no bootstrap object: %v", body)
		}
		return bs
	}

	s := &Server{bootstrapMethod: "ldap"}

	// Idle: reported but inactive, served without authentication.
	bs := decode(t, s)
	if bs["active"] != false {
		t.Errorf("bootstrap.active = %v, want false when idle", bs["active"])
	}
	if bs["method"] != "ldap" {
		t.Errorf("bootstrap.method = %v, want ldap", bs["method"])
	}

	// Active while a BootstrapLogin waits.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { s.BootstrapLogin(ctx) }()
	waitBootstrapActive(t, s)

	bs = decode(t, s)
	if bs["active"] != true {
		t.Errorf("bootstrap.active = %v, want true while a BootstrapLogin waits", bs["active"])
	}
	// The token must never be exposed, whatever the state.
	if _, ok := bs["token"]; ok {
		t.Error("bootstrap object exposes a token field")
	}
}

// TestLDAPStatus_LosingConcurrentPollCannotAdoptRawToken pins the fix for a
// TOCTOU found in pre-push review.
//
// LoginTracker.GetStatus returns a *copy* of the session and the session is
// cleared only after the bootstrap divert, so two overlapping polls of the
// (unauthenticated, un-CSRF'd) /auth/ldap/status can both observe the same
// authenticated session holding the same raw token. The winner is diverted to
// the waiting BootstrapLogin; the loser used to fall through to the adoption
// path — where Downscope is a NO-OP under an inactive constraint — installing
// the raw pki/sign bootstrap token on the shared client, in the token file,
// and behind GET /api/v1/token.
//
// This models the LOSER's state directly rather than racing two goroutines:
// an authenticated session still present, bootstrap mode already consumed
// (bootstrapCh nil), certificate auth configured. Sequencing two real polls
// cannot reproduce it, because the winner's Clear makes the second poll 404
// before it reaches the adoption path.
//
// Two things here are load-bearing and easy to lose in a refactor:
//   - the constraint is the shipped DEFAULT (no policies), so Downscope is a
//     no-op and adoption is silent. The other tests in this file set Policies,
//     which is why they miss this.
//   - bootstrapMethod is set, i.e. the daemon is under certificate auth.
//
// Reverting operationalAdoptionAllowed must fail this test.
func TestLDAPStatus_LosingConcurrentPollCannotAdoptRawToken(t *testing.T) {
	const rawToken = "raw-pki-sign-bootstrap-token"

	s, sessionID := ldapBootstrapServer(t, rawToken)
	tokenFile := filepath.Join(t.TempDir(), "vault-token")
	s.tokenFilePath = tokenFile
	s.vaultCfg = config.VaultConfig{} // shipped default: Downscope is a no-op
	s.bootstrapMethod = "ldap"        // certificate auth is configured

	// Wait for the session to authenticate WITHOUT polling the handler, so the
	// session survives (a poll would divert-and-Clear it).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st := s.login.GetStatus(sessionID); st != nil && st.State == "authenticated" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	st := s.login.GetStatus(sessionID)
	if st == nil || st.State != "authenticated" || st.Token != rawToken {
		t.Fatalf("precondition: session not authenticated with the raw token (got %+v)", st)
	}

	// bootstrapCh is nil — the winning poll already consumed bootstrap mode.
	if s.bootstrapActive() {
		t.Fatal("precondition: bootstrap mode should not be active")
	}

	req := httptest.NewRequest("GET", "/auth/ldap/status?session="+sessionID, nil)
	w := httptest.NewRecorder()
	s.handleLDAPStatus(w, req)

	if got := s.vault.Token(); got == rawToken {
		t.Error("shared client holds the raw pki/sign bootstrap token; it is now reachable via GET /api/v1/token")
	}
	if got := s.vault.Token(); got != "" {
		t.Errorf("shared client token = %q, want empty — nothing may be adopted under certificate auth", got)
	}
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Errorf("token file %s was written (stat err %v) — the bootstrap token must never reach disk", tokenFile, err)
	}
	if strings.Contains(w.Body.String(), rawToken) {
		t.Error("response body leaked the bootstrap token")
	}
}

// TestTokenLogin_RefusedUnderCertificateAuth pins the third adoption site.
//
// operationalAdoptionAllowed's contract is that under certificate auth the
// operational token comes from exactly one place — the cert login. Guarding
// only the two bootstrap-adjacent sites left /auth/token/login able to install
// a credential the cert flow never sanctioned, contradicting that contract.
// It is CSRF-protected and loopback-only and the SPA never renders the form
// under mtls, so this closes the direct-POST path rather than a likely one.
//
// Reverting the guard in handleTokenLogin must fail this test.
func TestTokenLogin_RefusedUnderCertificateAuth(t *testing.T) {
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("Vault called at %s — the request must be refused before any lookup", r.URL.Path)
	})
	s := authTestServer(t, vc)
	tokenFile := filepath.Join(t.TempDir(), "vault-token")
	s.tokenFilePath = tokenFile
	s.authMethod = "mtls"
	s.bootstrapMethod = "ldap" // certificate auth is configured

	body := strings.NewReader(`{"token":"s.user-supplied-token"}`)
	req := httptest.NewRequest("POST", "/auth/token/login", body)
	w := httptest.NewRecorder()
	s.handleTokenLogin(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if got := s.vault.Token(); got != "" {
		t.Errorf("shared client token = %q, want empty — nothing may be adopted under certificate auth", got)
	}
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Errorf("token file %s was written (stat err %v)", tokenFile, err)
	}
}

// TestTokenLogin_AllowedWithoutCertificateAuth is the counterpart: the guard
// must not disturb the ordinary token-login path, which is exempt from
// downscoping by design (a user-supplied token, like the CLI's token method).
func TestTokenLogin_AllowedWithoutCertificateAuth(t *testing.T) {
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "s.user-supplied-token"}})
	})
	s := authTestServer(t, vc)
	s.tokenFilePath = filepath.Join(t.TempDir(), "vault-token")
	s.authMethod = "token"
	s.bootstrapMethod = "" // not certificate auth

	body := strings.NewReader(`{"token":"s.user-supplied-token"}`)
	req := httptest.NewRequest("POST", "/auth/token/login", body)
	w := httptest.NewRecorder()
	s.handleTokenLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if got := s.vault.Token(); got != "s.user-supplied-token" {
		t.Errorf("shared client token = %q, want the adopted token", got)
	}
}

// TestLoginMount_UsesBootstrapMountUnderCertAuth pins PR-review finding P1.
//
// Under certificate auth every browser login is a bootstrap, so it must target
// vault.mtls.bootstrap_mount. The CLI bootstrap already does — runBootstrap
// builds its Manager with AuthMount: m.MTLS.BootstrapMount — so before this fix
// a deployment whose bootstrap mount differed from its operational auth mount
// worked from the CLI and silently hit the wrong Vault path from the SPA.
//
// Reverting loginMount (i.e. going back to s.authMount at the three handler
// sites) must fail the certAuth cases below.
func TestLoginMount_UsesBootstrapMountUnderCertAuth(t *testing.T) {
	tests := []struct {
		name            string
		authMount       string
		bootstrapMethod string
		bootstrapMount  string
		fallback        string
		want            string
	}{
		{
			name:            "certAuthPrefersBootstrapMount",
			authMount:       "operational-ldap",
			bootstrapMethod: "ldap",
			bootstrapMount:  "bootstrap-ldap",
			fallback:        "ldap",
			want:            "bootstrap-ldap",
		},
		{
			// The bug: auth_mount set, bootstrap_mount not. Must NOT leak the
			// operational mount into the bootstrap login.
			name:            "certAuthIgnoresAuthMount",
			authMount:       "operational-ldap",
			bootstrapMethod: "ldap",
			bootstrapMount:  "",
			fallback:        "ldap",
			want:            "ldap",
		},
		{
			name:            "certAuthOIDCFallback",
			authMount:       "operational-oidc",
			bootstrapMethod: "oidc",
			bootstrapMount:  "",
			fallback:        "oidc",
			want:            "oidc",
		},
		{
			name:      "nonCertAuthUsesAuthMount",
			authMount: "corp-ldap",
			fallback:  "ldap",
			want:      "corp-ldap",
		},
		{
			name:     "nonCertAuthFallsBack",
			fallback: "oidc",
			want:     "oidc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				authMount:       tt.authMount,
				bootstrapMethod: tt.bootstrapMethod,
				bootstrapMount:  tt.bootstrapMount,
			}
			if got := s.loginMount(tt.fallback); got != tt.want {
				t.Errorf("loginMount(%q) = %q, want %q", tt.fallback, got, tt.want)
			}
		})
	}
}
