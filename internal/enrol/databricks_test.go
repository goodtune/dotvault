package enrol

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDatabricksEngine_Name(t *testing.T) {
	e := &DatabricksEngine{}
	if got := e.Name(); got != "Databricks" {
		t.Errorf("Name() = %q, want %q", got, "Databricks")
	}
}

func TestDatabricksEngine_Fields(t *testing.T) {
	e := &DatabricksEngine{}
	got := e.Fields()
	want := []string{"access_token", "refresh_token", "host", "issued_at", "expires_at"}
	if len(got) != len(want) {
		t.Fatalf("Fields() = %v, want %v", got, want)
	}
	for i, f := range got {
		if f != want[i] {
			t.Errorf("Fields()[%d] = %q, want %q", i, f, want[i])
		}
	}
}

func TestDatabricksEngine_Registered(t *testing.T) {
	e, ok := GetEngine("databricks")
	if !ok {
		t.Fatal("databricks engine not registered")
	}
	if _, ok := e.(*DatabricksEngine); !ok {
		t.Errorf("registered engine is %T, want *DatabricksEngine", e)
	}
	if _, ok := e.(Refresher); !ok {
		t.Error("databricks engine does not implement Refresher")
	}
}

func TestNormalizeDatabricksHost(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"dbc-123.cloud.databricks.com", "https://dbc-123.cloud.databricks.com", false},
		{"https://dbc-123.cloud.databricks.com", "https://dbc-123.cloud.databricks.com", false},
		{"https://dbc-123.cloud.databricks.com/", "https://dbc-123.cloud.databricks.com", false},
		{"HTTPS://dbc-123.cloud.databricks.com", "https://dbc-123.cloud.databricks.com", false},
		// Rejected: explicit http (cleartext bearer), paths, queries,
		// fragments, empty, non-http schemes.
		{"http://dbc-123.cloud.databricks.com", "", true},
		{"http://127.0.0.1:8080", "", true},
		{"https://dbc-123.cloud.databricks.com/sql", "", true},
		{"https://dbc-123.cloud.databricks.com?x=1", "", true},
		{"https://dbc-123.cloud.databricks.com#f", "", true},
		{"", "", true},
		{"   ", "", true},
		{"ftp://dbc-123.cloud.databricks.com", "", true},
	}
	for _, tc := range cases {
		got, err := normalizeDatabricksHost(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("normalizeDatabricksHost(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeDatabricksHost(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("normalizeDatabricksHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDatabricksScopes(t *testing.T) {
	// Default when unset.
	got, err := databricksScopes(map[string]any{})
	if err != nil {
		t.Fatalf("default scopes error: %v", err)
	}
	if strings.Join(got, " ") != "offline_access all-apis" {
		t.Errorf("default scopes = %v, want [offline_access all-apis]", got)
	}

	// Custom list missing offline_access gets it prepended.
	got, err = databricksScopes(map[string]any{"scopes": []any{"all-apis"}})
	if err != nil {
		t.Fatalf("custom scopes error: %v", err)
	}
	if len(got) != 2 || got[0] != "offline_access" || got[1] != "all-apis" {
		t.Errorf("custom scopes = %v, want [offline_access all-apis]", got)
	}

	// Custom list already containing offline_access is left verbatim.
	got, err = databricksScopes(map[string]any{"scopes": []any{"all-apis", "offline_access"}})
	if err != nil {
		t.Fatalf("custom scopes error: %v", err)
	}
	if len(got) != 2 || got[0] != "all-apis" || got[1] != "offline_access" {
		t.Errorf("scopes = %v, want [all-apis offline_access]", got)
	}

	// Wrong type errors.
	if _, err := databricksScopes(map[string]any{"scopes": "all-apis"}); err == nil {
		t.Error("expected error for non-list scopes")
	}
}

func TestDatabricksRandString(t *testing.T) {
	a, err := databricksRandString(64)
	if err != nil {
		t.Fatalf("randString error: %v", err)
	}
	if len(a) != 64 {
		t.Errorf("len = %d, want 64", len(a))
	}
	b, _ := databricksRandString(64)
	if a == b {
		t.Error("two random strings collided")
	}
	s, _ := databricksRandString(16)
	if len(s) != 16 {
		t.Errorf("state len = %d, want 16", len(s))
	}
}

func TestDatabricksTokenLifetime(t *testing.T) {
	if got := databricksTokenLifetime(databricksTokenResp{ExpiresIn: 3600}); got != time.Hour {
		t.Errorf("lifetime(3600) = %v, want 1h", got)
	}
	if got := databricksTokenLifetime(databricksTokenResp{ExpiresIn: 0}); got != time.Hour {
		t.Errorf("lifetime(0) = %v, want 1h default", got)
	}
}

func TestDatabricksEngine_Run_MissingHost(t *testing.T) {
	e := &DatabricksEngine{}
	_, err := e.Run(context.Background(), map[string]any{}, newTestIO())
	if err == nil {
		t.Fatal("expected error when host setting is missing")
	}
	if !strings.Contains(err.Error(), "host") {
		t.Errorf("error %q does not mention 'host'", err.Error())
	}
}

// databricksTestServer builds an httptest TLS server that serves OIDC
// discovery, the token endpoint, and the SCIM /Me endpoint. A TLS server is
// used (not plain HTTP) because the engine requires an https host; srv.Client()
// is preconfigured to trust the server's cert. The discovery doc is served at
// both the workspace and account-level well-known paths so account_id tests can
// reuse the helper. The tokenHandler lets each test decide the token response.
func databricksTestServer(t *testing.T, tokenHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	discovery := func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(databricksOAuthServer{
			AuthorizationEndpoint: srv.URL + "/oidc/v1/authorize",
			TokenEndpoint:         srv.URL + "/oidc/v1/token",
		})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/.well-known/oauth-authorization-server", discovery)
	mux.HandleFunc("/oidc/v1/token", tokenHandler)
	mux.HandleFunc("/api/2.0/preview/scim/v2/Me", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"userName": "alice@example.com"})
	})
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// ephemeralListen returns a DatabricksEngine.listen func bound to a random
// loopback port so tests don't fight over the real 8020-8040 range.
func ephemeralListen(t *testing.T) func() (net.Listener, string, error) {
	t.Helper()
	return func() (net.Listener, string, error) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, "", err
		}
		return ln, "http://" + ln.Addr().String(), nil
	}
}

func TestDatabricksEngine_Run_FullFlow(t *testing.T) {
	var gotForm url.Values
	srv := databricksTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		_ = json.NewEncoder(w).Encode(databricksTokenResp{
			AccessToken:  "access-1",
			RefreshToken: "refresh-1",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
	})

	io := newTestIO()
	// The browser stand-in parses the authorize URL and simulates the IdP
	// redirecting back to the loopback listener with a code + the echoed state.
	io.Browser = func(rawAuthURL string) error {
		u, err := url.Parse(rawAuthURL)
		if err != nil {
			return err
		}
		q := u.Query()
		// Sanity-check the PKCE/authorize parameters the engine built.
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			t.Errorf("authorize URL missing PKCE challenge: %s", rawAuthURL)
		}
		if q.Get("client_id") != "databricks-cli" {
			t.Errorf("client_id = %q, want databricks-cli", q.Get("client_id"))
		}
		if q.Get("scope") != "offline_access all-apis" {
			t.Errorf("scope = %q", q.Get("scope"))
		}
		cb := q.Get("redirect_uri") + "/?code=auth-code-1&state=" + url.QueryEscape(q.Get("state"))
		resp, err := http.Get(cb)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}

	fixedNow := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	e := &DatabricksEngine{
		httpClient: srv.Client(),
		now:        func() time.Time { return fixedNow },
		listen:     ephemeralListen(t),
	}
	creds, err := e.Run(context.Background(), map[string]any{"host": srv.URL}, io)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if creds["access_token"] != "access-1" {
		t.Errorf("access_token = %q", creds["access_token"])
	}
	if creds["refresh_token"] != "refresh-1" {
		t.Errorf("refresh_token = %q", creds["refresh_token"])
	}
	if creds["host"] != srv.URL {
		t.Errorf("host = %q, want %q", creds["host"], srv.URL)
	}
	if creds["user"] != "alice@example.com" {
		t.Errorf("user = %q, want alice@example.com", creds["user"])
	}
	if creds["issued_at"] != fixedNow.Format(time.RFC3339) {
		t.Errorf("issued_at = %q", creds["issued_at"])
	}
	if creds["expires_at"] != fixedNow.Add(time.Hour).Format(time.RFC3339) {
		t.Errorf("expires_at = %q", creds["expires_at"])
	}

	// The token exchange must be a PKCE authorization_code grant.
	if gotForm.Get("grant_type") != "authorization_code" {
		t.Errorf("grant_type = %q", gotForm.Get("grant_type"))
	}
	if gotForm.Get("code") != "auth-code-1" {
		t.Errorf("code = %q", gotForm.Get("code"))
	}
	if gotForm.Get("code_verifier") == "" {
		t.Error("code_verifier missing from token exchange")
	}
	if gotForm.Get("client_id") != "databricks-cli" {
		t.Errorf("token client_id = %q", gotForm.Get("client_id"))
	}

	// HasAllFields must accept the result.
	data := make(map[string]any, len(creds))
	for k, v := range creds {
		data[k] = v
	}
	if !HasAllFields(data, e.Fields()) {
		t.Error("HasAllFields rejected a complete enrolment")
	}
}

func TestDatabricksEngine_Refresh_FullFlow(t *testing.T) {
	var gotForm url.Values
	srv := databricksTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		// Rotate both tokens, mirroring providers that issue a fresh refresh.
		_ = json.NewEncoder(w).Encode(databricksTokenResp{
			AccessToken:  "access-2",
			RefreshToken: "refresh-2",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
	})

	fixedNow := time.Date(2026, 6, 3, 13, 0, 0, 0, time.UTC)
	e := &DatabricksEngine{
		httpClient: srv.Client(),
		now:        func() time.Time { return fixedNow },
	}
	existing := map[string]string{
		"access_token":  "access-1",
		"refresh_token": "refresh-1",
		"host":          srv.URL,
		"user":          "alice@example.com",
	}
	out, err := e.Refresh(context.Background(), map[string]any{"host": srv.URL}, existing)
	if err != nil {
		t.Fatalf("Refresh error: %v", err)
	}

	if gotForm.Get("grant_type") != "refresh_token" {
		t.Errorf("grant_type = %q", gotForm.Get("grant_type"))
	}
	if gotForm.Get("refresh_token") != "refresh-1" {
		t.Errorf("sent refresh_token = %q, want refresh-1", gotForm.Get("refresh_token"))
	}
	if out["access_token"] != "access-2" {
		t.Errorf("rotated access_token = %q", out["access_token"])
	}
	if out["refresh_token"] != "refresh-2" {
		t.Errorf("rotated refresh_token = %q", out["refresh_token"])
	}
	if out["user"] != "alice@example.com" {
		t.Errorf("user not preserved: %q", out["user"])
	}
	if out["expires_at"] != fixedNow.Add(time.Hour).Format(time.RFC3339) {
		t.Errorf("expires_at = %q", out["expires_at"])
	}
}

func TestDatabricksEngine_Refresh_PreservesRefreshTokenWhenAbsent(t *testing.T) {
	srv := databricksTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// No refresh_token in the response — engine must keep the old one.
		_ = json.NewEncoder(w).Encode(databricksTokenResp{
			AccessToken: "access-2",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	})
	e := &DatabricksEngine{httpClient: srv.Client(), now: func() time.Time { return time.Now().UTC() }}
	out, err := e.Refresh(context.Background(), map[string]any{"host": srv.URL}, map[string]string{
		"refresh_token": "refresh-1",
		"host":          srv.URL,
	})
	if err != nil {
		t.Fatalf("Refresh error: %v", err)
	}
	if out["refresh_token"] != "refresh-1" {
		t.Errorf("refresh_token = %q, want refresh-1 preserved", out["refresh_token"])
	}
}

func TestDatabricksEngine_Refresh_Revoked(t *testing.T) {
	srv := databricksTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_grant","error_description":"refresh token invalid"}`, http.StatusUnauthorized)
	})
	e := &DatabricksEngine{httpClient: srv.Client()}
	_, err := e.Refresh(context.Background(), map[string]any{"host": srv.URL}, map[string]string{
		"refresh_token": "refresh-1",
		"host":          srv.URL,
	})
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("Refresh error = %v, want ErrRevoked", err)
	}
}

func TestDatabricksEngine_Refresh_TransientNotRevoked(t *testing.T) {
	srv := databricksTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream hiccup", http.StatusInternalServerError)
	})
	e := &DatabricksEngine{httpClient: srv.Client()}
	_, err := e.Refresh(context.Background(), map[string]any{"host": srv.URL}, map[string]string{
		"refresh_token": "refresh-1",
		"host":          srv.URL,
	})
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if errors.Is(err, ErrRevoked) {
		t.Errorf("a 500 must be transient, not ErrRevoked: %v", err)
	}
}

func TestDatabricksDiscover_AccountLevel(t *testing.T) {
	var gotPath string
	mux := http.NewServeMux()
	// Register ONLY the account-level path; if the engine builds the workspace
	// path instead, the request 404s and discovery fails the test.
	mux.HandleFunc("/oidc/accounts/acc-123/.well-known/oauth-authorization-server",
		func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			_ = json.NewEncoder(w).Encode(databricksOAuthServer{
				AuthorizationEndpoint: "https://example/authorize",
				TokenEndpoint:         "https://example/token",
			})
		})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	server, err := databricksDiscover(context.Background(), srv.Client(), srv.URL, "acc-123")
	if err != nil {
		t.Fatalf("discover error: %v", err)
	}
	if server.TokenEndpoint != "https://example/token" {
		t.Errorf("token endpoint = %q", server.TokenEndpoint)
	}
	if gotPath != "/oidc/accounts/acc-123/.well-known/oauth-authorization-server" {
		t.Errorf("discovery path = %q, want account-level path", gotPath)
	}
}

func TestDatabricksEngine_Run_StateMismatch(t *testing.T) {
	srv := databricksTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("token endpoint must not be called on a state mismatch")
	})
	io := newTestIO()
	io.Browser = func(rawAuthURL string) error {
		u, err := url.Parse(rawAuthURL)
		if err != nil {
			return err
		}
		// Reply with a code but the WRONG state — the CSRF guard must reject it.
		cb := u.Query().Get("redirect_uri") + "/?code=x&state=not-the-state"
		resp, err := http.Get(cb)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}
	e := &DatabricksEngine{httpClient: srv.Client(), listen: ephemeralListen(t)}
	_, err := e.Run(context.Background(), map[string]any{"host": srv.URL}, io)
	if err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("Run error = %v, want a state-mismatch error", err)
	}
}

func TestDatabricksEngine_Run_Timeout(t *testing.T) {
	srv := databricksTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("token endpoint must not be called when login never completes")
	})
	io := newTestIO()
	io.Browser = func(string) error { return nil } // user never finishes the login
	e := &DatabricksEngine{
		httpClient:   srv.Client(),
		listen:       ephemeralListen(t),
		loginTimeout: 50 * time.Millisecond,
	}
	_, err := e.Run(context.Background(), map[string]any{"host": srv.URL}, io)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("Run error = %v, want timeout", err)
	}
}
