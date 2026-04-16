package enrol

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestJFrogEngine_Name(t *testing.T) {
	e := &JFrogEngine{}
	if got := e.Name(); got != "JFrog" {
		t.Errorf("Name() = %q, want %q", got, "JFrog")
	}
}

func TestJFrogEngine_Fields(t *testing.T) {
	e := &JFrogEngine{}
	got := e.Fields()
	want := []string{"access_token", "refresh_token", "url", "server_id", "user", "issued_at", "expires_at"}
	if len(got) != len(want) {
		t.Fatalf("Fields() = %v, want %v", got, want)
	}
	for i, f := range got {
		if f != want[i] {
			t.Errorf("Fields()[%d] = %q, want %q", i, f, want[i])
		}
	}
}

func TestJFrogEngine_Registered(t *testing.T) {
	e, ok := GetEngine("jfrog")
	if !ok {
		t.Fatal("jfrog engine not registered")
	}
	if _, ok := e.(*JFrogEngine); !ok {
		t.Errorf("registered engine is %T, want *JFrogEngine", e)
	}
}

func TestDeduceJFrogServerID(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://mycompany.jfrog.io", "mycompany"},
		{"https://mycompany.jfrog.io/", "mycompany"},
		{"https://artifactory.example.com/", "artifactory"},
		{"https://127.0.0.1:8082", "default-server"},
		{"https://[::1]:8082", "default-server"},
	}
	for _, tc := range cases {
		got, err := deduceJFrogServerID(tc.in)
		if err != nil {
			t.Errorf("deduceJFrogServerID(%q) error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("deduceJFrogServerID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestEnsureScheme(t *testing.T) {
	cases := map[string]string{
		"mycompany.jfrog.io":          "https://mycompany.jfrog.io",
		"https://mycompany.jfrog.io":  "https://mycompany.jfrog.io",
		"http://localhost:8082":       "http://localhost:8082",
	}
	for in, want := range cases {
		if got := ensureScheme(in); got != want {
			t.Errorf("ensureScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeJFrogPlatformURL(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		// Accepted shapes — bare host, trailing slash, explicit scheme.
		{"mycompany.jfrog.io", "https://mycompany.jfrog.io", false},
		{"https://mycompany.jfrog.io", "https://mycompany.jfrog.io", false},
		{"https://mycompany.jfrog.io/", "https://mycompany.jfrog.io", false},
		{"http://127.0.0.1:8082", "http://127.0.0.1:8082", false},
		{"http://127.0.0.1:8082/", "http://127.0.0.1:8082", false},

		// Rejected: paths, queries, fragments, empty.
		{"https://mycompany.jfrog.io/artifactory", "", true},
		{"https://mycompany.jfrog.io/artifactory/", "", true},
		{"https://mycompany.jfrog.io?foo=bar", "", true},
		{"https://mycompany.jfrog.io#frag", "", true},
		{"", "", true},
		{"   ", "", true},
		// Rejected: non-http schemes would later fail at http.Client.Do with
		// a vague "unsupported protocol scheme" — easier to catch up front.
		{"ftp://mycompany.jfrog.io", "", true},
		{"file:///etc/passwd", "", true},
		{"ssh://mycompany.jfrog.io", "", true},
	}
	for _, tc := range cases {
		got, err := normalizeJFrogPlatformURL(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("normalizeJFrogPlatformURL(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeJFrogPlatformURL(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("normalizeJFrogPlatformURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNewUUIDv4_Format(t *testing.T) {
	u, err := newUUIDv4()
	if err != nil {
		t.Fatalf("newUUIDv4 error: %v", err)
	}
	if len(u) != 36 {
		t.Errorf("uuid length = %d, want 36", len(u))
	}
	if u[8] != '-' || u[13] != '-' || u[18] != '-' || u[23] != '-' {
		t.Errorf("uuid %q missing dashes in expected positions", u)
	}
	// Version nibble is position 14 (the 15th char), must be '4'.
	if u[14] != '4' {
		t.Errorf("uuid version nibble = %c, want '4' (got %q)", u[14], u)
	}
	// Variant nibble at position 19 must be one of 8,9,a,b.
	switch u[19] {
	case '8', '9', 'a', 'b':
	default:
		t.Errorf("uuid variant nibble = %c, want one of 8/9/a/b (got %q)", u[19], u)
	}
}

func TestExtractUsernameFromJWT(t *testing.T) {
	mkJWT := func(sub string) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		claims, _ := json.Marshal(map[string]string{"sub": sub})
		payload := base64.RawURLEncoding.EncodeToString(claims)
		return header + "." + payload + ".sig"
	}

	cases := map[string]string{
		mkJWT("jfrt@01g123/users/alice"): "alice",
		mkJWT("some/users/bob"):          "bob",
		mkJWT("carol"):                   "carol",
		mkJWT(""):                        "",
		"not-a-jwt":                      "",
	}
	for tok, want := range cases {
		if got := extractUsernameFromJWT(tok); got != want {
			t.Errorf("extractUsernameFromJWT(...) = %q, want %q", got, want)
		}
	}
}

func TestJFrogEngine_Run_MissingURL(t *testing.T) {
	e := &JFrogEngine{}
	_, err := e.Run(context.Background(), map[string]any{}, newTestIO())
	if err == nil {
		t.Fatal("expected error when url setting is missing")
	}
	if !strings.Contains(err.Error(), "url") {
		t.Errorf("error %q does not mention 'url'", err.Error())
	}
}

func TestJFrogEngine_Run_FullFlow(t *testing.T) {
	// Build JWTs for both the bootstrap (web-login) and minted tokens. The
	// minted token's subject is what we expect to appear in creds["user"].
	mkToken := func(subject string) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		claims, _ := json.Marshal(map[string]string{"sub": subject})
		payload := base64.RawURLEncoding.EncodeToString(claims)
		return header + "." + payload + ".sig"
	}
	// Distinct JWTs (subjects differ by issuer ID prefix) so we can tell
	// them apart; both still decode to username "alice".
	bootstrapAccess := mkToken("jfrt@bootstrap/users/alice")
	mintedAccess := mkToken("jfrt@minted/users/alice")

	var gotSession, gotBearer string
	var gotMintBody struct {
		ExpiresIn   int64  `json:"expires_in"`
		Refreshable bool   `json:"refreshable"`
		Scope       string `json:"scope"`
	}
	var requestHits, tokenHits, mintHits int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/access/api/v2/authentication/jfrog_client_login/request":
			requestHits++
			var body struct {
				Session string `json:"session"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			gotSession = body.Session
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/access/api/v2/authentication/jfrog_client_login/token/"):
			tokenHits++
			// First call: "not yet". Subsequent calls: return the bootstrap token.
			if tokenHits < 2 {
				http.Error(w, "pending", http.StatusBadRequest)
				return
			}
			exp := uint(3600)
			_ = json.NewEncoder(w).Encode(jfrogCommonTokenParams{
				AccessToken:  bootstrapAccess,
				RefreshToken: "bootstrap-refresh-should-be-ignored",
				TokenType:    "Bearer",
				ExpiresIn:    &exp,
				Scope:        "applied-permissions/user",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/access/api/v2/tokens":
			mintHits++
			gotBearer = r.Header.Get("Authorization")
			if err := json.NewDecoder(r.Body).Decode(&gotMintBody); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(jfrogCommonTokenParams{
				AccessToken:  mintedAccess,
				RefreshToken: "dotvault-refresh-1",
				TokenType:    "Bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var browsed string
	io := newTestIO()
	io.Browser = func(u string) error {
		browsed = u
		return nil
	}

	fixedNow := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	e := &JFrogEngine{
		httpClient:   srv.Client(),
		pollInterval: 5 * time.Millisecond,
		maxWait:      2 * time.Second,
		now:          func() time.Time { return fixedNow },
	}
	creds, err := e.Run(context.Background(), map[string]any{
		"url":       srv.URL,
		"token_ttl": "6h",
	}, io)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if creds["access_token"] != mintedAccess {
		t.Errorf("access_token = %q, want minted token %q", creds["access_token"], mintedAccess)
	}
	if creds["access_token"] == bootstrapAccess {
		t.Error("access_token is the bootstrap token — should have been replaced by the minted token")
	}
	if creds["refresh_token"] != "dotvault-refresh-1" {
		t.Errorf("refresh_token = %q, want %q", creds["refresh_token"], "dotvault-refresh-1")
	}
	if creds["user"] != "alice" {
		t.Errorf("user = %q, want %q", creds["user"], "alice")
	}
	if creds["url"] != srv.URL {
		t.Errorf("url = %q, want %q", creds["url"], srv.URL)
	}
	if creds["server_id"] == "" {
		t.Error("server_id is empty")
	}
	if creds["issued_at"] != "2026-04-17T12:00:00Z" {
		t.Errorf("issued_at = %q, want 2026-04-17T12:00:00Z", creds["issued_at"])
	}
	if creds["expires_at"] != "2026-04-17T18:00:00Z" {
		t.Errorf("expires_at = %q, want 2026-04-17T18:00:00Z", creds["expires_at"])
	}

	// Dropped fields must not leak into the stored secret.
	for _, k := range []string{"token_type", "expires_in", "scope"} {
		if _, ok := creds[k]; ok {
			t.Errorf("creds should not contain %q in the new schema", k)
		}
	}

	if requestHits != 1 {
		t.Errorf("request endpoint hit %d times, want 1", requestHits)
	}
	if tokenHits < 2 {
		t.Errorf("token endpoint hit %d times, want >= 2", tokenHits)
	}
	if mintHits != 1 {
		t.Errorf("mint endpoint hit %d times, want 1", mintHits)
	}
	if gotBearer != "Bearer "+bootstrapAccess {
		t.Errorf("mint authorization header = %q, want bearer of bootstrap token", gotBearer)
	}
	if gotMintBody.ExpiresIn != int64((6 * time.Hour).Seconds()) {
		t.Errorf("mint expires_in = %d, want %d", gotMintBody.ExpiresIn, int64((6 * time.Hour).Seconds()))
	}
	if !gotMintBody.Refreshable {
		t.Error("mint refreshable = false, want true")
	}
	if gotMintBody.Scope != "applied-permissions/user" {
		t.Errorf("mint scope = %q, want %q", gotMintBody.Scope, "applied-permissions/user")
	}
	if gotSession == "" {
		t.Error("server did not observe a session uuid")
	}
	if !strings.Contains(browsed, "jfClientSession=") {
		t.Errorf("browser URL %q missing jfClientSession", browsed)
	}
	if !strings.Contains(browsed, "jfClientName=JFrog-CLI") {
		t.Errorf("browser URL %q missing default jfClientName", browsed)
	}
	if !strings.Contains(browsed, "jfClientCode=1") {
		t.Errorf("browser URL %q missing default jfClientCode", browsed)
	}
}

func TestJFrogEngine_Run_RequestEndpointFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not implemented", http.StatusNotFound)
	}))
	defer srv.Close()

	e := &JFrogEngine{
		httpClient:   srv.Client(),
		pollInterval: time.Millisecond,
		maxWait:      100 * time.Millisecond,
	}
	_, err := e.Run(context.Background(), map[string]any{"url": srv.URL}, newTestIO())
	if err == nil {
		t.Fatal("expected error when request endpoint returns non-200")
	}
	if !strings.Contains(err.Error(), "initiate jfrog web login") {
		t.Errorf("error %q missing expected prefix", err)
	}
}

func TestJFrogEngine_Run_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "pending", http.StatusBadRequest)
	}))
	defer srv.Close()

	e := &JFrogEngine{
		httpClient:   srv.Client(),
		pollInterval: time.Millisecond,
		maxWait:      20 * time.Millisecond,
	}
	_, err := e.Run(context.Background(), map[string]any{"url": srv.URL}, newTestIO())
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error %q does not mention timeout", err)
	}
}

func TestJFrogEngine_Run_DefaultTTL(t *testing.T) {
	// When token_ttl is omitted, the engine should fall back to the 60d
	// default and pass that value to POST /access/api/v2/tokens.
	bootstrap := "bootstrap.token.sig"
	minted := "minted.token.sig"

	var gotMintBody struct {
		ExpiresIn   int64 `json:"expires_in"`
		Refreshable bool  `json:"refreshable"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/access/api/v2/authentication/jfrog_client_login/request":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/access/api/v2/authentication/jfrog_client_login/token/"):
			_ = json.NewEncoder(w).Encode(jfrogCommonTokenParams{AccessToken: bootstrap})
		case r.Method == http.MethodPost && r.URL.Path == "/access/api/v2/tokens":
			_ = json.NewDecoder(r.Body).Decode(&gotMintBody)
			_ = json.NewEncoder(w).Encode(jfrogCommonTokenParams{AccessToken: minted, RefreshToken: "r1"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := &JFrogEngine{
		httpClient:   srv.Client(),
		pollInterval: time.Millisecond,
		maxWait:      time.Second,
		now:          func() time.Time { return time.Unix(0, 0).UTC() },
	}
	if _, err := e.Run(context.Background(), map[string]any{"url": srv.URL}, newTestIO()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	wantTTLSeconds := int64((60 * 24 * time.Hour).Seconds())
	if gotMintBody.ExpiresIn != wantTTLSeconds {
		t.Errorf("default mint ExpiresIn = %d, want %d (60d)", gotMintBody.ExpiresIn, wantTTLSeconds)
	}
}

func TestJFrogEngine_Refresh_Success(t *testing.T) {
	rotatedAccess := mkTestJWT(t, "jfrt@01g.../users/alice")
	var gotForm url.Values
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/access/api/v1/tokens" {
			hits++
			_ = r.ParseForm()
			gotForm = r.PostForm
			_ = json.NewEncoder(w).Encode(jfrogCommonTokenParams{
				AccessToken:  rotatedAccess,
				RefreshToken: "new-refresh",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	fixedNow := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	e := &JFrogEngine{httpClient: srv.Client(), now: func() time.Time { return fixedNow }}
	existing := map[string]string{
		"access_token":  "old-access",
		"refresh_token": "old-refresh",
		"user":          "alice",
	}
	got, err := e.Refresh(context.Background(), map[string]any{
		"url":       srv.URL,
		"token_ttl": "6h",
	}, existing)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	if got["access_token"] != rotatedAccess {
		t.Errorf("access_token = %q, want rotated", got["access_token"])
	}
	if got["refresh_token"] != "new-refresh" {
		t.Errorf("refresh_token = %q, want %q", got["refresh_token"], "new-refresh")
	}
	if got["user"] != "alice" {
		t.Errorf("user = %q, want alice", got["user"])
	}
	if got["issued_at"] != "2026-04-17T12:00:00Z" {
		t.Errorf("issued_at = %q, want 2026-04-17T12:00:00Z", got["issued_at"])
	}
	if got["expires_at"] != "2026-04-17T18:00:00Z" {
		t.Errorf("expires_at = %q, want 2026-04-17T18:00:00Z", got["expires_at"])
	}
	if hits != 1 {
		t.Errorf("refresh endpoint hit %d times, want 1", hits)
	}
	if gotForm.Get("grant_type") != "refresh_token" {
		t.Errorf("form grant_type = %q, want refresh_token", gotForm.Get("grant_type"))
	}
	if gotForm.Get("access_token") != "old-access" {
		t.Errorf("form access_token = %q, want old-access", gotForm.Get("access_token"))
	}
	if gotForm.Get("refresh_token") != "old-refresh" {
		t.Errorf("form refresh_token = %q, want old-refresh", gotForm.Get("refresh_token"))
	}
}

func TestJFrogEngine_Refresh_NonJWTKeepsUser(t *testing.T) {
	// If the rotated token is a reference token (non-JWT), Refresh should
	// preserve the existing user rather than wiping it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jfrogCommonTokenParams{
			AccessToken:  "cmVmZXJlbmNl-not-a-jwt",
			RefreshToken: "new-refresh",
		})
	}))
	defer srv.Close()

	e := &JFrogEngine{httpClient: srv.Client(), now: func() time.Time { return time.Unix(0, 0).UTC() }}
	got, err := e.Refresh(context.Background(), map[string]any{
		"url":       srv.URL,
		"token_ttl": "1h",
	}, map[string]string{
		"access_token":  "old",
		"refresh_token": "old-refresh",
		"user":          "alice",
	})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got["user"] != "alice" {
		t.Errorf("user = %q, want alice (preserved from existing)", got["user"])
	}
}

func TestJFrogEngine_Refresh_Revoked(t *testing.T) {
	cases := []int{http.StatusUnauthorized, http.StatusForbidden}
	for _, status := range cases {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "revoked", status)
			}))
			defer srv.Close()

			e := &JFrogEngine{httpClient: srv.Client(), now: func() time.Time { return time.Unix(0, 0).UTC() }}
			_, err := e.Refresh(context.Background(), map[string]any{
				"url":       srv.URL,
				"token_ttl": "1h",
			}, map[string]string{
				"access_token":  "a",
				"refresh_token": "r",
			})
			if err == nil {
				t.Fatalf("expected error for status %d", status)
			}
			if !errors.Is(err, ErrRevoked) {
				t.Errorf("status %d error = %v, want errors.Is(ErrRevoked) == true", status, err)
			}
		})
	}
}

func TestJFrogEngine_Refresh_Transient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "kaboom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	e := &JFrogEngine{httpClient: srv.Client(), now: func() time.Time { return time.Unix(0, 0).UTC() }}
	_, err := e.Refresh(context.Background(), map[string]any{
		"url":       srv.URL,
		"token_ttl": "1h",
	}, map[string]string{
		"access_token":  "a",
		"refresh_token": "r",
	})
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if errors.Is(err, ErrRevoked) {
		t.Errorf("500 should be transient, got ErrRevoked: %v", err)
	}
}

func TestJFrogEngine_Refresh_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	e := &JFrogEngine{httpClient: srv.Client(), now: func() time.Time { return time.Unix(0, 0).UTC() }}
	_, err := e.Refresh(context.Background(), map[string]any{
		"url":       srv.URL,
		"token_ttl": "1h",
	}, map[string]string{
		"access_token":  "a",
		"refresh_token": "r",
	})
	if err == nil {
		t.Fatal("expected error for malformed JSON response")
	}
	if errors.Is(err, ErrRevoked) {
		t.Errorf("decode failure should not be ErrRevoked: %v", err)
	}
}

func TestJFrogEngine_Refresh_MissingExisting(t *testing.T) {
	e := &JFrogEngine{}
	_, err := e.Refresh(context.Background(), map[string]any{"url": "https://example.com"}, map[string]string{
		"access_token": "a",
		// refresh_token missing
	})
	if err == nil {
		t.Fatal("expected error when existing secret has no refresh_token")
	}
}

func mkTestJWT(t *testing.T, subject string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	claims, _ := json.Marshal(map[string]string{"sub": subject})
	payload := base64.RawURLEncoding.EncodeToString(claims)
	return header + "." + payload + ".sig"
}

// newTestIO builds an IO suitable for unit tests: writes go to /dev/null,
// logs go to a buffer, the browser opener is a no-op.
func newTestIO() IO {
	return IO{
		Out:      &bytes.Buffer{},
		Log:      slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		Username: "testuser",
		Browser:  func(string) error { return nil },
	}
}

