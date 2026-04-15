package enrol

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	want := []string{"access_token", "url", "server_id"}
	if len(got) != len(want) {
		t.Fatalf("Fields() len = %d, want %d", len(got), len(want))
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
	// Build a JWT whose subject decodes to "alice".
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	claims, _ := json.Marshal(map[string]string{"sub": "jfrt@01g.../users/alice"})
	payload := base64.RawURLEncoding.EncodeToString(claims)
	accessToken := header + "." + payload + ".sig"

	var gotSession string
	var requestHits, tokenHits int

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
			// First call: "not yet". Subsequent calls: return the token.
			if tokenHits < 2 {
				http.Error(w, "pending", http.StatusBadRequest)
				return
			}
			exp := uint(3600)
			_ = json.NewEncoder(w).Encode(jfrogCommonTokenParams{
				AccessToken:  accessToken,
				RefreshToken: "refresh-xyz",
				TokenType:    "Bearer",
				ExpiresIn:    &exp,
				Scope:        "applied-permissions/user",
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

	e := &JFrogEngine{
		httpClient:   srv.Client(),
		pollInterval: 5 * time.Millisecond,
		maxWait:      2 * time.Second,
	}
	creds, err := e.Run(context.Background(), map[string]any{"url": srv.URL}, io)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if creds["access_token"] != accessToken {
		t.Errorf("access_token = %q, want %q", creds["access_token"], accessToken)
	}
	if creds["refresh_token"] != "refresh-xyz" {
		t.Errorf("refresh_token = %q, want %q", creds["refresh_token"], "refresh-xyz")
	}
	if creds["user"] != "alice" {
		t.Errorf("user = %q, want %q", creds["user"], "alice")
	}
	if creds["token_type"] != "Bearer" {
		t.Errorf("token_type = %q, want %q", creds["token_type"], "Bearer")
	}
	if creds["expires_in"] != "3600" {
		t.Errorf("expires_in = %q, want %q", creds["expires_in"], "3600")
	}
	if creds["scope"] != "applied-permissions/user" {
		t.Errorf("scope = %q, want %q", creds["scope"], "applied-permissions/user")
	}
	if creds["url"] != srv.URL {
		t.Errorf("url = %q, want %q", creds["url"], srv.URL)
	}
	if creds["server_id"] == "" {
		t.Error("server_id is empty")
	}

	if requestHits != 1 {
		t.Errorf("request endpoint hit %d times, want 1", requestHits)
	}
	if tokenHits < 2 {
		t.Errorf("token endpoint hit %d times, want >= 2", tokenHits)
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

