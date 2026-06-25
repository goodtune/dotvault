package enrol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGHPEngine_Name(t *testing.T) {
	e := &GHPEngine{}
	if got := e.Name(); got != "ghp" {
		t.Errorf("Name() = %q, want %q", got, "ghp")
	}
}

func TestGHPEngine_Fields(t *testing.T) {
	e := &GHPEngine{}
	got := e.Fields()
	want := []string{"user_token", "server_url"}
	if len(got) != len(want) {
		t.Fatalf("Fields() = %v, want %v", got, want)
	}
	for i, f := range got {
		if f != want[i] {
			t.Errorf("Fields()[%d] = %q, want %q", i, f, want[i])
		}
	}
}

func TestGHPEngine_Registered(t *testing.T) {
	e, ok := GetEngine("ghp")
	if !ok {
		t.Fatal("ghp engine not registered")
	}
	if _, ok := e.(*GHPEngine); !ok {
		t.Errorf("registered engine is %T, want *GHPEngine", e)
	}
}

// GHPEngine must not be registered as a Refresher: the ghp session token
// has no unattended refresh path (recovery is re-enrolment).
func TestGHPEngine_NotRefresher(t *testing.T) {
	var e Engine = &GHPEngine{}
	if _, ok := e.(Refresher); ok {
		t.Error("GHPEngine should not implement Refresher")
	}
}

func TestGHPEngine_Run_MissingURL(t *testing.T) {
	e := &GHPEngine{}
	_, err := e.Run(context.Background(), map[string]any{}, newTestIO())
	if err == nil {
		t.Fatal("expected error when url setting is missing")
	}
	if !strings.Contains(err.Error(), "url") {
		t.Errorf("error %q does not mention 'url'", err.Error())
	}
}

func TestGHPEngine_Run_FullFlow(t *testing.T) {
	const userCode = "ABCD-EFGH"
	const sessionToken = "ghpr_deadbeefdeadbeef"

	var startHits, tokenHits int
	var gotDeviceCode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/cli/auth/device":
			startHits++
			_ = json.NewEncoder(w).Encode(ghpDeviceStart{
				DeviceCode:              "device-code-123",
				UserCode:                userCode,
				VerificationURI:         "/cli/auth",
				VerificationURIComplete: "/cli/auth?user_code=" + userCode,
				ExpiresIn:               600,
				Interval:                2,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/cli/auth/device/token":
			tokenHits++
			var body struct {
				DeviceCode string `json:"device_code"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotDeviceCode = body.DeviceCode
			// First poll: pending. Second poll: approved.
			if tokenHits < 2 {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(ghpTokenResponse{Error: "authorization_pending"})
				return
			}
			_ = json.NewEncoder(w).Encode(ghpTokenResponse{
				SessionToken: sessionToken,
				Username:     "octocat",
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

	e := &GHPEngine{
		httpClient:   srv.Client(),
		pollInterval: 5 * time.Millisecond,
		maxWait:      2 * time.Second,
	}
	creds, err := e.Run(context.Background(), map[string]any{"url": srv.URL}, io)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if creds["user_token"] != sessionToken {
		t.Errorf("user_token = %q, want %q", creds["user_token"], sessionToken)
	}
	if creds["server_url"] != srv.URL {
		t.Errorf("server_url = %q, want %q", creds["server_url"], srv.URL)
	}
	if creds["user"] != "octocat" {
		t.Errorf("user = %q, want %q", creds["user"], "octocat")
	}
	if gotDeviceCode != "device-code-123" {
		t.Errorf("token poll sent device_code %q, want %q", gotDeviceCode, "device-code-123")
	}
	if startHits != 1 {
		t.Errorf("device endpoint hit %d times, want 1", startHits)
	}
	if tokenHits < 2 {
		t.Errorf("token endpoint hit %d times, want >= 2", tokenHits)
	}
	if !strings.Contains(browsed, "/cli/auth?user_code="+userCode) {
		t.Errorf("browser URL %q missing verification path with user_code", browsed)
	}
}

func TestGHPEngine_Run_SlowDown(t *testing.T) {
	const sessionToken = "ghpr_token"
	var tokenHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cli/auth/device":
			_ = json.NewEncoder(w).Encode(ghpDeviceStart{
				DeviceCode: "dc", UserCode: "U-C", VerificationURI: "/cli/auth", Interval: 2,
			})
		case "/cli/auth/device/token":
			tokenHits++
			if tokenHits == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(ghpTokenResponse{Error: "slow_down"})
				return
			}
			_ = json.NewEncoder(w).Encode(ghpTokenResponse{SessionToken: sessionToken})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := &GHPEngine{
		httpClient:   srv.Client(),
		pollInterval: time.Millisecond,
		slowDownBump: time.Millisecond, // keep the test fast despite slow_down
		maxWait:      2 * time.Second,
	}
	creds, err := e.Run(context.Background(), map[string]any{"url": srv.URL}, newTestIO())
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if creds["user_token"] != sessionToken {
		t.Errorf("user_token = %q, want %q", creds["user_token"], sessionToken)
	}
	if tokenHits < 2 {
		t.Errorf("token endpoint hit %d times, want >= 2 (slow_down then success)", tokenHits)
	}
}

func TestGHPEngine_Run_AccessDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cli/auth/device":
			_ = json.NewEncoder(w).Encode(ghpDeviceStart{DeviceCode: "dc", UserCode: "U-C", VerificationURI: "/cli/auth"})
		case "/cli/auth/device/token":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(ghpTokenResponse{Error: "access_denied"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := &GHPEngine{httpClient: srv.Client(), pollInterval: time.Millisecond, maxWait: time.Second}
	_, err := e.Run(context.Background(), map[string]any{"url": srv.URL}, newTestIO())
	if err == nil {
		t.Fatal("expected error when authorization is denied")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("error %q does not mention denial", err)
	}
}

func TestGHPEngine_Run_InvalidTokenPrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cli/auth/device":
			_ = json.NewEncoder(w).Encode(ghpDeviceStart{DeviceCode: "dc", UserCode: "U-C", VerificationURI: "/cli/auth"})
		case "/cli/auth/device/token":
			// A token without the ghpr_ prefix must be rejected.
			_ = json.NewEncoder(w).Encode(ghpTokenResponse{SessionToken: "ghx_wrong_family"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := &GHPEngine{httpClient: srv.Client(), pollInterval: time.Millisecond, maxWait: time.Second}
	_, err := e.Run(context.Background(), map[string]any{"url": srv.URL}, newTestIO())
	if err == nil {
		t.Fatal("expected error for a session token without the ghpr_ prefix")
	}
	if !strings.Contains(err.Error(), "invalid session token") {
		t.Errorf("error %q does not mention invalid session token", err)
	}
}

func TestGHPEngine_Run_DeviceEndpointFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	e := &GHPEngine{httpClient: srv.Client(), pollInterval: time.Millisecond, maxWait: 100 * time.Millisecond}
	_, err := e.Run(context.Background(), map[string]any{"url": srv.URL}, newTestIO())
	if err == nil {
		t.Fatal("expected error when device endpoint returns non-200")
	}
	if !strings.Contains(err.Error(), "start ghp device authorization") {
		t.Errorf("error %q missing expected prefix", err)
	}
}

func TestGHPEngine_Run_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cli/auth/device":
			_ = json.NewEncoder(w).Encode(ghpDeviceStart{DeviceCode: "dc", UserCode: "U-C", VerificationURI: "/cli/auth"})
		case "/cli/auth/device/token":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(ghpTokenResponse{Error: "authorization_pending"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := &GHPEngine{httpClient: srv.Client(), pollInterval: time.Millisecond, maxWait: 20 * time.Millisecond}
	_, err := e.Run(context.Background(), map[string]any{"url": srv.URL}, newTestIO())
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error %q does not mention timeout", err)
	}
}

func TestGHPEngine_Run_ExpiredToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cli/auth/device":
			_ = json.NewEncoder(w).Encode(ghpDeviceStart{DeviceCode: "dc", UserCode: "U-C", VerificationURI: "/cli/auth"})
		case "/cli/auth/device/token":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(ghpTokenResponse{Error: "expired_token"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := &GHPEngine{httpClient: srv.Client(), pollInterval: time.Millisecond, maxWait: time.Second}
	_, err := e.Run(context.Background(), map[string]any{"url": srv.URL}, newTestIO())
	if err == nil {
		t.Fatal("expected error when the device code expires")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error %q does not mention expiry", err)
	}
}

func TestGHPEngine_Run_UnknownError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cli/auth/device":
			_ = json.NewEncoder(w).Encode(ghpDeviceStart{DeviceCode: "dc", UserCode: "U-C", VerificationURI: "/cli/auth"})
		case "/cli/auth/device/token":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(ghpTokenResponse{Error: "invalid_grant", ErrorDescription: "device code not recognised"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := &GHPEngine{httpClient: srv.Client(), pollInterval: time.Millisecond, maxWait: time.Second}
	_, err := e.Run(context.Background(), map[string]any{"url": srv.URL}, newTestIO())
	if err == nil {
		t.Fatal("expected error for an unrecognised RFC 8628 error code")
	}
	if !strings.Contains(err.Error(), "invalid_grant") || !strings.Contains(err.Error(), "device code not recognised") {
		t.Errorf("error %q should carry the error code and description", err)
	}
}

func TestGHPEngine_Run_EmptyResponse(t *testing.T) {
	// A 200 with neither a session token nor an error code is malformed and
	// must be a hard error rather than an infinite poll.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cli/auth/device":
			_ = json.NewEncoder(w).Encode(ghpDeviceStart{DeviceCode: "dc", UserCode: "U-C", VerificationURI: "/cli/auth"})
		case "/cli/auth/device/token":
			_ = json.NewEncoder(w).Encode(ghpTokenResponse{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := &GHPEngine{httpClient: srv.Client(), pollInterval: time.Millisecond, maxWait: time.Second}
	_, err := e.Run(context.Background(), map[string]any{"url": srv.URL}, newTestIO())
	if err == nil {
		t.Fatal("expected error for a response with no token and no error code")
	}
	if !strings.Contains(err.Error(), "no token or error code") {
		t.Errorf("error %q missing expected message", err)
	}
}

func TestGHPEngine_Run_RateLimited(t *testing.T) {
	// HTTP 429 without Retry-After must back off (not error) and keep polling.
	const sessionToken = "ghpr_token"
	var tokenHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cli/auth/device":
			_ = json.NewEncoder(w).Encode(ghpDeviceStart{DeviceCode: "dc", UserCode: "U-C", VerificationURI: "/cli/auth"})
		case "/cli/auth/device/token":
			tokenHits++
			if tokenHits == 1 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			_ = json.NewEncoder(w).Encode(ghpTokenResponse{SessionToken: sessionToken})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// pollInterval=1ms so the post-429 exponential backoff (2ms) stays fast.
	e := &GHPEngine{httpClient: srv.Client(), pollInterval: time.Millisecond, maxWait: 2 * time.Second}
	creds, err := e.Run(context.Background(), map[string]any{"url": srv.URL}, newTestIO())
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if creds["user_token"] != sessionToken {
		t.Errorf("user_token = %q, want %q", creds["user_token"], sessionToken)
	}
	if tokenHits < 2 {
		t.Errorf("token endpoint hit %d times, want >= 2 (429 then success)", tokenHits)
	}
}

func TestGHPRetryAfterSeconds(t *testing.T) {
	mk := func(v string) *http.Response {
		h := http.Header{}
		if v != "" {
			h.Set("Retry-After", v)
		}
		return &http.Response{Header: h}
	}
	cases := map[string]int{
		"5":     5,
		"  10 ": 10,
		"":      0,
		"-3":    0,
		"soon":  0, // HTTP-date form is intentionally ignored
	}
	for in, want := range cases {
		if got := ghpRetryAfterSeconds(mk(in)); got != want {
			t.Errorf("ghpRetryAfterSeconds(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestNormalizeGHPServerURL(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"ghp.example.com", "https://ghp.example.com", false},
		{"https://ghp.example.com", "https://ghp.example.com", false},
		{"https://ghp.example.com/", "https://ghp.example.com", false},
		{"HTTPS://ghp.example.com", "https://ghp.example.com", false},
		// http is allowed only to loopback (local dev / tests).
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080", false},
		{"http://localhost:8080", "http://localhost:8080", false},
		{"http://[::1]:8080", "http://[::1]:8080", false},

		// http to a non-loopback host is refused — it would expose the token.
		{"http://ghp.example.com", "", true},
		{"http://10.0.0.5:8080", "", true},

		{"https://ghp.example.com/path", "", true},
		{"https://ghp.example.com?x=1", "", true},
		{"https://ghp.example.com#frag", "", true},
		{"", "", true},
		{"   ", "", true},
		{"ftp://ghp.example.com", "", true},
	}
	for _, tc := range cases {
		got, err := normalizeGHPServerURL(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("normalizeGHPServerURL(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeGHPServerURL(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("normalizeGHPServerURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestResolveGHPVerificationURL(t *testing.T) {
	cases := []struct {
		name     string
		base     string
		complete string
		plain    string
		want     string
		wantErr  bool
	}{
		{"complete path preferred", "https://ghp.example.com", "/cli/auth?user_code=A-B", "/cli/auth", "https://ghp.example.com/cli/auth?user_code=A-B", false},
		{"falls back to plain", "https://ghp.example.com", "", "/cli/auth", "https://ghp.example.com/cli/auth", false},
		{"absolute honoured verbatim", "https://ghp.example.com", "https://other.example/cli/auth?user_code=A-B", "", "https://other.example/cli/auth?user_code=A-B", false},
		{"missing both is an error", "https://ghp.example.com", "", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveGHPVerificationURL(tc.base, tc.complete, tc.plain)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveGHPVerificationURL(...) = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveGHPVerificationURL(...) unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("resolveGHPVerificationURL(...) = %q, want %q", got, tc.want)
			}
		})
	}
}
