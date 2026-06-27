package enrol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLangSmithEngine_Name(t *testing.T) {
	e := &LangSmithEngine{}
	if got := e.Name(); got != "LangSmith" {
		t.Errorf("Name() = %q, want %q", got, "LangSmith")
	}
}

func TestLangSmithEngine_Fields(t *testing.T) {
	e := &LangSmithEngine{}
	got := e.Fields()
	want := []string{"access_token", "refresh_token", "api_url", "issued_at", "expires_at"}
	if len(got) != len(want) {
		t.Fatalf("Fields() = %v, want %v", got, want)
	}
	for i, f := range got {
		if f != want[i] {
			t.Errorf("Fields()[%d] = %q, want %q", i, f, want[i])
		}
	}
}

func TestLangSmithEngine_Registered(t *testing.T) {
	e, ok := GetEngine("langsmith")
	if !ok {
		t.Fatal("langsmith engine not registered")
	}
	if _, ok := e.(*LangSmithEngine); !ok {
		t.Errorf("registered engine is %T, want *LangSmithEngine", e)
	}
	if _, ok := e.(Refresher); !ok {
		t.Error("langsmith engine does not implement Refresher")
	}
}

func TestLangSmithResource(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"api.smith.langchain.com", "https://api.smith.langchain.com", false},
		{"https://api.smith.langchain.com", "https://api.smith.langchain.com", false},
		{"https://api.smith.langchain.com/", "https://api.smith.langchain.com", false},
		{"https://api.smith.langchain.com/api/v1", "https://api.smith.langchain.com", false},
		{"https://api.smith.langchain.com/api/v1/", "https://api.smith.langchain.com", false},
		{"HTTPS://api.smith.langchain.com", "https://api.smith.langchain.com", false},
		{"https://eu.api.smith.langchain.com/api/v1", "https://eu.api.smith.langchain.com", false},
		// Rejected: explicit http (cleartext bearer), query, fragment, empty,
		// non-http schemes.
		{"http://api.smith.langchain.com", "", true},
		{"http://127.0.0.1:8080", "", true},
		{"https://api.smith.langchain.com?x=1", "", true},
		{"https://api.smith.langchain.com#f", "", true},
		{"", "", true},
		{"   ", "", true},
		{"ftp://api.smith.langchain.com", "", true},
	}
	for _, tc := range cases {
		got, err := langsmithResource(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("langsmithResource(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("langsmithResource(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("langsmithResource(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLangSmithAPIURLFromSettings(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
		wantErr  string // substring; "" means expect success
		want     string
	}{
		{"unset defaults to saas", map[string]any{}, "", "https://api.smith.langchain.com"},
		{"empty defaults to saas", map[string]any{"api_url": "  "}, "", "https://api.smith.langchain.com"},
		{"custom", map[string]any{"api_url": "https://langsmith.internal.example/api/v1"}, "", "https://langsmith.internal.example"},
		{"wrong type", map[string]any{"api_url": 8080}, "must be a string", ""},
		{"http rejected", map[string]any{"api_url": "http://api.smith.langchain.com"}, "must use https", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := langsmithAPIURLFromSettings(tc.settings)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tc.want {
					t.Errorf("api_url = %q, want %q", got, tc.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestLangSmithClientID(t *testing.T) {
	if got := langsmithClientID(map[string]any{}); got != "langsmith-cli" {
		t.Errorf("default client_id = %q, want langsmith-cli", got)
	}
	if got := langsmithClientID(map[string]any{"client_id": "custom-app"}); got != "custom-app" {
		t.Errorf("custom client_id = %q, want custom-app", got)
	}
	if got := langsmithClientID(map[string]any{"client_id": ""}); got != "langsmith-cli" {
		t.Errorf("empty client_id = %q, want langsmith-cli fallback", got)
	}
}

func TestLangSmithWorkspaceID(t *testing.T) {
	if got, err := langsmithWorkspaceID(map[string]any{}); err != nil || got != "" {
		t.Errorf("unset workspace_id = %q, %v; want \"\", nil", got, err)
	}
	if got, err := langsmithWorkspaceID(map[string]any{"workspace_id": "  ws-1  "}); err != nil || got != "ws-1" {
		t.Errorf("workspace_id = %q, %v; want ws-1, nil", got, err)
	}
	if _, err := langsmithWorkspaceID(map[string]any{"workspace_id": 5}); err == nil {
		t.Error("expected error for non-string workspace_id")
	}
}

func TestLangSmithTokenLifetime(t *testing.T) {
	if got := langsmithTokenLifetime(langsmithTokenResp{ExpiresIn: 3600}); got != time.Hour {
		t.Errorf("lifetime(3600) = %v, want 1h", got)
	}
	if got := langsmithTokenLifetime(langsmithTokenResp{ExpiresIn: 0}); got != time.Hour {
		t.Errorf("lifetime(0) = %v, want 1h default", got)
	}
}

// langsmithTestServer stands up a TLS httptest server serving the device-code
// and token endpoints. A TLS server is used because the engine requires an
// https api_url; srv.Client() trusts the cert. The tokenHandler lets each test
// drive the poll response sequence.
func langsmithTestServer(t *testing.T, deviceHandler, tokenHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	if deviceHandler != nil {
		mux.HandleFunc("/oauth/device/code", deviceHandler)
	}
	mux.HandleFunc("/oauth/token", tokenHandler)
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestLangSmithEngine_Run_FullFlow(t *testing.T) {
	var deviceForm url.Values
	device := func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		deviceForm = r.Form
		_ = json.NewEncoder(w).Encode(langsmithDeviceResp{
			DeviceCode:      "dev-code-1",
			UserCode:        "WXYZ-1234",
			VerificationURI: "https://smith.langchain.com/device",
			ExpiresIn:       900,
			Interval:        0,
		})
	}

	var tokenCalls int32
	var lastTokenForm url.Values
	token := func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		lastTokenForm = r.Form
		// First poll: authorization_pending. Second: success. This exercises
		// the device-flow poll loop.
		if atomic.AddInt32(&tokenCalls, 1) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(langsmithTokenResp{Error: "authorization_pending"})
			return
		}
		_ = json.NewEncoder(w).Encode(langsmithTokenResp{
			AccessToken:  "access-1",
			RefreshToken: "refresh-1",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
	}
	srv := langsmithTestServer(t, device, token)

	io := newTestIO()
	var browsedURL string
	io.In = strings.NewReader("\n")
	io.Browser = func(u string) error {
		browsedURL = u
		return nil
	}

	fixedNow := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	e := &LangSmithEngine{
		httpClient:   srv.Client(),
		now:          func() time.Time { return fixedNow },
		minInterval:  time.Millisecond,
		loginTimeout: 5 * time.Second,
	}
	creds, err := e.Run(context.Background(), map[string]any{"api_url": srv.URL, "workspace_id": "ws-42"}, io)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if creds["access_token"] != "access-1" {
		t.Errorf("access_token = %q", creds["access_token"])
	}
	if creds["refresh_token"] != "refresh-1" {
		t.Errorf("refresh_token = %q", creds["refresh_token"])
	}
	if creds["api_url"] != srv.URL {
		t.Errorf("api_url = %q, want %q", creds["api_url"], srv.URL)
	}
	if creds["workspace_id"] != "ws-42" {
		t.Errorf("workspace_id = %q, want ws-42", creds["workspace_id"])
	}
	if creds["issued_at"] != fixedNow.Format(time.RFC3339) {
		t.Errorf("issued_at = %q", creds["issued_at"])
	}
	if creds["expires_at"] != fixedNow.Add(time.Hour).Format(time.RFC3339) {
		t.Errorf("expires_at = %q", creds["expires_at"])
	}

	// The device-code request carried the client_id + resource.
	if deviceForm.Get("client_id") != "langsmith-cli" {
		t.Errorf("device client_id = %q", deviceForm.Get("client_id"))
	}
	if deviceForm.Get("resource") != srv.URL {
		t.Errorf("device resource = %q, want %q", deviceForm.Get("resource"), srv.URL)
	}

	// The token poll used the device-code grant.
	if lastTokenForm.Get("grant_type") != langsmithDeviceGrant {
		t.Errorf("token grant_type = %q", lastTokenForm.Get("grant_type"))
	}
	if lastTokenForm.Get("device_code") != "dev-code-1" {
		t.Errorf("device_code = %q", lastTokenForm.Get("device_code"))
	}
	if atomic.LoadInt32(&tokenCalls) < 2 {
		t.Errorf("expected at least 2 token polls (pending then success), got %d", tokenCalls)
	}

	// The browser was opened to the verification URI.
	if browsedURL != "https://smith.langchain.com/device" {
		t.Errorf("browsed URL = %q", browsedURL)
	}
}

func TestLangSmithEngine_Run_VerificationURIComplete(t *testing.T) {
	device := func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(langsmithDeviceResp{
			DeviceCode:              "dev-code-2",
			UserCode:                "ABCD-9999",
			VerificationURI:         "https://smith.langchain.com/device",
			VerificationURIComplete: "https://smith.langchain.com/device?code=ABCD-9999",
			ExpiresIn:               900,
			Interval:                0,
		})
	}
	token := func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(langsmithTokenResp{
			AccessToken:  "access-2",
			RefreshToken: "refresh-2",
			ExpiresIn:    3600,
		})
	}
	srv := langsmithTestServer(t, device, token)

	io := newTestIO()
	var browsedURL string
	io.In = strings.NewReader("\n")
	io.Browser = func(u string) error { browsedURL = u; return nil }

	e := &LangSmithEngine{httpClient: srv.Client(), minInterval: time.Millisecond, loginTimeout: 5 * time.Second}
	if _, err := e.Run(context.Background(), map[string]any{"api_url": srv.URL}, io); err != nil {
		t.Fatalf("Run error: %v", err)
	}
	// When the server returns verification_uri_complete, that pre-filled URL is
	// what the browser opens.
	if browsedURL != "https://smith.langchain.com/device?code=ABCD-9999" {
		t.Errorf("browsed URL = %q, want the complete URI", browsedURL)
	}
}

func TestLangSmithEngine_Run_WebModeNoBrowser(t *testing.T) {
	device := func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(langsmithDeviceResp{
			DeviceCode: "dev-3", UserCode: "CODE-3", VerificationURI: "https://smith.langchain.com/device",
			ExpiresIn: 900, Interval: 0,
		})
	}
	token := func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(langsmithTokenResp{AccessToken: "a3", RefreshToken: "r3", ExpiresIn: 3600})
	}
	srv := langsmithTestServer(t, device, token)

	out := &strings.Builder{}
	io := newTestIO()
	io.Out = out
	io.Browser = nil // web mode: the daemon must not open a browser

	e := &LangSmithEngine{httpClient: srv.Client(), minInterval: time.Millisecond, loginTimeout: 5 * time.Second}
	if _, err := e.Run(context.Background(), map[string]any{"api_url": srv.URL}, io); err != nil {
		t.Fatalf("Run error: %v", err)
	}
	got := out.String()
	// The web enrolment card keys off these two output shapes.
	if !strings.Contains(got, "! First, copy your one-time code: CODE-3") {
		t.Errorf("output missing device-code line:\n%s", got)
	}
	if !strings.Contains(got, "https://smith.langchain.com/device") {
		t.Errorf("output missing verification URL:\n%s", got)
	}
}

func TestLangSmithEngine_Run_IncompleteToken(t *testing.T) {
	device := func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(langsmithDeviceResp{
			DeviceCode: "dev-4", UserCode: "CODE-4", VerificationURI: "https://smith.langchain.com/device",
			ExpiresIn: 900, Interval: 0,
		})
	}
	token := func(w http.ResponseWriter, r *http.Request) {
		// Access token but no refresh token — dotvault needs the refresh token.
		_ = json.NewEncoder(w).Encode(langsmithTokenResp{AccessToken: "a4", ExpiresIn: 3600})
	}
	srv := langsmithTestServer(t, device, token)

	io := newTestIO()
	io.In = strings.NewReader("\n")
	e := &LangSmithEngine{httpClient: srv.Client(), minInterval: time.Millisecond, loginTimeout: 5 * time.Second}
	_, err := e.Run(context.Background(), map[string]any{"api_url": srv.URL}, io)
	if err == nil || !strings.Contains(err.Error(), "refresh token") {
		t.Errorf("error = %v, want a missing-refresh-token error", err)
	}
}

func TestLangSmithEngine_Run_AccessDenied(t *testing.T) {
	device := func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(langsmithDeviceResp{
			DeviceCode: "dev-5", UserCode: "CODE-5", VerificationURI: "https://smith.langchain.com/device",
			ExpiresIn: 900, Interval: 0,
		})
	}
	token := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(langsmithTokenResp{Error: "access_denied"})
	}
	srv := langsmithTestServer(t, device, token)

	io := newTestIO()
	io.In = strings.NewReader("\n")
	e := &LangSmithEngine{httpClient: srv.Client(), minInterval: time.Millisecond, loginTimeout: 5 * time.Second}
	_, err := e.Run(context.Background(), map[string]any{"api_url": srv.URL}, io)
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("error = %v, want a denied error", err)
	}
}

func TestLangSmithEngine_Run_ExpiredToken(t *testing.T) {
	device := func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(langsmithDeviceResp{
			DeviceCode: "dev-6", UserCode: "CODE-6", VerificationURI: "https://smith.langchain.com/device",
			ExpiresIn: 900, Interval: 0,
		})
	}
	token := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(langsmithTokenResp{Error: "expired_token"})
	}
	srv := langsmithTestServer(t, device, token)

	io := newTestIO()
	io.In = strings.NewReader("\n")
	e := &LangSmithEngine{httpClient: srv.Client(), minInterval: time.Millisecond, loginTimeout: 5 * time.Second}
	_, err := e.Run(context.Background(), map[string]any{"api_url": srv.URL}, io)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("error = %v, want an expired-device-code error", err)
	}
}

func TestLangSmithEngine_Run_SlowDownThenSuccess(t *testing.T) {
	device := func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(langsmithDeviceResp{
			DeviceCode: "dev-7", UserCode: "CODE-7", VerificationURI: "https://smith.langchain.com/device",
			ExpiresIn: 900, Interval: 0,
		})
	}
	var calls int32
	token := func(w http.ResponseWriter, r *http.Request) {
		// First poll: slow_down (exercises the back-off arithmetic). Second:
		// success.
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(langsmithTokenResp{Error: "slow_down"})
			return
		}
		_ = json.NewEncoder(w).Encode(langsmithTokenResp{AccessToken: "a7", RefreshToken: "r7", ExpiresIn: 3600})
	}
	srv := langsmithTestServer(t, device, token)

	io := newTestIO()
	io.In = strings.NewReader("\n")
	// slowDownStep tiny so the slow_down branch's interval bump doesn't add a
	// real 5s wait.
	e := &LangSmithEngine{httpClient: srv.Client(), minInterval: time.Millisecond, slowDownStep: time.Millisecond, loginTimeout: 5 * time.Second}
	creds, err := e.Run(context.Background(), map[string]any{"api_url": srv.URL}, io)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if creds["access_token"] != "a7" {
		t.Errorf("access_token = %q, want a7 (success after slow_down)", creds["access_token"])
	}
	if atomic.LoadInt32(&calls) < 2 {
		t.Errorf("expected at least 2 polls (slow_down then success), got %d", calls)
	}
}

func TestLangSmithEngine_Run_Timeout(t *testing.T) {
	device := func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(langsmithDeviceResp{
			DeviceCode: "dev-8", UserCode: "CODE-8", VerificationURI: "https://smith.langchain.com/device",
			ExpiresIn: 900, Interval: 0,
		})
	}
	token := func(w http.ResponseWriter, r *http.Request) {
		// Never approved — the poll loop must give up at loginTimeout.
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(langsmithTokenResp{Error: "authorization_pending"})
	}
	srv := langsmithTestServer(t, device, token)

	io := newTestIO()
	io.In = strings.NewReader("\n")
	e := &LangSmithEngine{httpClient: srv.Client(), minInterval: time.Millisecond, loginTimeout: 50 * time.Millisecond}
	_, err := e.Run(context.Background(), map[string]any{"api_url": srv.URL}, io)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error = %v, want a timeout error", err)
	}
}

func TestLangSmithEngine_Run_ContextCancelled(t *testing.T) {
	device := func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(langsmithDeviceResp{
			DeviceCode: "dev-9", UserCode: "CODE-9", VerificationURI: "https://smith.langchain.com/device",
			ExpiresIn: 900, Interval: 0,
		})
	}
	token := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(langsmithTokenResp{Error: "authorization_pending"})
	}
	srv := langsmithTestServer(t, device, token)

	io := newTestIO()
	io.In = strings.NewReader("\n")
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel shortly after Run starts polling; the loop must surface ctx.Err(),
	// not the generic timeout.
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	e := &LangSmithEngine{httpClient: srv.Client(), minInterval: time.Millisecond, loginTimeout: 5 * time.Second}
	_, err := e.Run(ctx, map[string]any{"api_url": srv.URL}, io)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}

func TestLangSmithEngine_Refresh(t *testing.T) {
	var gotForm url.Values
	token := func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		_ = json.NewEncoder(w).Encode(langsmithTokenResp{
			AccessToken:  "access-new",
			RefreshToken: "refresh-new",
			ExpiresIn:    3600,
		})
	}
	srv := langsmithTestServer(t, nil, token)

	fixedNow := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	e := &LangSmithEngine{httpClient: srv.Client(), now: func() time.Time { return fixedNow }}
	out, err := e.Refresh(context.Background(), map[string]any{"api_url": srv.URL}, map[string]string{
		"refresh_token": "refresh-old",
		"workspace_id":  "ws-keep",
	})
	if err != nil {
		t.Fatalf("Refresh error: %v", err)
	}
	if out["access_token"] != "access-new" || out["refresh_token"] != "refresh-new" {
		t.Errorf("tokens = %q / %q", out["access_token"], out["refresh_token"])
	}
	if out["api_url"] != srv.URL {
		t.Errorf("api_url = %q, want %q", out["api_url"], srv.URL)
	}
	if out["workspace_id"] != "ws-keep" {
		t.Errorf("workspace_id = %q, want ws-keep (preserved across refresh)", out["workspace_id"])
	}
	if out["expires_at"] != fixedNow.Add(time.Hour).Format(time.RFC3339) {
		t.Errorf("expires_at = %q", out["expires_at"])
	}
	if gotForm.Get("grant_type") != "refresh_token" {
		t.Errorf("grant_type = %q", gotForm.Get("grant_type"))
	}
	if gotForm.Get("refresh_token") != "refresh-old" {
		t.Errorf("refresh_token sent = %q", gotForm.Get("refresh_token"))
	}
}

func TestLangSmithEngine_Refresh_KeepsRefreshTokenWhenNotRotated(t *testing.T) {
	token := func(w http.ResponseWriter, r *http.Request) {
		// No refresh_token in the response — engine keeps the existing one.
		_ = json.NewEncoder(w).Encode(langsmithTokenResp{AccessToken: "access-new", ExpiresIn: 3600})
	}
	srv := langsmithTestServer(t, nil, token)

	e := &LangSmithEngine{httpClient: srv.Client()}
	out, err := e.Refresh(context.Background(), map[string]any{"api_url": srv.URL}, map[string]string{"refresh_token": "refresh-old"})
	if err != nil {
		t.Fatalf("Refresh error: %v", err)
	}
	if out["refresh_token"] != "refresh-old" {
		t.Errorf("refresh_token = %q, want refresh-old preserved", out["refresh_token"])
	}
}

func TestLangSmithEngine_Refresh_Revoked(t *testing.T) {
	token := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(langsmithTokenResp{Error: "invalid_grant"})
	}
	srv := langsmithTestServer(t, nil, token)

	e := &LangSmithEngine{httpClient: srv.Client()}
	_, err := e.Refresh(context.Background(), map[string]any{"api_url": srv.URL}, map[string]string{"refresh_token": "refresh-old"})
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !errors.Is(err, ErrRevoked) {
		t.Errorf("error = %v, want ErrRevoked", err)
	}
}

func TestLangSmithEngine_Refresh_MissingRefreshToken(t *testing.T) {
	e := &LangSmithEngine{}
	_, err := e.Refresh(context.Background(), map[string]any{"api_url": "https://api.smith.langchain.com"}, map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "refresh_token") {
		t.Errorf("error = %v, want missing refresh_token error", err)
	}
}
