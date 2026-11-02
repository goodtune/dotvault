package enrol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cli/oauth/api"

	"github.com/goodtune/dotvault/internal/config"
)

func TestGitHubEngine_Name(t *testing.T) {
	e := &GitHubEngine{}
	if e.Name() != "GitHub" {
		t.Errorf("Name() = %q, want %q", e.Name(), "GitHub")
	}
}

func TestGitHubEngine_Fields(t *testing.T) {
	e := &GitHubEngine{}
	fields := e.Fields()
	want := []string{"oauth_token"}
	if len(fields) != len(want) {
		t.Fatalf("Fields() len = %d, want %d", len(fields), len(want))
	}
	for i, f := range fields {
		if f != want[i] {
			t.Errorf("Fields()[%d] = %q, want %q", i, f, want[i])
		}
	}
}

func TestGitHubDefaultsUsedWhenNoSettings(t *testing.T) {
	// Verify that the engine uses default client_id and scopes when settings is nil.
	// We can't run a real OAuth flow in unit tests, so we just verify the defaults
	// are correct by checking the constants.
	if githubDefaultClientID == "" {
		t.Error("githubDefaultClientID is empty")
	}
	if githubDefaultHost == "" {
		t.Error("githubDefaultHost is empty")
	}
	if len(githubDefaultScopes) == 0 {
		t.Error("githubDefaultScopes is empty")
	}
}

func TestGitHubSettingsOverride(t *testing.T) {
	// The override logic is inline in Run(), but we can verify the constant defaults
	// are distinct from typical override values so overrides would actually change behaviour.
	customClientID := "custom-client-id"
	if customClientID == githubDefaultClientID {
		t.Error("test client ID matches default — override test would be vacuous")
	}
}

func TestGitHubCredential(t *testing.T) {
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

	t.Run("non-expiring token keeps the legacy shape", func(t *testing.T) {
		got := githubCredential(&api.AccessToken{Token: "gho_x"}, now)
		if len(got) != 1 || got["oauth_token"] != "gho_x" {
			t.Errorf("got %v", got)
		}
	})

	t.Run("expiry without a refresh token is not rotatable", func(t *testing.T) {
		got := githubCredential(&api.AccessToken{Token: "ghu_x", ExpiresIn: 8 * time.Hour}, now)
		if _, ok := got["expires_at"]; ok {
			t.Errorf("expires_at written without a refresh token: %v", got)
		}
	})

	t.Run("expiring token gains the refresh fields", func(t *testing.T) {
		got := githubCredential(&api.AccessToken{
			Token:                 "ghu_x",
			RefreshToken:          "ghr_y",
			ExpiresIn:             8 * time.Hour,
			RefreshTokenExpiresIn: 184 * 24 * time.Hour,
		}, now)
		want := map[string]string{
			"oauth_token":              "ghu_x",
			"refresh_token":            "ghr_y",
			"issued_at":                "2026-11-01T10:00:00Z",
			"expires_at":               "2026-11-01T18:00:00Z",
			"refresh_token_expires_at": "2027-05-04T10:00:00Z",
		}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s = %q, want %q", k, got[k], v)
			}
		}
	})
}

// fakeGitHubTokenEndpoint serves /login/oauth/access_token the way github.com
// does (form-encoded), recording the refresh grants it sees.
func fakeGitHubTokenEndpoint(t *testing.T, respond func(w http.ResponseWriter, form url.Values)) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login/oauth/access_token" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		calls++
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		respond(w, r.PostForm)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// fakeGitHubDeviceFlow serves the device-code and token endpoints the way
// github.com does: the token endpoint answers with a refresh token only when
// the code request carried offline_access, so the fake rewards exactly what the
// real server does. honourOffline false models a host without support, which
// ignores the request. It reports the scope the engine actually sent.
func fakeGitHubDeviceFlow(t *testing.T, honourOffline bool) (*httptest.Server, *string) {
	t.Helper()
	var scope string
	mux := http.NewServeMux()
	mux.HandleFunc("/login/device/code", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		scope = r.PostForm.Get("scope")
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		fmt.Fprint(w, url.Values{
			"device_code":      {"dc"},
			"user_code":        {"ABCD-1234"},
			"verification_uri": {"https://example.test/device"},
			"expires_in":       {"60"},
			"interval":         {"1"},
		}.Encode())
	})
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		v := url.Values{"access_token": {"gho_new"}, "token_type": {"bearer"}}
		if honourOffline && strings.Contains(scope, "offline_access") {
			v.Set("refresh_token", "ghr_new")
			v.Set("expires_in", "28800")
			v.Set("refresh_token_expires_in", "15811200")
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		fmt.Fprint(w, v.Encode())
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &scope
}

func TestGitHubRunTokenLifetime(t *testing.T) {
	// A test run must not replace the developer's clipboard.
	orig := copyToClipboard
	copyToClipboard = func(string) {}
	t.Cleanup(func() { copyToClipboard = orig })

	tests := []struct {
		name        string
		settings    map[string]any
		unsupported bool // the host ignores offline_access
		wantScope   string
		wantRefresh bool
	}{
		{
			name:      "unset requests no refresh token",
			wantScope: "repo read:org gist",
		},
		{
			name:      "non-expiring requests no refresh token",
			settings:  map[string]any{"token_lifetime": "non-expiring"},
			wantScope: "repo read:org gist",
		},
		{
			name:        "expiring requests offline_access with the default scopes",
			settings:    map[string]any{"token_lifetime": "expiring"},
			wantScope:   "repo read:org gist offline_access",
			wantRefresh: true,
		},
		{
			name: "expiring keeps a custom scope list",
			settings: map[string]any{
				"token_lifetime": "expiring",
				"scopes":         []any{"repo", "workflow"},
			},
			wantScope:   "repo workflow offline_access",
			wantRefresh: true,
		},
		{
			name: "expiring does not repeat an explicit offline_access",
			settings: map[string]any{
				"token_lifetime": "expiring",
				"scopes":         []any{"repo", "offline_access"},
			},
			wantScope:   "repo offline_access",
			wantRefresh: true,
		},
		{
			name:        "a host that ignores the request yields an ordinary token",
			settings:    map[string]any{"token_lifetime": "expiring"},
			unsupported: true,
			wantScope:   "repo read:org gist offline_access",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, scope := fakeGitHubDeviceFlow(t, !tt.unsupported)
			settings := map[string]any{"host": srv.URL}
			for k, v := range tt.settings {
				settings[k] = v
			}
			e := &GitHubEngine{httpClient: srv.Client()}
			got, err := e.Run(context.Background(), settings, IO{
				Out: io.Discard,
				In:  strings.NewReader("\n"),
				Log: slog.New(slog.DiscardHandler),
			})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if *scope != tt.wantScope {
				t.Errorf("scope sent = %q, want %q", *scope, tt.wantScope)
			}
			if got["oauth_token"] != "gho_new" {
				t.Errorf("oauth_token = %q", got["oauth_token"])
			}
			if _, ok := got["refresh_token"]; ok != tt.wantRefresh {
				t.Errorf("refresh_token present = %v, want %v", ok, tt.wantRefresh)
			}
			if _, ok := got["expires_at"]; ok != tt.wantRefresh {
				t.Errorf("expires_at present = %v, want %v", ok, tt.wantRefresh)
			}
		})
	}

	t.Run("an invalid value fails before contacting GitHub", func(t *testing.T) {
		srv, scope := fakeGitHubDeviceFlow(t, true)
		e := &GitHubEngine{httpClient: srv.Client()}
		_, err := e.Run(context.Background(), map[string]any{
			"host":           srv.URL,
			"token_lifetime": "forever",
		}, IO{Out: io.Discard, In: strings.NewReader("")})
		if err == nil || !strings.Contains(err.Error(), "token_lifetime") {
			t.Fatalf("err = %v, want a token_lifetime error", err)
		}
		if *scope != "" {
			t.Errorf("device code was requested with scope %q", *scope)
		}
	})
}

// Refresh refuses a cleartext host, so enrolling an expiring token over one
// would deliver a refresh token in the clear and then strand it.
func TestGitHubRunExpiringRefusesCleartextHost(t *testing.T) {
	e := &GitHubEngine{httpClient: http.DefaultClient}
	_, err := e.Run(context.Background(), map[string]any{
		"host":           "http://github.example.com",
		"token_lifetime": "expiring",
	}, IO{Out: io.Discard, In: strings.NewReader("")})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("err = %v, want a refusal naming https", err)
	}
}

func TestGitHubRefresh(t *testing.T) {
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	existing := map[string]string{
		"oauth_token":   "ghu_old",
		"refresh_token": "ghr_old",
		"issued_at":     "2026-11-01T02:00:00Z",
		"expires_at":    "2026-11-01T10:00:00Z",
		"user":          "octocat",
	}
	ctx := context.Background()

	t.Run("rotates both tokens and keeps the user", func(t *testing.T) {
		srv, calls := fakeGitHubTokenEndpoint(t, func(w http.ResponseWriter, form url.Values) {
			if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "ghr_old" || form.Get("client_id") != "Iv1.custom" {
				t.Errorf("unexpected grant %v", form)
			}
			if form.Get("client_secret") != "" {
				t.Error("no client secret should be sent for a device-flow token")
			}
			fmt.Fprint(w, "access_token=ghu_new&refresh_token=ghr_new&expires_in=28800&refresh_token_expires_in=15897600&token_type=bearer")
		})
		e := &GitHubEngine{httpClient: srv.Client(), now: func() time.Time { return now }}
		got, err := e.Refresh(ctx, map[string]any{"host": srv.URL, "client_id": "Iv1.custom"}, existing)
		if err != nil {
			t.Fatal(err)
		}
		if *calls != 1 {
			t.Errorf("token endpoint calls = %d", *calls)
		}
		if got["oauth_token"] != "ghu_new" || got["refresh_token"] != "ghr_new" || got["user"] != "octocat" {
			t.Errorf("got %v", got)
		}
		if got["issued_at"] != "2026-11-01T10:00:00Z" || got["expires_at"] != "2026-11-01T18:00:00Z" || got["refresh_token_expires_at"] != "2027-05-04T10:00:00Z" {
			t.Errorf("timestamps: %v", got)
		}
	})

	t.Run("a response without expires_in keeps the credential rotatable", func(t *testing.T) {
		srv, _ := fakeGitHubTokenEndpoint(t, func(w http.ResponseWriter, _ url.Values) {
			fmt.Fprint(w, "access_token=ghu_new")
		})
		e := &GitHubEngine{httpClient: srv.Client(), now: func() time.Time { return now }}
		got, err := e.Refresh(ctx, map[string]any{"host": srv.URL}, existing)
		if err != nil {
			t.Fatal(err)
		}
		// The previous 8h lifetime is assumed, and oauth.Refresh carries the
		// unrotated refresh token forward, so the next half-life still fires.
		if got["refresh_token"] != "ghr_old" || got["expires_at"] != "2026-11-01T18:00:00Z" {
			t.Errorf("credential downgraded: %v", got)
		}
	})

	t.Run("a cleartext non-loopback host is refused", func(t *testing.T) {
		e := &GitHubEngine{now: func() time.Time { return now }}
		_, err := e.Refresh(ctx, map[string]any{"host": "http://ghe.example.com"}, existing)
		if err == nil || errors.Is(err, ErrRevoked) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("a rejected refresh token means re-enrol", func(t *testing.T) {
		srv, _ := fakeGitHubTokenEndpoint(t, func(w http.ResponseWriter, _ url.Values) {
			fmt.Fprint(w, "error=bad_refresh_token&error_description=The+refresh+token+passed+is+incorrect+or+expired.")
		})
		e := &GitHubEngine{httpClient: srv.Client(), now: func() time.Time { return now }}
		_, err := e.Refresh(ctx, map[string]any{"host": srv.URL}, existing)
		if !errors.Is(err, ErrRevoked) {
			t.Errorf("err = %v, want ErrRevoked", err)
		}
	})

	t.Run("a server fault is transient", func(t *testing.T) {
		srv, _ := fakeGitHubTokenEndpoint(t, func(w http.ResponseWriter, _ url.Values) {
			w.WriteHeader(http.StatusBadGateway)
		})
		e := &GitHubEngine{httpClient: srv.Client(), now: func() time.Time { return now }}
		_, err := e.Refresh(ctx, map[string]any{"host": srv.URL}, existing)
		if err == nil || errors.Is(err, ErrRevoked) {
			t.Errorf("err = %v, want a transient error", err)
		}
	})

	t.Run("a stored refresh-token expiry does not short-circuit GitHub", func(t *testing.T) {
		srv, calls := fakeGitHubTokenEndpoint(t, func(w http.ResponseWriter, _ url.Values) {
			fmt.Fprint(w, "access_token=ghu_new&refresh_token=ghr_new&expires_in=28800")
		})
		skewed := map[string]string{}
		for k, v := range existing {
			skewed[k] = v
		}
		// A local clock that thinks the refresh token lapsed must not be
		// what wipes the secret; GitHub accepting it is the answer.
		skewed["refresh_token_expires_at"] = "2026-10-01T00:00:00Z"
		e := &GitHubEngine{httpClient: srv.Client(), now: func() time.Time { return now }}
		if _, err := e.Refresh(ctx, map[string]any{"host": srv.URL}, skewed); err != nil || *calls != 1 {
			t.Errorf("err = %v, calls = %d", err, *calls)
		}
	})

	t.Run("no refresh token is an error, not a revocation", func(t *testing.T) {
		e := &GitHubEngine{now: func() time.Time { return now }}
		_, err := e.Refresh(ctx, nil, map[string]string{"oauth_token": "x", "expires_at": "2026-11-01T10:00:00Z"})
		if err == nil || errors.Is(err, ErrRevoked) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("cancellation aborts the in-flight request", func(t *testing.T) {
		arrived := make(chan struct{})
		aborted := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The server only watches for a hang-up once the body is read.
			_, _ = io.ReadAll(r.Body)
			close(arrived)
			<-r.Context().Done() // the client hung up
			close(aborted)
		}))
		t.Cleanup(srv.Close)
		e := &GitHubEngine{httpClient: srv.Client(), now: func() time.Time { return now }}
		cctx, cancel := context.WithCancel(ctx)
		go func() { <-arrived; cancel() }()
		if _, err := e.Refresh(cctx, map[string]any{"host": srv.URL}, existing); !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v", err)
		}
		select {
		case <-aborted:
		case <-time.After(5 * time.Second):
			t.Error("the request was abandoned rather than cancelled")
		}
	})
}

// TestRefreshManagerRotatesGitHub drives the real engine through the
// RefreshManager: an expiring GitHub token past half-life is rotated in
// Vault, and a classic non-expiring one is never sent to the token endpoint.
func TestRefreshManagerRotatesGitHub(t *testing.T) {
	issued := time.Date(2026, 11, 1, 2, 0, 0, 0, time.UTC)
	now := issued.Add(5 * time.Hour) // past the 4h half-life of an 8h token

	srv, calls := fakeGitHubTokenEndpoint(t, func(w http.ResponseWriter, form url.Values) {
		if form.Get("refresh_token") != "ghr_old" {
			t.Errorf("refresh grant presented %q", form.Get("refresh_token"))
		}
		fmt.Fprint(w, "access_token=ghu_new&refresh_token=ghr_new&expires_in=28800")
	})
	RegisterEngine("github-test", &GitHubEngine{httpClient: srv.Client(), now: func() time.Time { return now }})
	t.Cleanup(func() { UnregisterEngine("github-test") })

	fv := newFakeVault("kv")
	vc := fv.serve(t)
	fv.seed("users/alice/gh", map[string]string{
		"oauth_token":   "ghu_old",
		"refresh_token": "ghr_old",
		"issued_at":     issued.Format(time.RFC3339),
		"expires_at":    issued.Add(8 * time.Hour).Format(time.RFC3339),
		"user":          "alice",
	})
	fv.seed("users/alice/classic", map[string]string{"oauth_token": "gho_forever", "user": "alice"})

	settings := map[string]any{"host": srv.URL}
	m := NewRefreshManager(vc, "kv", "users/alice/", map[string]config.Enrolment{
		"gh":      {Engine: "github-test", Settings: settings},
		"classic": {Engine: "github-test", Settings: settings},
	}, time.Hour, WithClock(&fixedClock{now: now}))
	m.tick(context.Background())

	if *calls != 1 {
		t.Errorf("token endpoint calls = %d, want 1 (the classic token must not be refreshed)", *calls)
	}
	got := fv.secret("users/alice/gh")
	if got["oauth_token"] != "ghu_new" || got["refresh_token"] != "ghr_new" || got["user"] != "alice" {
		t.Errorf("rotated secret = %v", got)
	}
	if got["expires_at"] != now.Add(8*time.Hour).Format(time.RFC3339) {
		t.Errorf("expires_at = %q", got["expires_at"])
	}
	if c := fv.secret("users/alice/classic"); c["oauth_token"] != "gho_forever" {
		t.Errorf("classic secret changed: %v", c)
	}
}

// A GitHub App can return an expiring token unasked, so the host check must
// key off the response, not the token_lifetime setting.
func TestCheckExpiringHost(t *testing.T) {
	expiring := &api.AccessToken{Token: "ghu_x", RefreshToken: "ghr_y", ExpiresIn: 8 * time.Hour}
	classic := &api.AccessToken{Token: "gho_x"}
	for _, tc := range []struct {
		name    string
		tok     *api.AccessToken
		host    string
		wantErr bool
	}{
		{"expiring over cleartext", expiring, "http://ghe.example.com", true},
		{"expiring over https", expiring, "https://ghe.example.com", false},
		{"expiring over loopback", expiring, "http://127.0.0.1:8080", false},
		{"classic over cleartext", classic, "http://ghe.example.com", false},
		// The boundary githubCredential also draws: no expiry means nothing
		// to rotate, so the refresh fields would not be written anyway.
		{"refresh token without expiry over cleartext", &api.AccessToken{Token: "x", RefreshToken: "r"}, "http://ghe.example.com", false},
		{"expiry without refresh token over cleartext", &api.AccessToken{Token: "x", ExpiresIn: time.Hour}, "http://ghe.example.com", false},
	} {
		if err := checkExpiringHost(tc.tok, tc.host); (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}
