package enrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSlack serves a workspace page and auth.test for any domain (the first
// path segment), signed in only for the cookie good. Domain "limited" answers
// its first page load with a 429.
type fakeSlack struct {
	srv     *httptest.Server
	good    string
	pages   atomic.Int32
	limited atomic.Bool
}

func newFakeSlack(t *testing.T, good string) *fakeSlack {
	t.Helper()
	f := &fakeSlack{good: good}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		domain, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		cookie := ""
		if c, err := r.Cookie("d"); err == nil {
			cookie = c.Value
		}
		switch rest {
		case "":
			f.pages.Add(1)
			if domain == "limited" && !f.limited.Swap(true) {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			if cookie != f.good {
				_, _ = w.Write([]byte(`<html>Sign in to Slack</html>`))
				return
			}
			_, _ = w.Write([]byte(`<script>var boot = {"api_token":"xoxc-` + domain + `-` + f.pagesString() + `","x":1}</script>`))
		case "api/auth.test":
			_ = r.ParseForm()
			if cookie != f.good || !strings.HasPrefix(r.Form.Get("token"), "xoxc-"+domain) {
				_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": true, "team": strings.ToUpper(domain), "team_id": "T-" + domain, "user_id": "U1",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSlack) pagesString() string { return string(rune('0' + f.pages.Load())) }

func (f *fakeSlack) engine(now time.Time) *SlackEngine {
	return &SlackEngine{
		pageURL:    func(d string) string { return f.srv.URL + "/" + d + "/" },
		apiURL:     func(d, m string) string { return f.srv.URL + "/" + d + "/api/" + m },
		httpClient: f.srv.Client(),
		now:        func() time.Time { return now },
	}
}

func slackSettings(ws ...string) map[string]any {
	list := make([]any, len(ws))
	for i, w := range ws {
		list[i] = w
	}
	return map[string]any{"workspaces": list}
}

func pasteIO(paste string) IO {
	return IO{
		Out:          &bytes.Buffer{},
		PromptSecret: func(string) (string, error) { return paste, nil },
	}
}

func decodeCred(t *testing.T, s string) SlackCredential {
	t.Helper()
	var c SlackCredential
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		t.Fatalf("field is not a SlackCredential: %v (%q)", err, s)
	}
	return c
}

var slackNow = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func TestSlackRunMintsEveryWorkspace(t *testing.T) {
	f := newFakeSlack(t, "xoxd-good")
	curl := `curl 'https://acme.slack.com/api/client.counts' -H 'cookie: b=x; d=xoxd-good; d-s=1' --data-raw 'token=xoxc-old'`
	out, err := f.engine(slackNow).Run(context.Background(), slackSettings("acme", "beta"), pasteIO(curl))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"acme", "beta"} {
		c := decodeCred(t, out[d])
		if c.Domain != d || c.TeamID != "T-"+d || c.TeamName != strings.ToUpper(d) || c.UserID != "U1" ||
			c.Cookie != "xoxd-good" || !strings.HasPrefix(c.AccessToken, "xoxc-"+d) {
			t.Errorf("%s credential = %+v", d, c)
		}
	}
	if out["issued_at"] != "2026-11-03T12:00:00Z" || out["expires_at"] != "2026-11-04T12:00:00Z" {
		t.Errorf("timestamps = %q / %q", out["issued_at"], out["expires_at"])
	}
	// The field set the manager checks for completeness is the workspaces.
	if got := (&SlackEngine{}).FieldsFromSettings(slackSettings("acme", "beta")); strings.Join(got, ",") != "acme,beta" {
		t.Errorf("FieldsFromSettings = %v", got)
	}
}

func TestSlackRunRefusesWithoutWritingWhenAWorkspaceFails(t *testing.T) {
	f := newFakeSlack(t, "xoxd-good")
	_, err := f.engine(slackNow).Run(context.Background(), slackSettings("acme"), pasteIO("xoxd-wrong"))
	if err == nil || !strings.Contains(err.Error(), "acme.slack.com did not accept that session") {
		t.Fatalf("err = %v", err)
	}
}

func TestSlackRunNeedsACookie(t *testing.T) {
	f := newFakeSlack(t, "xoxd-good")
	_, err := f.engine(slackNow).Run(context.Background(), slackSettings("acme"), pasteIO("just some text"))
	if err == nil || !strings.Contains(err.Error(), "no d cookie") {
		t.Fatalf("err = %v", err)
	}
	if _, err := f.engine(slackNow).Run(context.Background(), slackSettings("acme"), IO{}); err == nil {
		t.Fatal("no PromptSecret: want an error")
	}
	if _, err := f.engine(slackNow).Run(context.Background(), map[string]any{}, pasteIO("xoxd-good")); err == nil {
		t.Fatal("no workspaces: want an error")
	}
}

func TestSlackRetriesRateLimit(t *testing.T) {
	f := newFakeSlack(t, "xoxd-good")
	out, err := f.engine(slackNow).Run(context.Background(), slackSettings("limited"), pasteIO("xoxd-good"))
	if err != nil {
		t.Fatal(err)
	}
	if decodeCred(t, out["limited"]).TeamID != "T-limited" {
		t.Errorf("out = %v", out)
	}
	if n := f.pages.Load(); n != 2 {
		t.Errorf("page loads = %d, want 2 (one 429, one retry)", n)
	}
}

func TestSlackRefreshReMintsAndKeepsOtherFields(t *testing.T) {
	f := newFakeSlack(t, "xoxd-good")
	old, _ := json.Marshal(SlackCredential{Domain: "acme", TeamID: "T-acme", AccessToken: "xoxc-stale", Cookie: "xoxd-good"})
	existing := map[string]string{
		"acme":       string(old),
		"issued_at":  "2026-11-01T00:00:00Z",
		"expires_at": "2026-11-02T00:00:00Z",
		"note":       "written by hand",
	}
	settings := slackSettings("acme")
	settings["refresh_interval"] = "6h"
	out, err := f.engine(slackNow).Refresh(context.Background(), settings, existing)
	if err != nil {
		t.Fatal(err)
	}
	if c := decodeCred(t, out["acme"]); c.AccessToken == "xoxc-stale" || !strings.HasPrefix(c.AccessToken, "xoxc-acme") {
		t.Errorf("token not re-minted: %+v", c)
	}
	if out["note"] != "written by hand" {
		t.Errorf("other field lost: %v", out)
	}
	if out["expires_at"] != "2026-11-03T18:00:00Z" {
		t.Errorf("expires_at = %q, want refresh_interval after now", out["expires_at"])
	}
	if existing["acme"] != string(old) {
		t.Error("Refresh must not write its input")
	}
}

func TestSlackRefreshDeadCookieIsRevoked(t *testing.T) {
	f := newFakeSlack(t, "xoxd-good")
	dead, _ := json.Marshal(SlackCredential{Domain: "acme", AccessToken: "xoxc-x", Cookie: "xoxd-expired"})
	_, err := f.engine(slackNow).Refresh(context.Background(), slackSettings("acme"), map[string]string{"acme": string(dead)})
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("err = %v, want ErrRevoked", err)
	}
}

func TestSlackRefreshTransientIsNotRevoked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	e := &SlackEngine{pageURL: func(string) string { return srv.URL }, httpClient: srv.Client()}
	cred, _ := json.Marshal(SlackCredential{Domain: "acme", Cookie: "xoxd-good"})
	_, err := e.Refresh(context.Background(), slackSettings("acme"), map[string]string{"acme": string(cred)})
	if err == nil || errors.Is(err, ErrRevoked) {
		t.Fatalf("err = %v, want a transient (non-revoked) error", err)
	}
}

func TestParseSlackCookie(t *testing.T) {
	cases := map[string]string{
		"bash curl":   `curl 'https://x.slack.com/api/a' -H 'cookie: b=1; d=xoxd-abc%2Fdef; x=2'`,
		"cmd curl":    `curl ^"https://x.slack.com/api/a^" -H ^"cookie: d=xoxd-abc%2Fdef; x=2^"`,
		"powershell":  `$session.Cookies.Add((New-Object System.Net.Cookie("d", "xoxd-abc%2Fdef", "/", ".slack.com")))`,
		"pair":        `d=xoxd-abc%2Fdef`,
		"bare":        "  xoxd-abc%2Fdef  ",
		"decoded":     "xoxd-abc/def",
		"bare + semi": "xoxd-abc%2Fdef;",
	}
	for name, paste := range cases {
		if got := parseSlackCookie(paste); got != "xoxd-abc%2Fdef" {
			t.Errorf("%s: got %q", name, got)
		}
	}
	if got := parseSlackCookie("ds=xoxd-nope"); got != "" {
		t.Errorf("a cookie merely ending in d must not match, got %q", got)
	}
}
