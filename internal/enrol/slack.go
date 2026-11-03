package enrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/httpproxy"
)

var (
	_ Engine          = (*SlackEngine)(nil)
	_ SettingsFielder = (*SlackEngine)(nil)
	_ Refresher       = (*SlackEngine)(nil)
)

// SlackEngine enrols Slack browser sessions for slk
// (docs/superpowers/specs/2026-11-03-slack-enrolment-design.md). The user
// pastes their browser session once; the engine keeps its d cookie, mints an
// xoxc token per configured workspace from it, and re-mints on refresh. The
// secret holds one field per workspace (named by its subdomain) whose value is
// a SlackCredential as JSON, plus issued_at / expires_at.
//
// The field names and the JSON shape are the contract with slk, which reads
// them through the client facade. Nothing here imports slk: slk imports
// dotvault, so the reverse would make the two modules depend on each other.
type SlackEngine struct {
	// pageURL and apiURL build a workspace's page and Web API URLs; tests
	// point them at an httptest server. Nil means https://<domain>.slack.com.
	pageURL func(domain string) string
	apiURL  func(domain, method string) string
	// httpClient overrides the settings-derived client (tests).
	httpClient *http.Client
	now        func() time.Time
}

// SlackCredential is one workspace's field in a slack enrolment's secret.
type SlackCredential struct {
	Domain      string `json:"domain"`
	TeamID      string `json:"team_id"`
	TeamName    string `json:"team_name"`
	UserID      string `json:"user_id"`
	AccessToken string `json:"access_token"` // xoxc-…
	Cookie      string `json:"cookie"`       // the d cookie, URL-encoded
}

func (e *SlackEngine) Name() string { return "Slack" }

// Fields has no static answer: the written fields are the configured
// workspaces. See FieldsFromSettings.
func (e *SlackEngine) Fields() []string { return nil }

// FieldsFromSettings returns the configured workspace names, so an enrolment
// is incomplete until every listed workspace has a credential, and listing a
// new one brings the enrolment back as pending. Malformed settings return nil,
// which the manager reads as incomplete.
func (e *SlackEngine) FieldsFromSettings(settings map[string]any) []string {
	ws, err := config.SlackWorkspaces(settings)
	if err != nil {
		return nil
	}
	return ws
}

// slackPastePrompt is the PromptSecret label. The web card renders it as a
// secret input, so it must stand on its own.
const slackPastePrompt = "Paste your Slack browser session (DevTools → Network → a request to /api/ → Copy as cURL), or just the d cookie (xoxd-…):"

// Run asks for the browser session once and mints every configured workspace
// from its d cookie. A workspace that fails fails the run and nothing is
// written: a partial secret would count as complete for the workspaces it has.
// Fields already in the secret that this run does not produce (a workspace no
// longer listed, anything another tool wrote) are kept.
func (e *SlackEngine) Run(ctx context.Context, settings map[string]any, eio IO) (map[string]string, error) {
	workspaces, err := config.SlackWorkspaces(settings)
	if err != nil {
		return nil, fmt.Errorf("slack: settings.%w", err)
	}
	interval, err := config.SlackRefreshInterval(settings)
	if err != nil {
		return nil, fmt.Errorf("slack: settings.%w", err)
	}
	if eio.PromptSecret == nil {
		return nil, errors.New("slack: no way to ask for the browser session (PromptSecret is nil)")
	}
	client, err := e.client(settings)
	if err != nil {
		return nil, err
	}

	out := make(map[string]string)
	if eio.Vault != nil && eio.TargetPath != "" {
		existing, err := eio.Vault.ReadKVv2(ctx, eio.KVMount, eio.TargetPath)
		if err != nil {
			return nil, fmt.Errorf("slack: read %s/%s: %w", eio.KVMount, eio.TargetPath, err)
		}
		if existing != nil {
			for k, v := range existing.Data {
				out[k] = stringifyField(v)
			}
		}
	}

	paste, err := eio.PromptSecret(slackPastePrompt)
	if err != nil {
		return nil, fmt.Errorf("slack: read session: %w", err)
	}
	cookie := parseSlackCookie(paste)
	if cookie == "" {
		return nil, errors.New("slack: no d cookie (xoxd-…) found in what was pasted; copy a request to /api/ as cURL, or the d cookie from DevTools → Application → Cookies")
	}

	for _, domain := range workspaces {
		if eio.Out != nil {
			fmt.Fprintf(eio.Out, "Signing in to %s.slack.com…\n", domain)
		}
		cred, err := e.mint(ctx, client, domain, cookie)
		if errors.Is(err, ErrRevoked) {
			// At enrolment the usual cause is a browser not signed in to
			// this workspace at all, not a session that expired.
			return nil, fmt.Errorf("slack: %s.slack.com did not accept that session; sign in to it in the same browser and copy the request again", domain)
		}
		if err != nil {
			return nil, fmt.Errorf("slack: %s: %w", domain, err)
		}
		b, err := json.Marshal(cred)
		if err != nil {
			return nil, err
		}
		out[domain] = string(b)
		if eio.Out != nil {
			fmt.Fprintf(eio.Out, "✓ %s (%s)\n", cred.TeamName, cred.TeamID)
		}
	}
	e.stamp(out, interval)
	return out, nil
}

// Refresh re-mints every workspace credential in the secret from its own
// cookie. A dead cookie for any of them is ErrRevoked for the whole secret:
// the alternative is a secret the manager counts as complete with a workspace
// in it that can no longer sign in.
func (e *SlackEngine) Refresh(ctx context.Context, settings map[string]any, existing map[string]string) (map[string]string, error) {
	interval, err := config.SlackRefreshInterval(settings)
	if err != nil {
		return nil, fmt.Errorf("slack: settings.%w", err)
	}
	client, err := e.client(settings)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(existing))
	names := make([]string, 0, len(existing))
	for k, v := range existing {
		out[k] = v
		names = append(names, k)
	}
	sort.Strings(names) // deterministic order for logs and tests
	for _, name := range names {
		var cred SlackCredential
		if json.Unmarshal([]byte(existing[name]), &cred) != nil || cred.Domain == "" || cred.Cookie == "" {
			continue // not a workspace field (issued_at, or another tool's)
		}
		fresh, err := e.mint(ctx, client, cred.Domain, cred.Cookie)
		if err != nil {
			return nil, fmt.Errorf("slack: %s: %w", name, err)
		}
		b, err := json.Marshal(fresh)
		if err != nil {
			return nil, err
		}
		out[name] = string(b)
	}
	e.stamp(out, interval)
	return out, nil
}

func (e *SlackEngine) stamp(out map[string]string, interval time.Duration) {
	now := time.Now
	if e.now != nil {
		now = e.now
	}
	t := now().UTC()
	out["issued_at"] = t.Format(time.RFC3339)
	out["expires_at"] = t.Add(interval).Format(time.RFC3339)
}

func (e *SlackEngine) client(settings map[string]any) (*http.Client, error) {
	if e.httpClient != nil {
		return e.httpClient, nil
	}
	c, err := httpproxy.ClientFromSettings(settings, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("slack: %w", err)
	}
	return c, nil
}

// errSlackSignedOut is a mint that reached Slack and was told the cookie no
// longer signs in. It wraps ErrRevoked so the RefreshManager wipes the secret.
var errSlackSignedOut = fmt.Errorf("the d cookie is no longer signed in to Slack: %w", ErrRevoked)

// mint signs in to one workspace with the cookie: the workspace page carries
// an xoxc api_token for a signed-in session, and auth.test with it names the
// team and user and proves the session works.
func (e *SlackEngine) mint(ctx context.Context, client *http.Client, domain, cookie string) (SlackCredential, error) {
	token, err := e.pageToken(ctx, client, domain, cookie)
	if err != nil {
		return SlackCredential{}, err
	}
	who, err := e.authTest(ctx, client, domain, token, cookie)
	if err != nil {
		return SlackCredential{}, err
	}
	return SlackCredential{
		Domain: domain, TeamID: who.TeamID, TeamName: who.Team, UserID: who.UserID,
		AccessToken: token, Cookie: cookie,
	}, nil
}

var slackAPITokenRE = regexp.MustCompile(`"api_token":"(xoxc-[^"]+)"`)

// slackUserAgent is sent on both requests: Slack serves a bare Go client a
// different page than it serves a browser.
const slackUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

const slackMaxAttempts = 3

func (e *SlackEngine) pageToken(ctx context.Context, client *http.Client, domain, cookie string) (string, error) {
	pageURL := "https://" + domain + ".slack.com/"
	if e.pageURL != nil {
		pageURL = e.pageURL(domain)
	}
	resp, err := slackDo(ctx, client, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Cookie", "d="+cookie)
		req.Header.Set("User-Agent", slackUserAgent)
		return req, nil
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("workspace page answered HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", fmt.Errorf("read workspace page: %w", err)
	}
	m := slackAPITokenRE.FindSubmatch(body)
	if m == nil {
		// A signed-out session is redirected to the sign-in page, which
		// carries no token.
		return "", errSlackSignedOut
	}
	return string(m[1]), nil
}

type slackAuthTest struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error"`
	Team   string `json:"team"`
	TeamID string `json:"team_id"`
	UserID string `json:"user_id"`
}

func (e *SlackEngine) authTest(ctx context.Context, client *http.Client, domain, token, cookie string) (slackAuthTest, error) {
	apiURL := "https://" + domain + ".slack.com/api/auth.test"
	if e.apiURL != nil {
		apiURL = e.apiURL(domain, "auth.test")
	}
	form := url.Values{"token": {token}}.Encode()
	resp, err := slackDo(ctx, client, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(form))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Cookie", "d="+cookie)
		req.Header.Set("User-Agent", slackUserAgent)
		return req, nil
	})
	if err != nil {
		return slackAuthTest{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return slackAuthTest{}, fmt.Errorf("auth.test answered HTTP %d", resp.StatusCode)
	}
	var out slackAuthTest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return slackAuthTest{}, fmt.Errorf("auth.test: %w", err)
	}
	switch {
	case out.OK && out.TeamID != "":
		return out, nil
	case out.Error == "invalid_auth" || out.Error == "not_authed" || out.Error == "account_inactive" || out.Error == "token_revoked":
		return slackAuthTest{}, errSlackSignedOut
	case out.Error != "":
		return slackAuthTest{}, fmt.Errorf("auth.test: %s", out.Error)
	}
	return slackAuthTest{}, errors.New("auth.test: answer named no team")
}

// slackDo sends the request newReq builds, retrying a 429 up to
// slackMaxAttempts times after its Retry-After (capped at 10s).
func slackDo(ctx context.Context, client *http.Client, newReq func() (*http.Request, error)) (*http.Response, error) {
	for attempt := 1; ; attempt++ {
		req, err := newReq()
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusTooManyRequests {
			return resp, nil
		}
		wait := slackRetryAfter(resp.Header.Get("Retry-After"))
		resp.Body.Close()
		if attempt >= slackMaxAttempts {
			return nil, errors.New("rate-limited by Slack (HTTP 429); try again in a minute")
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		}
	}
}

func slackRetryAfter(h string) time.Duration {
	wait := 2 * time.Second
	if secs, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && secs >= 0 {
		wait = time.Duration(secs) * time.Second
	}
	return min(wait, 10*time.Second)
}

var (
	// d=xoxd-… in a Cookie header, a -b argument or a $session cookie line.
	slackDCookieRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])d=(xoxd-[^;\s"'\\]+)`)
	// PowerShell's Copy as PowerShell: New-Object System.Net.Cookie("d", "xoxd-…", …).
	slackPSCookieRE = regexp.MustCompile(`Cookie\(\s*"d"\s*,\s*"(xoxd-[^"]+)"`)
	// A bare xoxd-… value on its own line.
	slackBareCookieRE = regexp.MustCompile(`(?m)^[ \t]*(xoxd-[^;\s"'\\]+);?[ \t]*\r?$`)
)

// parseSlackCookie finds the d cookie in a pasted browser request (cURL bash,
// cmd or PowerShell form), a d=… pair, or a bare value, and returns it
// URL-encoded, the form Slack sends. "" means none was found. It accepts the
// same forms as slk's --add-workspace --browser, which it mirrors without
// importing.
func parseSlackCookie(paste string) string {
	// cmd's Copy as cURL escapes with carets (^", ^%), none of which can be
	// part of a cookie.
	if strings.Contains(paste, `^"`) {
		paste = strings.ReplaceAll(paste, "^", "")
	}
	var cookie string
	for _, re := range []*regexp.Regexp{slackDCookieRE, slackPSCookieRE, slackBareCookieRE} {
		if m := re.FindStringSubmatch(paste); m != nil {
			cookie = m[1]
			break
		}
	}
	// DevTools' Application tab can show the value decoded
	// (xoxd-AbC/def+Ghi==); an encoded one has none of /+=.
	if strings.ContainsAny(cookie, "/+=") {
		cookie = url.QueryEscape(cookie)
	}
	return cookie
}

// stringifyField renders an existing KVv2 value as the string the engine
// contract carries, as the copy engine does: strings verbatim, anything else
// as JSON so it is kept rather than dropped.
func stringifyField(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
