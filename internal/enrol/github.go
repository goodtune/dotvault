package enrol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cli/oauth"
	"github.com/cli/oauth/api"

	"github.com/goodtune/dotvault/internal/httpproxy"
)

const (
	// githubDefaultClientID is the GitHub CLI's public OAuth app client ID.
	githubDefaultClientID = "178c6fc778ccc68e1d6a"
	githubDefaultHost     = "https://github.com"
	// githubDefaultTokenLifetime is GitHub's documented lifetime for an
	// expiring user access token, used only when a refresh response omits
	// expires_in for a credential already known to expire.
	githubDefaultTokenLifetime = 8 * time.Hour
)

var githubDefaultScopes = []string{"repo", "read:org", "gist"}

// GitHubEngine performs a GitHub OAuth device flow.
//
// Whether the credential expires is GitHub's decision, not dotvault's: a
// classic OAuth app (the GitHub CLI's default client ID among them) issues a
// token that never expires, while a GitHub App with user-token expiration
// returns an 8-hour access token alongside a refresh token. The engine records whatever came back. When the response
// carried a refresh token and an expiry, the secret gains refresh_token,
// issued_at and expires_at and the RefreshManager rotates it past half-life,
// exactly as it does for JFrog and Databricks; when it did not, the secret is
// what it always was, and the RefreshManager skips it (no expires_at). Note
// the converse trap: switching client_id on an existing classic enrolment
// changes nothing until the user re-runs `dotvault enrol`, since Fields()
// already reports the old secret complete.
type GitHubEngine struct {
	// httpClient overrides the proxy-aware client built from settings.
	// Tests only.
	httpClient *http.Client
	// now is injected for deterministic issued_at/expires_at timestamps.
	now func() time.Time
}

func (e *GitHubEngine) Name() string { return "GitHub" }

// Fields is deliberately the non-expiring shape only. refresh_token,
// issued_at and expires_at exist only when GitHub issued an expiring token,
// so listing them would mark every classic-OAuth-app enrolment incomplete.
func (e *GitHubEngine) Fields() []string { return []string{"oauth_token"} }

func (e *GitHubEngine) clock() time.Time {
	if e.now != nil {
		return e.now()
	}
	return time.Now()
}

func (e *GitHubEngine) client(settings map[string]any) (*http.Client, error) {
	if e.httpClient != nil {
		return e.httpClient, nil
	}
	return httpproxy.ClientFromSettings(settings, 30*time.Second)
}

// githubClientID returns the configured OAuth client ID, or the GitHub CLI's.
// Refresh must present the same client ID the token was issued to; it is read
// from the same settings rather than stored in the secret, so a changed
// client_id is noticed at the next refresh. Whether GitHub answers that with a
// code cli/oauth maps to ErrRefreshTokenInvalid (wipe + re-enrol) or with
// another error (transient, retried) is GitHub's call; re-running
// `dotvault enrol` is the reliable way to switch clients.
func githubClientID(settings map[string]any) string {
	if v, ok := settings["client_id"].(string); ok && v != "" {
		return v
	}
	return githubDefaultClientID
}

// githubHostURL returns the configured GitHub host as a URL.
func githubHostURL(settings map[string]any) string {
	if v, ok := settings["host"].(string); ok && v != "" {
		if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
			return v
		}
		return "https://" + v
	}
	return githubDefaultHost
}

func (e *GitHubEngine) Run(ctx context.Context, settings map[string]any, io IO) (map[string]string, error) {
	clientID := githubClientID(settings)

	hostURL := githubHostURL(settings)

	scopes := githubDefaultScopes
	if raw, ok := settings["scopes"]; ok {
		sl, ok := raw.([]any)
		if !ok {
			return nil, fmt.Errorf("invalid scopes setting: expected list, got %T", raw)
		}
		parsed := make([]string, 0, len(sl))
		for _, s := range sl {
			str, ok := s.(string)
			if !ok {
				return nil, fmt.Errorf("invalid scope value: expected string, got %T", s)
			}
			parsed = append(parsed, str)
		}
		scopes = parsed
	}

	host, err := oauth.NewGitHubHost(hostURL)
	if err != nil {
		return nil, fmt.Errorf("parse github host: %w", err)
	}

	httpClient, err := e.client(settings)
	if err != nil {
		return nil, fmt.Errorf("configure http client: %w", err)
	}

	in := io.In
	if in == nil {
		in = os.Stdin
	}

	flow := &oauth.Flow{
		Host:       host,
		ClientID:   clientID,
		Scopes:     scopes,
		HTTPClient: httpClient,
		Stdout:     io.Out,
		Stdin:      in,
		DisplayCode: func(userCode, verificationURI string) error {
			copyToClipboard(userCode)
			fmt.Fprintf(io.Out, "! First, copy your one-time code: %s\n", userCode)
			fmt.Fprintf(io.Out, "- Press Enter to open %s in your browser... ", verificationURI)
			bufio.NewScanner(in).Scan()
			return nil
		},
		BrowseURL: func(url string) error {
			if io.Browser == nil {
				fmt.Fprintf(io.Out, "- Please open %s in your browser.\n", url)
				return nil
			}
			if err := io.Browser(url); err != nil {
				fmt.Fprintf(io.Out, "  (could not open browser automatically: %v)\n", err)
				return nil
			}
			fmt.Fprintf(io.Out, "✓ Opened %s in browser\n", url)
			return nil
		},
	}

	type result struct {
		token *api.AccessToken
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		fmt.Fprintf(io.Out, "⠼ Waiting for authentication...\n")
		tok, err := flow.DeviceFlow()
		ch <- result{tok, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("device flow: %w", r.err)
		}
		user, err := fetchGitHubUser(ctx, httpClient, hostURL, r.token.Token)
		if err != nil {
			io.Log.Warn("could not fetch github username", "error", err)
			user = ""
		}
		out := githubCredential(r.token, e.clock())
		out["user"] = user
		return out, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// githubCredential renders a token response as the Vault secret. The
// refresh fields are written only for an expiring token that came with a
// refresh token: an expiry without one cannot be rotated (writing expires_at
// would only have the RefreshManager fail on it every half-life), and a
// refresh token without an expiry has nothing to rotate ahead of. Refresh
// guarantees the expiry half for a credential already known to expire; the
// refresh-token half it gets from oauth.Refresh, which carries the presented
// token forward when the server does not rotate it.
func githubCredential(tok *api.AccessToken, now time.Time) map[string]string {
	out := map[string]string{"oauth_token": tok.Token}
	if tok.RefreshToken == "" || tok.ExpiresIn <= 0 {
		return out
	}
	now = now.UTC()
	out["refresh_token"] = tok.RefreshToken
	out["issued_at"] = now.Format(time.RFC3339)
	out["expires_at"] = now.Add(tok.ExpiresIn).Format(time.RFC3339)
	if tok.RefreshTokenExpiresIn > 0 {
		out["refresh_token_expires_at"] = now.Add(tok.RefreshTokenExpiresIn).Format(time.RFC3339)
	}
	return out
}

// Refresh exchanges the stored refresh token for a new token pair. GitHub
// rotates the refresh token on every use, so the old one is dead the moment
// this succeeds — the same contract as JFrog. It is only ever called for a
// secret carrying expires_at, i.e. one githubCredential wrote from an
// expiring token. No client secret is sent: cli/oauth documents device-flow
// tokens as refreshable by client ID alone.
func (e *GitHubEngine) Refresh(ctx context.Context, settings map[string]any, existing map[string]string) (map[string]string, error) {
	refresh := existing["refresh_token"]
	if refresh == "" {
		return nil, fmt.Errorf("github refresh requires a refresh_token in the existing secret")
	}
	// refresh_token_expires_at is deliberately not pre-checked: an
	// ErrRevoked wipes the secret, and that decision belongs to GitHub, not
	// to a host clock that may be skewed.

	hostURL := githubHostURL(settings)
	if err := requireSecureTokenEndpoint(hostURL); err != nil {
		return nil, err
	}
	host, err := oauth.NewGitHubHost(hostURL)
	if err != nil {
		return nil, fmt.Errorf("parse github host: %w", err)
	}
	client, err := e.client(settings)
	if err != nil {
		return nil, fmt.Errorf("configure http client: %w", err)
	}

	// oauth.Refresh takes no context, so the request is bound to ctx through
	// the client it is handed. Cancelling the request itself, rather than
	// abandoning it in a goroutine, matters here: GitHub rotates the refresh
	// token on use, so an abandoned call that still succeeded would consume
	// the stored token, and the next tick's bad_refresh_token would wipe the
	// secret — credential loss caused by an ordinary daemon shutdown.
	tok, err := oauth.Refresh(oauth.RefreshOptions{
		Host:         host,
		ClientID:     githubClientID(settings),
		RefreshToken: refresh,
		HTTPClient:   ctxPoster{ctx: ctx, client: client},
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, oauth.ErrRefreshTokenInvalid) {
			return nil, fmt.Errorf("github refresh rejected: %w", ErrRevoked)
		}
		return nil, fmt.Errorf("github refresh: %w", err)
	}

	// The secret already proved this credential expires, so a response that
	// omits expires_in must not be read as "never expires": githubCredential
	// would drop the refresh fields, the RefreshManager would then skip the
	// secret as legacy, and the token would die hours later with nothing
	// prompting a re-enrol. Assume the previous lifetime instead.
	if tok.ExpiresIn <= 0 {
		tok.ExpiresIn = previousLifetime(existing)
	}

	out := githubCredential(tok, e.clock())
	// Preserve the identity resolved at enrolment; the token endpoint does
	// not return it and a /user call on every rotation is waste.
	if user := existing["user"]; user != "" {
		out["user"] = user
	}
	return out, nil
}

// ctxPoster adapts an *http.Client to the PostForm-only interface cli/oauth
// accepts, binding every request to ctx.
type ctxPoster struct {
	ctx    context.Context
	client *http.Client
}

func (p ctxPoster) PostForm(u string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(p.ctx, http.MethodPost, u, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return p.client.Do(req)
}

// requireSecureTokenEndpoint refuses to send a refresh token in cleartext.
// The device flow tolerates an http:// host (GHES behind a TLS-terminating
// proxy on loopback, say), but a refresh is different twice over: the token
// it carries is long-lived, and an on-path forger of the error response
// could make dotvault delete the secret. Loopback stays allowed.
func requireSecureTokenEndpoint(hostURL string) error {
	u, err := url.Parse(hostURL)
	if err != nil {
		return fmt.Errorf("parse github host: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if ip := net.ParseIP(u.Hostname()); (ip != nil && ip.IsLoopback()) || u.Hostname() == "localhost" {
		return nil
	}
	return fmt.Errorf("github refresh refuses a non-https host %q", u.Host)
}

// previousLifetime is the access-token lifetime the existing secret records,
// falling back to GitHub's documented eight hours when it cannot be read.
func previousLifetime(existing map[string]string) time.Duration {
	issued, err1 := time.Parse(time.RFC3339, existing["issued_at"])
	expires, err2 := time.Parse(time.RFC3339, existing["expires_at"])
	if err1 == nil && err2 == nil && expires.After(issued) {
		return expires.Sub(issued)
	}
	return githubDefaultTokenLifetime
}

func fetchGitHubUser(ctx context.Context, client *http.Client, hostURL, token string) (string, error) {
	normalizedHostURL := strings.TrimRight(hostURL, "/")

	var userURL string
	if normalizedHostURL == githubDefaultHost {
		userURL = "https://api.github.com/user"
	} else {
		userURL = normalizedHostURL + "/api/v3/user"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api status %d", resp.StatusCode)
	}

	var data struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	return data.Login, nil
}
