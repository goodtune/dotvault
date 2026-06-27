package enrol

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/httpproxy"
)

const (
	// langsmithDefaultClientID is the public OAuth client ID the LangSmith
	// CLI uses for `langsmith auth login`. It is a public client — no secret —
	// authenticating via the OAuth 2.0 device authorization grant.
	// (langsmith-cli: internal/cmd/login.go, const oauthClientID.)
	langsmithDefaultClientID = "langsmith-cli"

	// langsmithDefaultAPIURL is the LangSmith SaaS API endpoint, matching the
	// langsmith SDK's default LANGSMITH_ENDPOINT. The OAuth endpoints are
	// derived from it (see langsmithResource).
	langsmithDefaultAPIURL = "https://api.smith.langchain.com"

	// langsmithDevicePath/langsmithTokenPath are the device-flow endpoints,
	// rooted at the OAuth resource (the api_url with any /api/v1 suffix
	// stripped). (langsmith-cli: /oauth/device/code and /oauth/token.)
	langsmithDevicePath = "/oauth/device/code"
	langsmithTokenPath  = "/oauth/token"

	// langsmithDeviceGrant is the RFC 8628 device-flow grant type sent when
	// polling the token endpoint for the user's approval.
	langsmithDeviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

	// langsmithMinPollInterval is the floor for the token-poll cadence. The
	// device-code response advertises an interval, but RFC 8628 mandates a
	// 5-second minimum and dotvault never polls faster than the server asks.
	langsmithMinPollInterval = 5 * time.Second

	// langsmithDefaultLoginTimeout caps how long Run waits for the user to
	// finish the browser approval when the device-code response carries no
	// (or an implausible) expires_in. Generous because LangSmith logins
	// routinely route through SSO/MFA.
	langsmithDefaultLoginTimeout = 15 * time.Minute
)

// LangSmithEngine performs a LangSmith OAuth device-flow login, mirroring
// `langsmith auth login`: it requests a device/user code, has the user
// approve it in a browser, and polls the token endpoint until LangSmith
// issues an access/refresh pair. LangSmith access tokens are short-lived, so
// the engine implements Refresher — the daemon's RefreshManager rotates the
// pair at its half-life and dotvault owns the rotation, exactly as it does
// for JFrog and Databricks.
type LangSmithEngine struct {
	// httpClient is used for the device-code request, the token poll, and the
	// refresh. Overridable for tests. When nil, a proxy-aware client is built
	// per-call from the enrolment settings.
	httpClient *http.Client
	// now is injected for deterministic issued_at/expires_at timestamps.
	now func() time.Time
	// loginTimeout overrides the device-code expiry / default timeout in tests.
	loginTimeout time.Duration
	// minInterval overrides langsmithMinPollInterval in tests so the poll loop
	// doesn't sleep whole seconds.
	minInterval time.Duration
	// slowDownStep overrides the RFC 8628 slow_down back-off increment (5s) in
	// tests so the slow_down branch can be exercised without a real 5s wait.
	slowDownStep time.Duration
}

func (e *LangSmithEngine) Name() string { return "LangSmith" }

// Fields lists the Vault KV fields a complete enrolment must carry.
// access_token drives the rendered credential, refresh_token powers the
// rotation cycle, api_url identifies the endpoint, and issued_at+expires_at
// drive the half-life refresh decision. workspace_id is an optional
// passthrough and is intentionally not required (see Run).
func (e *LangSmithEngine) Fields() []string {
	return []string{"access_token", "refresh_token", "api_url", "issued_at", "expires_at"}
}

func (e *LangSmithEngine) clock() time.Time {
	if e.now != nil {
		return e.now()
	}
	return time.Now().UTC()
}

func (e *LangSmithEngine) client(settings map[string]any) (*http.Client, error) {
	if e.httpClient != nil {
		return e.httpClient, nil
	}
	return httpproxy.ClientFromSettings(settings, 30*time.Second)
}

func (e *LangSmithEngine) pollFloor() time.Duration {
	if e.minInterval > 0 {
		return e.minInterval
	}
	return langsmithMinPollInterval
}

func (e *LangSmithEngine) slowDownIncrement() time.Duration {
	if e.slowDownStep > 0 {
		return e.slowDownStep
	}
	return 5 * time.Second
}

func (e *LangSmithEngine) Run(ctx context.Context, settings map[string]any, io IO) (map[string]string, error) {
	resource, err := langsmithAPIURLFromSettings(settings)
	if err != nil {
		return nil, err
	}
	clientID := langsmithClientID(settings)
	workspaceID, err := langsmithWorkspaceID(settings)
	if err != nil {
		return nil, err
	}

	client, err := e.client(settings)
	if err != nil {
		return nil, fmt.Errorf("configure http client: %w", err)
	}

	// Step 1: request a device + user code.
	dev, err := langsmithRequestDeviceCode(ctx, client, resource, clientID)
	if err != nil {
		return nil, fmt.Errorf("langsmith device code request: %w", err)
	}

	// The browser-open target prefers verification_uri_complete (which
	// pre-fills the user code) when LangSmith returns it, falling back to the
	// bare verification_uri.
	browseURL := dev.VerificationURI
	if dev.VerificationURIComplete != "" {
		browseURL = dev.VerificationURIComplete
	}

	// Present the code + verification URL. The web enrolment card keys its
	// device-flow rendering off the "! First, copy your one-time code: X" line
	// plus an https URL, so the same output drives both the CLI and the web UI
	// (the daemon never opens a browser in web mode — io.Browser is nil there).
	copyToClipboard(dev.UserCode)
	fmt.Fprintf(io.Out, "! First, copy your one-time code: %s\n", dev.UserCode)
	if io.Browser == nil {
		fmt.Fprintf(io.Out, "- Please open %s in your browser and enter the code.\n", browseURL)
	} else {
		in := io.In
		if in == nil {
			in = os.Stdin
		}
		fmt.Fprintf(io.Out, "- Press Enter to open %s in your browser... ", browseURL)
		bufio.NewScanner(in).Scan()
		if browseErr := io.Browser(browseURL); browseErr != nil {
			fmt.Fprintf(io.Out, "  (could not open browser automatically: %v)\n", browseErr)
			fmt.Fprintf(io.Out, "- Please open %s manually.\n", browseURL)
		} else {
			fmt.Fprintf(io.Out, "✓ Opened %s in browser\n", browseURL)
		}
	}
	fmt.Fprintf(io.Out, "⠼ Waiting for authentication...\n")

	// Step 2: poll the token endpoint until the user approves (or we time out).
	tok, err := e.pollForToken(ctx, client, resource, clientID, dev)
	if err != nil {
		return nil, err
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		return nil, fmt.Errorf("langsmith token response incomplete (access present=%t, refresh present=%t); dotvault needs a refresh token to keep the credential rotated",
			tok.AccessToken != "", tok.RefreshToken != "")
	}

	now := e.clock()
	result := map[string]string{
		"access_token":  tok.AccessToken,
		"refresh_token": tok.RefreshToken,
		"api_url":       resource,
		"issued_at":     now.UTC().Format(time.RFC3339),
		"expires_at":    now.Add(langsmithTokenLifetime(tok)).UTC().Format(time.RFC3339),
	}
	if workspaceID != "" {
		result["workspace_id"] = workspaceID
	}
	return result, nil
}

// Refresh rotates a LangSmith access/refresh token pair past its half-life.
// A 401/403 from the token endpoint means the refresh token has been revoked
// upstream (ErrRevoked → re-enrol); any other failure is transient.
func (e *LangSmithEngine) Refresh(ctx context.Context, settings map[string]any, existing map[string]string) (map[string]string, error) {
	resource, err := langsmithAPIURLFromSettings(settings)
	if err != nil {
		return nil, err
	}
	clientID := langsmithClientID(settings)

	refresh := existing["refresh_token"]
	if refresh == "" {
		return nil, fmt.Errorf("langsmith refresh requires a refresh_token in the existing secret")
	}

	client, err := e.client(settings)
	if err != nil {
		return nil, fmt.Errorf("configure http client: %w", err)
	}

	tok, status, err := langsmithTokenRequest(ctx, client, resource+langsmithTokenPath, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"resource":      {resource},
		"refresh_token": {refresh},
	})
	if err != nil {
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			return nil, fmt.Errorf("langsmith refresh rejected (status %d): %w", status, ErrRevoked)
		}
		return nil, fmt.Errorf("langsmith refresh (status %d): %w", status, err)
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("langsmith refresh returned no access token")
	}

	// LangSmith may rotate the refresh token. Adopt a new one when returned;
	// otherwise keep the existing token.
	newRefresh := tok.RefreshToken
	if newRefresh == "" {
		newRefresh = refresh
	}

	now := e.clock()
	out := map[string]string{
		"access_token":  tok.AccessToken,
		"refresh_token": newRefresh,
		"api_url":       resource,
		"issued_at":     now.UTC().Format(time.RFC3339),
		"expires_at":    now.Add(langsmithTokenLifetime(tok)).UTC().Format(time.RFC3339),
	}
	// Preserve the optional workspace_id passthrough across rotations.
	if ws := existing["workspace_id"]; ws != "" {
		out["workspace_id"] = ws
	}
	return out, nil
}

// langsmithDeviceResp is the device authorization response (RFC 8628).
type langsmithDeviceResp struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// langsmithRequestDeviceCode POSTs the device authorization request. LangSmith
// keys the device code to the client_id and the resource (the API base), so
// both are sent; no scope parameter is sent, matching the CLI.
func langsmithRequestDeviceCode(ctx context.Context, client *http.Client, resource, clientID string) (langsmithDeviceResp, error) {
	form := url.Values{
		"client_id": {clientID},
		"resource":  {resource},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resource+langsmithDevicePath, strings.NewReader(form.Encode()))
	if err != nil {
		return langsmithDeviceResp{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return langsmithDeviceResp{}, err
	}
	body, err := readAndClose(resp)
	if err != nil {
		return langsmithDeviceResp{}, fmt.Errorf("read device code response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return langsmithDeviceResp{}, fmt.Errorf("device code endpoint returned status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var dev langsmithDeviceResp
	if err := json.Unmarshal(body, &dev); err != nil {
		return langsmithDeviceResp{}, fmt.Errorf("decode device code response: %w", err)
	}
	if dev.DeviceCode == "" || dev.UserCode == "" || dev.VerificationURI == "" {
		return langsmithDeviceResp{}, fmt.Errorf("device code response missing device_code, user_code, or verification_uri")
	}
	return dev, nil
}

// pollForToken polls the token endpoint on the device-flow cadence until the
// user approves (200 + tokens), denies, or the device code expires. It honours
// authorization_pending (keep waiting) and slow_down (back off by 5s), per
// RFC 8628.
func (e *LangSmithEngine) pollForToken(ctx context.Context, client *http.Client, resource, clientID string, dev langsmithDeviceResp) (langsmithTokenResp, error) {
	interval := time.Duration(dev.Interval) * time.Second
	if floor := e.pollFloor(); interval < floor {
		interval = floor
	}

	timeout := e.loginTimeout
	if timeout == 0 {
		if dev.ExpiresIn > 0 {
			timeout = time.Duration(dev.ExpiresIn) * time.Second
		} else {
			timeout = langsmithDefaultLoginTimeout
		}
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	form := url.Values{
		"grant_type":  {langsmithDeviceGrant},
		"client_id":   {clientID},
		"device_code": {dev.DeviceCode},
		"resource":    {resource},
	}

	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				return langsmithTokenResp{}, ctx.Err()
			}
			return langsmithTokenResp{}, fmt.Errorf("timed out waiting for langsmith login after %s", timeout)
		case <-timer.C:
		}

		tok, status, err := langsmithTokenRequest(waitCtx, client, resource+langsmithTokenPath, form)
		if err == nil && status == http.StatusOK && tok.AccessToken != "" {
			return tok, nil
		}
		// If the deadline elapsed (or the parent ctx was cancelled) while the
		// request was in flight, the transport reports a generic "context
		// deadline exceeded". Normalise that to the same friendly timeout /
		// cancellation error the between-poll select branch returns, so the
		// outcome is deterministic regardless of where the clock ran out.
		if waitCtx.Err() != nil {
			if ctx.Err() != nil {
				return langsmithTokenResp{}, ctx.Err()
			}
			return langsmithTokenResp{}, fmt.Errorf("timed out waiting for langsmith login after %s", timeout)
		}
		switch tok.Error {
		case "authorization_pending":
			// User hasn't approved yet; keep waiting.
		case "slow_down":
			interval += e.slowDownIncrement()
		case "access_denied":
			return langsmithTokenResp{}, fmt.Errorf("langsmith login was denied")
		case "expired_token":
			return langsmithTokenResp{}, fmt.Errorf("langsmith device code expired before approval")
		default:
			// A transport error, an unexpected status, or an unrecognised
			// OAuth error are all fatal — there is nothing to keep polling for.
			// This also catches a 200 with an empty access token and no error
			// code (a malformed server response): it fails the success guard
			// above, carries no recognised tok.Error, and lands here.
			if err != nil {
				return langsmithTokenResp{}, fmt.Errorf("langsmith token poll (status %d): %w", status, err)
			}
			return langsmithTokenResp{}, fmt.Errorf("langsmith token poll returned unexpected status %d", status)
		}
		timer.Reset(interval)
	}
}

// langsmithTokenResp is the OAuth token endpoint response (RFC 6749) plus the
// error fields returned on a non-200.
type langsmithTokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// langsmithTokenRequest POSTs a form-encoded body to the token endpoint.
// LangSmith treats langsmith-cli as a public client, so credentials live in
// the body (no HTTP Basic). Returns the parsed response, the HTTP status (so
// callers can distinguish device-flow signals and revocation from transient
// errors), and an error on any non-200.
func langsmithTokenRequest(ctx context.Context, client *http.Client, tokenEndpoint string, form url.Values) (langsmithTokenResp, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return langsmithTokenResp{}, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return langsmithTokenResp{}, 0, err
	}
	body, err := readAndClose(resp)
	if err != nil {
		return langsmithTokenResp{}, resp.StatusCode, fmt.Errorf("read token response: %w", err)
	}

	var tok langsmithTokenResp
	if len(body) > 0 {
		// Tolerate a non-JSON error body (e.g. an HTML gateway page) — the
		// status code and raw snippet still make a useful error.
		_ = json.Unmarshal(body, &tok)
	}
	if resp.StatusCode != http.StatusOK {
		if tok.Error != "" {
			return tok, resp.StatusCode, fmt.Errorf("%s: %s", tok.Error, tok.ErrorDesc)
		}
		return tok, resp.StatusCode, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	return tok, resp.StatusCode, nil
}

// langsmithTokenLifetime returns the access-token lifetime from the response,
// defaulting to one hour when expires_in is absent or non-positive so the
// half-life refresh math stays sane against an unexpected response.
func langsmithTokenLifetime(tok langsmithTokenResp) time.Duration {
	if tok.ExpiresIn <= 0 {
		return time.Hour
	}
	return time.Duration(tok.ExpiresIn) * time.Second
}

// langsmithClientID returns the configured OAuth client ID, defaulting to
// langsmith-cli (the CLI's public app).
func langsmithClientID(settings map[string]any) string {
	if v, ok := settings["client_id"].(string); ok && v != "" {
		return v
	}
	return langsmithDefaultClientID
}

// langsmithWorkspaceID reads the optional workspace_id passthrough. It is
// written to the secret verbatim (for a rendered LANGSMITH_WORKSPACE_ID) but
// is not acquired during login and not required for completeness.
func langsmithWorkspaceID(settings map[string]any) (string, error) {
	raw, ok := settings["workspace_id"]
	if !ok {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("langsmith workspace_id must be a string, got %T", raw)
	}
	return strings.TrimSpace(s), nil
}

// langsmithAPIURLFromSettings reads the optional api_url setting (defaulting to
// the LangSmith SaaS endpoint) and returns the OAuth resource base.
func langsmithAPIURLFromSettings(settings map[string]any) (string, error) {
	raw, ok := settings["api_url"]
	if !ok {
		return langsmithResource(langsmithDefaultAPIURL)
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("langsmith api_url must be a string, got %T", raw)
	}
	if strings.TrimSpace(s) == "" {
		return langsmithResource(langsmithDefaultAPIURL)
	}
	return langsmithResource(s)
}

// langsmithResource validates `raw` as an https scheme+host URL and returns the
// OAuth resource base: the URL with a trailing slash and any trailing `/api/v1`
// suffix stripped. The `/api/v1` strip mirrors the LangSmith CLI's
// oauthResource — LANGSMITH_ENDPOINT is conventionally `.../api/v1`, but the
// OAuth endpoints are rooted at the host. https is required because the access
// token travels as a bearer header against this base.
func langsmithResource(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("langsmith api_url must not be empty")
	}
	// Detect an explicit scheme without mangling an unknown one: a bare host
	// (no "://") defaults to https, but "ftp://" / "http://" are parsed as-is
	// so the https check below rejects them rather than silently prepending
	// https in front of the foreign scheme.
	withScheme := raw
	if !strings.Contains(raw, "://") {
		withScheme = "https://" + raw
	}
	u, err := url.Parse(withScheme)
	if err != nil {
		return "", fmt.Errorf("parse langsmith api_url: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" {
		return "", fmt.Errorf("langsmith api_url must use https, got %q", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("langsmith api_url must include a host: %q", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("langsmith api_url must not include a query or fragment: %q", raw)
	}
	base := (&url.URL{Scheme: scheme, Host: u.Host, Path: u.Path}).String()
	base = strings.TrimRight(base, "/")
	base = strings.TrimSuffix(base, "/api/v1")
	base = strings.TrimRight(base, "/")
	return base, nil
}
