package enrol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/config"
)

const (
	// jfrogDefaultClientName is the label JFrog CLI uses to identify itself
	// to the JFrog Platform browser-based web login flow.
	jfrogDefaultClientName = "JFrog-CLI"
	// jfrogDefaultClientCode is the jfClientCode query parameter JFrog CLI
	// always sends (a constant "1" in the upstream source).
	jfrogDefaultClientCode = "1"
)

const (
	jfrogDefaultPollInterval = 3 * time.Second
	jfrogDefaultMaxWait      = 5 * time.Minute
	// jfrogDefaultTokenTTL is the default dotvault-minted access token
	// lifetime. 60d is considerably shorter than JFrog's own 1-year default
	// and reflects the assumption that dotvault users are more often admins
	// who should see tighter rotation windows.
	jfrogDefaultTokenTTL = 60 * 24 * time.Hour
)

// JFrogEngine performs a JFrog Platform browser-based web login exchange,
// mirroring the flow used by `jf login` in jfrog-cli. After the web login
// completes, the engine mints a second, dotvault-owned refreshable token
// with a shorter TTL; the bootstrap token from the web login is discarded.
type JFrogEngine struct {
	// overridable for tests
	httpClient   *http.Client
	pollInterval time.Duration
	maxWait      time.Duration
	// now is injected for deterministic issued_at/expires_at timestamps.
	now func() time.Time
}

func (e *JFrogEngine) Name() string { return "JFrog" }

// Fields lists the Vault KV fields this engine requires for a complete
// enrolment: access_token drives the CLI config, refresh_token powers
// the rotation cycle, url+server_id render the jfrog-cli.conf.v6 template,
// and issued_at+expires_at drive the half-life refresh decision.
//
// `user` is intentionally NOT listed: the engine writes it when it can be
// extracted from the access-token JWT subject, but JFrog reference
// (non-JWT) tokens don't expose a parseable subject. Making user
// mandatory would have `enrol.Manager.HasAllFields` reject otherwise-good
// enrolments with reference-token deployments. GitHub's engine takes the
// same approach — its `user` value is written when available but isn't
// required for `HasAllFields`.
func (e *JFrogEngine) Fields() []string {
	return []string{
		"access_token",
		"refresh_token",
		"url",
		"server_id",
		"issued_at",
		"expires_at",
	}
}

// clock returns the current time via the engine's injected clock (or
// time.Now if none is set).
func (e *JFrogEngine) clock() time.Time {
	if e.now != nil {
		return e.now()
	}
	return time.Now().UTC()
}

// resolveTokenTTL resolves the configured token_ttl setting against the
// engine default. Returns an error for non-string or unparseable values.
// The 10-minute floor is enforced at config-load time; here we just parse.
func resolveTokenTTL(settings map[string]any) (time.Duration, error) {
	raw, ok := settings["token_ttl"]
	if !ok {
		return jfrogDefaultTokenTTL, nil
	}
	s, ok := raw.(string)
	if !ok {
		return 0, fmt.Errorf("jfrog token_ttl must be a string, got %T", raw)
	}
	d, err := config.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("parse jfrog token_ttl %q: %w", s, err)
	}
	return d, nil
}

func (e *JFrogEngine) Run(ctx context.Context, settings map[string]any, io IO) (map[string]string, error) {
	rawPlatformURL, ok := settings["url"].(string)
	if !ok {
		return nil, fmt.Errorf("jfrog enrolment requires a non-empty 'url' setting (your JFrog Platform URL, e.g. https://mycompany.jfrog.io)")
	}
	platformURL, err := normalizeJFrogPlatformURL(rawPlatformURL)
	if err != nil {
		return nil, err
	}

	clientName := jfrogDefaultClientName
	if v, ok := settings["client_name"].(string); ok && v != "" {
		clientName = v
	}

	clientCode := jfrogDefaultClientCode
	if v, ok := settings["client_code"].(string); ok && v != "" {
		clientCode = v
	}

	ttl, err := resolveTokenTTL(settings)
	if err != nil {
		return nil, err
	}

	serverID, err := deduceJFrogServerID(platformURL)
	if err != nil {
		return nil, fmt.Errorf("parse jfrog url: %w", err)
	}

	session, err := newUUIDv4()
	if err != nil {
		return nil, fmt.Errorf("generate session uuid: %w", err)
	}

	client := e.httpClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	// Step 1: tell the JFrog Access service we're about to start a web login.
	if err := jfrogSendLoginRequest(ctx, client, platformURL, session); err != nil {
		return nil, fmt.Errorf("initiate jfrog web login: %w", err)
	}

	// Step 2: present the URL to the user; they authenticate via the browser
	// and enter the short confirmation code (last 4 chars of the UUID).
	confirmCode := session[len(session)-4:]
	loginURL := fmt.Sprintf(
		"%s/ui/login?jfClientSession=%s&jfClientName=%s&jfClientCode=%s",
		platformURL,
		url.QueryEscape(session),
		url.QueryEscape(clientName),
		url.QueryEscape(clientCode),
	)

	copyToClipboard(confirmCode)
	fmt.Fprintf(io.Out, "! First, copy your one-time code: %s\n", confirmCode)
	fmt.Fprintf(io.Out, "  (you will be prompted for this after signing in)\n")
	if io.Browser == nil {
		fmt.Fprintf(io.Out, "- Please open %s in your browser.\n", loginURL)
	} else if browseErr := io.Browser(loginURL); browseErr != nil {
		fmt.Fprintf(io.Out, "  (could not open browser automatically: %v)\n", browseErr)
		fmt.Fprintf(io.Out, "- Please open %s manually.\n", loginURL)
	} else {
		fmt.Fprintf(io.Out, "✓ Opened %s in browser\n", loginURL)
	}

	// Step 3: poll for the bootstrap token.
	pollInterval := e.pollInterval
	if pollInterval == 0 {
		pollInterval = jfrogDefaultPollInterval
	}
	maxWait := e.maxWait
	if maxWait == 0 {
		maxWait = jfrogDefaultMaxWait
	}

	fmt.Fprintf(io.Out, "⠼ Waiting for authentication...\n")
	bootstrap, err := jfrogPollForToken(ctx, client, platformURL, session, pollInterval, maxWait)
	if err != nil {
		return nil, err
	}
	if bootstrap.AccessToken == "" {
		return nil, fmt.Errorf("jfrog returned empty access token after web login")
	}

	// Step 4: exchange the bootstrap token for a dotvault-owned,
	// refreshable token with the configured TTL. The bootstrap token is
	// discarded — it is never stored or reused.
	fmt.Fprintf(io.Out, "⠼ Minting dotvault-owned access token (ttl=%s)...\n", ttl)
	minted, err := jfrogMintRefreshableToken(ctx, client, platformURL, bootstrap.AccessToken, ttl)
	if err != nil {
		return nil, fmt.Errorf("mint jfrog access token: %w", err)
	}
	if minted.AccessToken == "" || minted.RefreshToken == "" {
		return nil, fmt.Errorf("jfrog mint returned incomplete token pair (access_token present=%t, refresh_token present=%t)",
			minted.AccessToken != "", minted.RefreshToken != "")
	}

	user := extractUsernameFromJWT(minted.AccessToken)
	if user == "" {
		// Fall back to the bootstrap token's subject if the minted JWT
		// doesn't carry a parseable username. This keeps compatibility
		// with odd JFrog deployments while still preferring the minted
		// identity when available.
		user = extractUsernameFromJWT(bootstrap.AccessToken)
	}

	now := e.clock()
	result := map[string]string{
		"access_token":  minted.AccessToken,
		"refresh_token": minted.RefreshToken,
		"url":           platformURL,
		"server_id":     serverID,
		"user":          user,
		"issued_at":     now.UTC().Format(time.RFC3339),
		"expires_at":    now.Add(ttl).UTC().Format(time.RFC3339),
	}
	return result, nil
}

// Refresh rotates a dotvault-owned JFrog token pair. Returns the same 7
// fields that Run returns so the caller can atomically replace the Vault
// secret. A 401/403 from the access service means the refresh token itself
// has been revoked upstream — callers should treat that as permanent and
// force a fresh enrolment.
func (e *JFrogEngine) Refresh(ctx context.Context, settings map[string]any, existing map[string]string) (map[string]string, error) {
	rawPlatformURL, ok := settings["url"].(string)
	if !ok {
		return nil, fmt.Errorf("jfrog refresh requires a non-empty 'url' setting")
	}
	platformURL, err := normalizeJFrogPlatformURL(rawPlatformURL)
	if err != nil {
		return nil, err
	}

	access := existing["access_token"]
	refresh := existing["refresh_token"]
	if access == "" || refresh == "" {
		return nil, fmt.Errorf("jfrog refresh requires both access_token and refresh_token in the existing secret")
	}

	ttl, err := resolveTokenTTL(settings)
	if err != nil {
		return nil, err
	}

	serverID, err := deduceJFrogServerID(platformURL)
	if err != nil {
		return nil, fmt.Errorf("parse jfrog url: %w", err)
	}

	client := e.httpClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	rotated, err := jfrogExchangeRefreshToken(ctx, client, platformURL, access, refresh)
	if err != nil {
		return nil, err
	}
	if rotated.AccessToken == "" || rotated.RefreshToken == "" {
		return nil, fmt.Errorf("jfrog refresh returned incomplete token pair")
	}

	user := extractUsernameFromJWT(rotated.AccessToken)
	if user == "" {
		// The refresh endpoint may return a reference (non-JWT) token;
		// fall back to the username we already had on file rather than
		// losing it on every rotation.
		user = existing["user"]
	}

	now := e.clock()
	return map[string]string{
		"access_token":  rotated.AccessToken,
		"refresh_token": rotated.RefreshToken,
		"url":           platformURL,
		"server_id":     serverID,
		"user":          user,
		"issued_at":     now.UTC().Format(time.RFC3339),
		"expires_at":    now.Add(ttl).UTC().Format(time.RFC3339),
	}, nil
}

// ensureScheme prepends https:// if the URL has no scheme.
func ensureScheme(u string) string {
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	return "https://" + u
}

// normalizeJFrogPlatformURL parses `raw`, enforces that it is a
// scheme+host-only URL (no path, query, or fragment), and returns the
// canonical string form. JFrog API paths are concatenated directly onto
// this value, so any embedded path would route requests incorrectly and
// a query/fragment would appear verbatim in the stored template.
func normalizeJFrogPlatformURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("jfrog enrolment requires a non-empty 'url' setting (your JFrog Platform URL, e.g. https://mycompany.jfrog.io)")
	}
	u, err := url.Parse(ensureScheme(raw))
	if err != nil {
		return "", fmt.Errorf("parse jfrog url: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("jfrog url must use http or https, got %q", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("jfrog url must include a host: %q", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("jfrog url must not include a query or fragment: %q", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("jfrog url must be the platform base URL without a path (got %q)", raw)
	}
	return (&url.URL{Scheme: scheme, Host: u.Host}).String(), nil
}

// deduceJFrogServerID extracts a short server identifier from the platform
// URL hostname, matching the logic in jfrog-cli-core/general/utils.go.
// e.g. https://mycompany.jfrog.io/ -> "mycompany"; IP addresses -> "default-server".
func deduceJFrogServerID(platformURL string) (string, error) {
	u, err := url.Parse(platformURL)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("platform url %q has no hostname", platformURL)
	}
	if net.ParseIP(host) != nil {
		return "default-server", nil
	}
	return strings.Split(host, ".")[0], nil
}

// jfrogCommonTokenParams mirrors jfrog-client-go's auth.CommonTokenParams.
type jfrogCommonTokenParams struct {
	Scope        string `json:"scope,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	ExpiresIn    *uint  `json:"expires_in,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// jfrogSendLoginRequest performs the initial POST to the JFrog Access service
// telling it to prepare a web login session for our UUID.
func jfrogSendLoginRequest(ctx context.Context, client *http.Client, platformURL, session string) error {
	endpoint := platformURL + "/access/api/v2/authentication/jfrog_client_login/request"
	body, err := json.Marshal(struct {
		Session string `json:"session"`
	}{Session: session})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jfrog login request returned status %d (web login may be unavailable; requires Artifactory 7.64.0 or newer)", resp.StatusCode)
	}
	return nil
}

// jfrogPollForToken polls the token endpoint. A 400 means "not yet"; a 200
// means we have the token. Any other status is a hard error.
func jfrogPollForToken(ctx context.Context, client *http.Client, platformURL, session string, interval, max time.Duration) (jfrogCommonTokenParams, error) {
	endpoint := fmt.Sprintf("%s/access/api/v2/authentication/jfrog_client_login/token/%s", platformURL, url.PathEscape(session))
	deadline := time.Now().Add(max)

	// Reusable timer avoids leaking a new timer on every loop iteration
	// (each `time.After(interval)` allocates one that lives until it fires,
	// even if we return early on ctx cancellation or a hard error).
	timer := time.NewTimer(0)
	if !timer.Stop() {
		<-timer.C // drain the initial fire so the first iteration goes straight to the HTTP call
	}
	defer timer.Stop()

	first := true
	for {
		// On the first iteration, skip the wait and poll immediately.
		if !first {
			timer.Reset(interval)
			select {
			case <-ctx.Done():
				return jfrogCommonTokenParams{}, ctx.Err()
			case <-timer.C:
			}
		}
		first = false

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return jfrogCommonTokenParams{}, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return jfrogCommonTokenParams{}, err
		}
		body, err := readAndClose(resp)
		if err != nil {
			return jfrogCommonTokenParams{}, fmt.Errorf("read jfrog token poll response: %w", err)
		}

		switch resp.StatusCode {
		case http.StatusOK:
			var token jfrogCommonTokenParams
			if err := json.Unmarshal(body, &token); err != nil {
				return jfrogCommonTokenParams{}, fmt.Errorf("decode jfrog token response: %w", err)
			}
			return token, nil
		case http.StatusBadRequest:
			// Not yet authenticated; keep polling.
		default:
			return jfrogCommonTokenParams{}, fmt.Errorf("jfrog token poll returned unexpected status %d", resp.StatusCode)
		}

		if time.Now().After(deadline) {
			return jfrogCommonTokenParams{}, fmt.Errorf("timed out waiting for jfrog web login after %s", max)
		}
	}
}

// jfrogMintRefreshableToken exchanges the bootstrap access token produced
// by the web-login flow for a dotvault-owned, refreshable token pair with
// the caller-specified TTL. Called once at enrolment time; the bootstrap
// token is discarded after this call returns.
//
// Endpoint: POST {platform}/access/api/v2/tokens with a bearer auth header.
// Body: {"expires_in": <seconds>, "refreshable": true, "scope": "applied-permissions/user"}.
//
// Non-admin users can successfully mint refreshable tokens for themselves
// with any non-zero TTL; the admin-only restriction in JFrog only applies
// to expires_in=0 (never-expiring tokens), which we intentionally do not use.
func jfrogMintRefreshableToken(ctx context.Context, client *http.Client, platformURL, bootstrapToken string, ttl time.Duration) (jfrogCommonTokenParams, error) {
	endpoint := platformURL + "/access/api/v2/tokens"
	body, err := json.Marshal(struct {
		ExpiresIn   int64  `json:"expires_in"`
		Refreshable bool   `json:"refreshable"`
		Scope       string `json:"scope"`
	}{
		ExpiresIn:   int64(ttl.Seconds()),
		Refreshable: true,
		Scope:       "applied-permissions/user",
	})
	if err != nil {
		return jfrogCommonTokenParams{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return jfrogCommonTokenParams{}, err
	}
	req.Header.Set("Authorization", "Bearer "+bootstrapToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return jfrogCommonTokenParams{}, err
	}
	respBody, err := readAndClose(resp)
	if err != nil {
		return jfrogCommonTokenParams{}, fmt.Errorf("read jfrog mint response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return jfrogCommonTokenParams{}, fmt.Errorf("jfrog mint returned status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}
	var token jfrogCommonTokenParams
	if err := json.Unmarshal(respBody, &token); err != nil {
		return jfrogCommonTokenParams{}, fmt.Errorf("decode jfrog mint response: %w", err)
	}
	return token, nil
}

// jfrogExchangeRefreshToken rotates an existing token pair. JFrog's
// refresh endpoint ROTATES the refresh token on every successful call —
// the old refresh_token is invalidated immediately, so callers must
// persist the returned pair atomically before acknowledging success.
//
// Endpoint: POST {platform}/access/api/v1/tokens with form-urlencoded body
// grant_type=refresh_token&access_token=<old>&refresh_token=<old>.
//
// 401/403 → ErrRevoked (token has been revoked upstream; caller should
// discard the secret and force a fresh enrolment). Any other error is
// transient and the caller should keep the existing secret for retry.
func jfrogExchangeRefreshToken(ctx context.Context, client *http.Client, platformURL, accessToken, refreshToken string) (jfrogCommonTokenParams, error) {
	endpoint := platformURL + "/access/api/v1/tokens"
	form := url.Values{
		"grant_type":    []string{"refresh_token"},
		"access_token":  []string{accessToken},
		"refresh_token": []string{refreshToken},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return jfrogCommonTokenParams{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return jfrogCommonTokenParams{}, err
	}
	respBody, err := readAndClose(resp)
	if err != nil {
		return jfrogCommonTokenParams{}, fmt.Errorf("read jfrog refresh response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var token jfrogCommonTokenParams
		if err := json.Unmarshal(respBody, &token); err != nil {
			return jfrogCommonTokenParams{}, fmt.Errorf("decode jfrog refresh response: %w", err)
		}
		return token, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return jfrogCommonTokenParams{}, fmt.Errorf("jfrog refresh rejected (status %d): %w", resp.StatusCode, ErrRevoked)
	default:
		return jfrogCommonTokenParams{}, fmt.Errorf("jfrog refresh returned status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}
}

// truncate trims s to maxLen runes with an ellipsis, for error logs. Rune-
// aware rather than byte-aware so a truncated UTF-8 multi-byte sequence
// doesn't emit mojibake in the log line.
func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "…"
}

// readAndClose reads the response body (capped at 1 MB to limit exposure
// to unexpectedly large payloads from a user-configured URL) and closes
// the body. 1 MB is generous for any JFrog API response; legitimate
// token responses are a few KB at most.
func readAndClose(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	const maxBody = 1 << 20 // 1 MB
	limited := io.LimitReader(resp.Body, maxBody+1)
	buf := new(bytes.Buffer)
	n, err := buf.ReadFrom(limited)
	if err != nil {
		return nil, err
	}
	if n > maxBody {
		return nil, fmt.Errorf("response body exceeds %d bytes", maxBody)
	}
	return buf.Bytes(), nil
}

// extractUsernameFromJWT parses a JFrog access token JWT and returns the
// username portion of the subject claim, mirroring
// jfrog-client-go/auth.ExtractUsernameFromAccessToken. Returns "" for
// non-JWT tokens (e.g. reference tokens).
func extractUsernameFromJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Try standard encoding as a fallback.
		payload, err = base64.RawStdEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	sub := claims.Subject
	if sub == "" {
		return ""
	}
	// Subjects like "jfrt@01g.../users/alice" or ".../users/alice" have the
	// username as the final path segment.
	if strings.HasPrefix(sub, "jfrt@") || strings.Contains(sub, "/users/") {
		if idx := strings.LastIndex(sub, "/"); idx >= 0 {
			return sub[idx+1:]
		}
	}
	// Otherwise (OIDC-groups-scoped tokens etc.) the subject is the username.
	return sub
}

// newUUIDv4 generates an RFC-4122 version-4 UUID without pulling in a
// new dependency. Matches the format that jfrog-cli sends as jfClientSession.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
