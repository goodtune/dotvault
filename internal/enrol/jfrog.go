package enrol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
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
)

// JFrogEngine performs a JFrog Platform browser-based web login exchange,
// mirroring the flow used by `jf login` in jfrog-cli.
type JFrogEngine struct {
	// overridable for tests
	httpClient   *http.Client
	pollInterval time.Duration
	maxWait      time.Duration
}

func (e *JFrogEngine) Name() string { return "JFrog" }

// Fields lists the Vault KV fields this engine writes. access_token is the
// only strictly-required credential; the other fields are identity metadata
// needed to render a jfrog-cli config file.
func (e *JFrogEngine) Fields() []string {
	return []string{"access_token", "url", "server_id"}
}

func (e *JFrogEngine) Run(ctx context.Context, settings map[string]any, io IO) (map[string]string, error) {
	platformURL, ok := settings["url"].(string)
	if !ok || strings.TrimSpace(platformURL) == "" {
		return nil, fmt.Errorf("jfrog enrolment requires a non-empty 'url' setting (your JFrog Platform URL, e.g. https://mycompany.jfrog.io)")
	}
	platformURL = ensureScheme(strings.TrimRight(platformURL, "/"))

	clientName := jfrogDefaultClientName
	if v, ok := settings["client_name"].(string); ok && v != "" {
		clientName = v
	}

	clientCode := jfrogDefaultClientCode
	if v, ok := settings["client_code"].(string); ok && v != "" {
		clientCode = v
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

	// Step 3: poll for the token.
	pollInterval := e.pollInterval
	if pollInterval == 0 {
		pollInterval = jfrogDefaultPollInterval
	}
	maxWait := e.maxWait
	if maxWait == 0 {
		maxWait = jfrogDefaultMaxWait
	}

	fmt.Fprintf(io.Out, "⠼ Waiting for authentication...\n")
	token, err := jfrogPollForToken(ctx, client, platformURL, session, pollInterval, maxWait)
	if err != nil {
		return nil, err
	}
	if token.AccessToken == "" {
		return nil, fmt.Errorf("jfrog returned empty access token after web login")
	}

	user := extractUsernameFromJWT(token.AccessToken)

	result := map[string]string{
		"access_token": token.AccessToken,
		"url":          platformURL,
		"server_id":    serverID,
	}
	if token.RefreshToken != "" {
		result["refresh_token"] = token.RefreshToken
	}
	if token.TokenType != "" {
		result["token_type"] = token.TokenType
	}
	if token.Scope != "" {
		result["scope"] = token.Scope
	}
	if token.ExpiresIn != nil {
		result["expires_in"] = fmt.Sprintf("%d", *token.ExpiresIn)
	}
	if user != "" {
		result["user"] = user
	}

	return result, nil
}

// ensureScheme prepends https:// if the URL has no scheme.
func ensureScheme(u string) string {
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	return "https://" + u
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

	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return jfrogCommonTokenParams{}, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return jfrogCommonTokenParams{}, err
		}
		body, _ := readAndClose(resp)

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

		select {
		case <-ctx.Done():
			return jfrogCommonTokenParams{}, ctx.Err()
		case <-time.After(interval):
		}
	}
}

func readAndClose(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(resp.Body)
	return buf.Bytes(), err
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
