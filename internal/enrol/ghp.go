package enrol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/httpproxy"
)

const (
	// ghpDefaultPollInterval is the fallback poll cadence when the ghp
	// device-authorization response carries no (or a non-positive)
	// interval. It matches the server's documented minimum of 2s.
	ghpDefaultPollInterval = 2 * time.Second
	// ghpDefaultMaxWait is the fallback authorization window when the
	// device-authorization response carries no (or a non-positive)
	// expires_in. The ghp server defaults its device requests to a 10m TTL.
	ghpDefaultMaxWait = 10 * time.Minute
	// ghpSlowDownBump is how much the poll interval grows when the server
	// asks us to slow down, matching the RFC 8628 convention the ghp CLI uses.
	ghpSlowDownBump = 5 * time.Second
	// ghpMaxBackoff caps the poll interval when the server returns HTTP 429
	// without a Retry-After header.
	ghpMaxBackoff = 60 * time.Second
	// ghpSessionTokenPrefix is the prefix every ghp CLI session token
	// carries. The ghp CLI rejects anything else, so dotvault does too —
	// a token without it means the server returned the wrong credential.
	ghpSessionTokenPrefix = "ghpr_"
)

// GHPEngine performs the ghp CLI device-authorization flow against a
// self-hosted ghp server (github.com/goodtune/ghp). The flow is an
// RFC 8628-style device grant served entirely by the ghp server: dotvault
// asks for a device code, the user approves it in a browser (authenticating
// to ghp via GitHub there), and dotvault polls until the server hands back a
// CLI session token (prefix "ghpr_"). That session token plus the server URL
// are exactly the two fields ghp's own dotvault integration reads back out of
// Vault, so no further translation is needed downstream.
//
// The session token does not expire on a fixed schedule and ghp exposes no
// unattended refresh endpoint for it, so this engine deliberately does NOT
// implement Refresher — a revoked or rotated token is recovered by
// re-enrolling, the same model the GitHub engine uses for its OAuth token.
type GHPEngine struct {
	// overridable for tests
	httpClient   *http.Client
	pollInterval time.Duration // when set, overrides the server-supplied interval
	maxWait      time.Duration // when set, overrides the server-supplied expires_in
	slowDownBump time.Duration // when set, overrides ghpSlowDownBump
}

func (e *GHPEngine) Name() string { return "GitHub Proxy" }

// Fields lists the Vault KV fields a complete ghp enrolment requires.
// user_token is the "ghpr_" CLI session token; server_url is the ghp
// server it is valid against. Both names match the defaults ghp's own
// dotvault integration reads, so a stored secret is consumable as-is.
//
// `user` is intentionally NOT listed: the engine writes the resolved ghp
// username when the token endpoint returns it, but a server that omits it
// must not make an otherwise-good enrolment look incomplete — the same
// best-effort treatment GitHub/JFrog give their `user` field.
func (e *GHPEngine) Fields() []string {
	return []string{"user_token", "server_url"}
}

func (e *GHPEngine) Run(ctx context.Context, settings map[string]any, io IO) (map[string]string, error) {
	rawServerURL, ok := settings["url"].(string)
	if !ok {
		return nil, fmt.Errorf("ghp enrolment requires a non-empty 'url' setting (your ghp server URL, e.g. https://ghp.example.com)")
	}
	serverURL, err := normalizeGHPServerURL(rawServerURL)
	if err != nil {
		return nil, err
	}

	client := e.httpClient
	if client == nil {
		client, err = httpproxy.ClientFromSettings(settings, 30*time.Second)
		if err != nil {
			return nil, fmt.Errorf("configure http client: %w", err)
		}
	}

	// Step 1: start the device authorization and obtain the user code.
	start, err := ghpStartDeviceAuth(ctx, client, serverURL)
	if err != nil {
		return nil, fmt.Errorf("start ghp device authorization: %w", err)
	}

	verificationURL, err := resolveGHPVerificationURL(serverURL, start.VerificationURIComplete, start.VerificationURI)
	if err != nil {
		return nil, err
	}

	// Step 2: present the code + URL. The "! First, copy your one-time code"
	// line plus an https URL is the shape the web enrol card recognises as a
	// device-code flow (same as GitHub/JFrog).
	copyToClipboard(start.UserCode)
	fmt.Fprintf(io.Out, "! First, copy your one-time code: %s\n", start.UserCode)
	fmt.Fprintf(io.Out, "  (confirm it matches the code shown after you sign in)\n")
	if io.Browser == nil {
		fmt.Fprintf(io.Out, "- Please open %s in your browser.\n", verificationURL)
	} else if browseErr := io.Browser(verificationURL); browseErr != nil {
		fmt.Fprintf(io.Out, "  (could not open browser automatically: %v)\n", browseErr)
		fmt.Fprintf(io.Out, "- Please open %s manually.\n", verificationURL)
	} else {
		fmt.Fprintf(io.Out, "✓ Opened %s in browser\n", verificationURL)
	}

	// Step 3: poll for approval.
	interval := ghpDefaultPollInterval
	if start.Interval > 0 {
		interval = time.Duration(start.Interval) * time.Second
	}
	if e.pollInterval > 0 {
		interval = e.pollInterval
	}
	maxWait := ghpDefaultMaxWait
	if start.ExpiresIn > 0 {
		maxWait = time.Duration(start.ExpiresIn) * time.Second
	}
	if e.maxWait > 0 {
		maxWait = e.maxWait
	}
	slowDownBump := ghpSlowDownBump
	if e.slowDownBump > 0 {
		slowDownBump = e.slowDownBump
	}

	fmt.Fprintf(io.Out, "⠼ Waiting for authentication...\n")
	tok, err := ghpPollForToken(ctx, client, serverURL+"/cli/auth/device/token", start.DeviceCode, interval, slowDownBump, maxWait)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(tok.SessionToken, ghpSessionTokenPrefix) {
		return nil, fmt.Errorf("ghp returned an invalid session token (expected %q prefix)", ghpSessionTokenPrefix)
	}

	result := map[string]string{
		"user_token": tok.SessionToken,
		"server_url": serverURL,
	}
	if tok.Username != "" {
		result["user"] = tok.Username
	}
	return result, nil
}

// ghpDeviceStart mirrors the ghp server's device-authorization response.
type ghpDeviceStart struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// ghpTokenResponse mirrors the ghp token-poll response: either the
// approved session token (+ username) or an RFC 8628 error code.
type ghpTokenResponse struct {
	SessionToken     string `json:"session_token"`
	Username         string `json:"username"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// ghpStartDeviceAuth performs the initial POST that opens a device
// authorization on the ghp server and returns the device + user codes.
func ghpStartDeviceAuth(ctx context.Context, client *http.Client, serverURL string) (ghpDeviceStart, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/cli/auth/device", nil)
	if err != nil {
		return ghpDeviceStart{}, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return ghpDeviceStart{}, err
	}
	body, err := readAndClose(resp)
	if err != nil {
		return ghpDeviceStart{}, fmt.Errorf("read ghp device response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return ghpDeviceStart{}, fmt.Errorf("ghp device authorization returned status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var start ghpDeviceStart
	if err := json.Unmarshal(body, &start); err != nil {
		return ghpDeviceStart{}, fmt.Errorf("decode ghp device response: %w", err)
	}
	if start.DeviceCode == "" || start.UserCode == "" {
		return ghpDeviceStart{}, fmt.Errorf("ghp device authorization response missing device_code or user_code")
	}
	return start, nil
}

// ghpPollForToken polls the token endpoint until the user approves the
// device authorization (returning the session token) or the flow fails.
// authorization_pending keeps polling at the current interval; slow_down
// grows it; an HTTP 429 backs off (honouring Retry-After). access_denied,
// expired_token, and any other RFC 8628 error code are terminal.
func ghpPollForToken(ctx context.Context, client *http.Client, tokenEndpoint, deviceCode string, interval, slowDownBump, maxWait time.Duration) (ghpTokenResponse, error) {
	deadline := time.Now().Add(maxWait)
	reqBody, err := json.Marshal(struct {
		DeviceCode string `json:"device_code"`
	}{DeviceCode: deviceCode})
	if err != nil {
		return ghpTokenResponse{}, err
	}

	// Reusable timer avoids leaking a new timer per loop iteration (mirrors
	// the JFrog poll loop).
	timer := time.NewTimer(0)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	first := true
	for {
		if !first {
			timer.Reset(interval)
			select {
			case <-ctx.Done():
				return ghpTokenResponse{}, ctx.Err()
			case <-timer.C:
			}
		}
		first = false

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, bytes.NewReader(reqBody))
		if err != nil {
			return ghpTokenResponse{}, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return ghpTokenResponse{}, err
		}
		body, err := readAndClose(resp)
		if err != nil {
			return ghpTokenResponse{}, fmt.Errorf("read ghp token poll response: %w", err)
		}

		var tr ghpTokenResponse
		decodeErr := json.Unmarshal(body, &tr)

		switch {
		case resp.StatusCode == http.StatusOK && tr.SessionToken != "":
			return tr, nil
		case resp.StatusCode == http.StatusTooManyRequests:
			if ra := ghpRetryAfterSeconds(resp); ra > 0 {
				interval = time.Duration(ra) * time.Second
			} else {
				interval *= 2
				if interval > ghpMaxBackoff {
					interval = ghpMaxBackoff
				}
			}
		default:
			switch tr.Error {
			case "authorization_pending":
				// keep polling at the current interval
			case "slow_down":
				interval += slowDownBump
			case "access_denied":
				return ghpTokenResponse{}, fmt.Errorf("ghp authorization was denied")
			case "expired_token":
				return ghpTokenResponse{}, fmt.Errorf("ghp device code expired before it was approved")
			case "":
				if decodeErr != nil {
					return ghpTokenResponse{}, fmt.Errorf("decode ghp token response (status %d): %w", resp.StatusCode, decodeErr)
				}
				return ghpTokenResponse{}, fmt.Errorf("ghp token poll returned status %d with no token or error code", resp.StatusCode)
			default:
				return ghpTokenResponse{}, fmt.Errorf("ghp authorization failed: %s%s", tr.Error, ghpDescSuffix(tr.ErrorDescription))
			}
		}

		if time.Now().After(deadline) {
			return ghpTokenResponse{}, fmt.Errorf("timed out waiting for ghp authorization after %s", maxWait)
		}
	}
}

// ghpRetryAfterSeconds parses an integer Retry-After header (seconds form).
// The HTTP-date form is ignored — ghp emits the seconds form — and any
// unparseable value yields 0 so the caller falls back to exponential backoff.
func ghpRetryAfterSeconds(resp *http.Response) int {
	v := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// ghpDescSuffix renders an optional " (description)" suffix for error logs.
func ghpDescSuffix(desc string) string {
	desc = strings.TrimSpace(desc)
	if desc == "" {
		return ""
	}
	return " (" + desc + ")"
}

// resolveGHPVerificationURL builds an absolute, clickable verification URL
// from the server's response. The ghp server returns these as paths
// (e.g. "/cli/auth?user_code=ABCD-EFGH") resolved against the server base,
// but an absolute URL is honoured verbatim. verification_uri_complete is
// preferred because it pre-fills the user code; verification_uri is the
// fallback.
func resolveGHPVerificationURL(serverURL, complete, plain string) (string, error) {
	ref := complete
	if ref == "" {
		ref = plain
	}
	if ref == "" {
		return "", fmt.Errorf("ghp device authorization response did not include a verification URI")
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("parse ghp verification URI %q: %w", ref, err)
	}
	if refURL.IsAbs() {
		return ref, nil
	}
	base, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("parse ghp server url: %w", err)
	}
	return base.ResolveReference(refURL).String(), nil
}

// normalizeGHPServerURL parses raw into a canonical scheme+host-only ghp
// server URL (see normalizeBaseURL) and additionally refuses plaintext http
// to a non-loopback host: the device code and, on approval, the "ghpr_"
// session token cross this connection, so http to a remote server would
// expose them to anyone on the path. http is still allowed to loopback (local
// dev, tests). A bare host gains an https:// scheme.
func normalizeGHPServerURL(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ghp enrolment requires a non-empty 'url' setting (your ghp server URL, e.g. https://ghp.example.com)")
	}
	normalized, err := normalizeBaseURL("ghp", raw)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return "", fmt.Errorf("parse ghp url: %w", err)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return "", fmt.Errorf("ghp url must use https for a non-loopback host (got %q): plaintext http would expose the session token", raw)
	}
	return normalized, nil
}
