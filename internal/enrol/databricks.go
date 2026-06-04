package enrol

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/httpproxy"
)

const (
	// databricksDefaultClientID is the public OAuth client ID the Databricks
	// CLI uses for its user-to-machine (U2M) login. It is a public client —
	// no secret — that authenticates via PKCE. (databricks-sdk-go:
	// credentials/u2m/persistent_auth.go, const appClientID.)
	databricksDefaultClientID = "databricks-cli"

	// databricksRedirectPortLo/Hi bound the localhost callback port range.
	// The public `databricks-cli` OAuth app registers http://localhost:<port>
	// for a preferred port of 8020, walking upward to 8040 until it finds a
	// free one (credentials/u2m: defaultPort=8020, maxPortFallback=8040). The
	// redirect URI advertised to Databricks must be http://localhost:<bound-port>
	// to match that registration (an explicit 127.0.0.1 literal is rejected as
	// an unregistered redirect_uri); the path is not significant. See
	// databricksDefaultListen for why the listener still binds 127.0.0.1.
	databricksRedirectPortLo = 8020
	databricksRedirectPortHi = 8040

	// databricksLoginTimeout caps how long Run waits for the user to finish
	// the browser login before giving up. Generous compared with the SDK's
	// 45s because dotvault users routinely sign in through SSO/MFA.
	databricksLoginTimeout = 5 * time.Minute
)

// databricksDefaultScopes is the scope set the CLI requests. offline_access
// is what yields a refresh token (so dotvault can rotate the short-lived
// access token at its half-life); all-apis grants the workspace REST surface.
var databricksDefaultScopes = []string{"offline_access", "all-apis"}

// DatabricksEngine performs a Databricks OAuth U2M (user-to-machine) login,
// mirroring `databricks auth login`: an authorization-code + PKCE flow against
// the workspace (or account) OAuth endpoints, with a localhost redirect
// listener catching the code. Databricks access tokens live for about an
// hour, so the engine implements Refresher — the daemon's RefreshManager
// rotates the access/refresh pair at its half-life and dotvault owns the
// rotation, exactly as it does for JFrog.
type DatabricksEngine struct {
	// httpClient is used for OIDC discovery, the token exchange/refresh, and
	// the SCIM identity lookup. Overridable for tests. When nil, a proxy-aware
	// client is built per-call from the enrolment settings.
	httpClient *http.Client
	// now is injected for deterministic issued_at/expires_at timestamps.
	now func() time.Time
	// loginTimeout overrides databricksLoginTimeout in tests.
	loginTimeout time.Duration
	// listen creates the local redirect listener and returns it alongside the
	// redirect_uri to advertise to Databricks. Overridable in tests to bind an
	// ephemeral port; the default loops databricksRedirectPortLo..Hi.
	listen func() (net.Listener, string, error)
}

func (e *DatabricksEngine) Name() string { return "Databricks" }

// Fields lists the Vault KV fields a complete enrolment must carry.
// access_token drives the rendered credential, refresh_token powers the
// rotation cycle, host identifies the workspace, and issued_at+expires_at
// drive the half-life refresh decision.
//
// `user` is intentionally NOT listed: the engine writes it when the SCIM
// /Me lookup succeeds, but a transient lookup failure must not make an
// otherwise-good enrolment look incomplete (the same approach GitHub and
// JFrog take for their best-effort `user` field).
func (e *DatabricksEngine) Fields() []string {
	return []string{"access_token", "refresh_token", "host", "issued_at", "expires_at"}
}

func (e *DatabricksEngine) clock() time.Time {
	if e.now != nil {
		return e.now()
	}
	return time.Now().UTC()
}

func (e *DatabricksEngine) client(settings map[string]any) (*http.Client, error) {
	if e.httpClient != nil {
		return e.httpClient, nil
	}
	return httpproxy.ClientFromSettings(settings, 30*time.Second)
}

func (e *DatabricksEngine) Run(ctx context.Context, settings map[string]any, io IO) (map[string]string, error) {
	host, err := databricksHostFromSettings(settings)
	if err != nil {
		return nil, err
	}
	accountID, err := databricksAccountID(settings)
	if err != nil {
		return nil, err
	}
	clientID := databricksDefaultClientID
	if v, ok := settings["client_id"].(string); ok && v != "" {
		clientID = v
	}
	scopes, err := databricksScopes(settings)
	if err != nil {
		return nil, err
	}

	client, err := e.client(settings)
	if err != nil {
		return nil, fmt.Errorf("configure http client: %w", err)
	}

	// Discover the authorization and token endpoints from the workspace
	// (or account) OAuth metadata document.
	server, err := databricksDiscover(ctx, client, host, accountID)
	if err != nil {
		return nil, fmt.Errorf("discover databricks oauth endpoints: %w", err)
	}

	// Bind the local redirect listener (preferring port 8020).
	listenFn := e.listen
	if listenFn == nil {
		listenFn = databricksDefaultListen
	}
	listener, redirectURI, err := listenFn()
	if err != nil {
		return nil, fmt.Errorf("start databricks callback listener: %w", err)
	}
	defer listener.Close()

	// PKCE: verifier (64 chars) + S256 challenge, and an anti-CSRF state.
	verifier, err := databricksRandString(64)
	if err != nil {
		return nil, fmt.Errorf("generate pkce verifier: %w", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state, err := databricksRandString(16)
	if err != nil {
		return nil, fmt.Errorf("generate oauth state: %w", err)
	}

	authURL := server.AuthorizationEndpoint + "?" + url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"state":                 {state},
		"scope":                 {strings.Join(scopes, " ")},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	// Serve the redirect catcher. The handler validates state, surfaces an
	// IdP error param, and hands the code back over the channel.
	type callbackResult struct {
		code string
		err  error
	}
	resultCh := make(chan callbackResult, 1)
	// reply writes the browser-facing message and hands the result back over
	// the channel with a non-blocking send: only the first callback wins, and a
	// duplicate request (a browser refresh/retry, or any other process hitting
	// the loopback port) is answered but its result dropped — so the handler
	// goroutine never blocks on a full channel and server2.Shutdown never hangs
	// waiting on a wedged connection.
	reply := func(w http.ResponseWriter, msg string, res callbackResult) {
		fmt.Fprint(w, msg)
		select {
		case resultCh <- res:
		default:
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if errParam := q.Get("error"); errParam != "" {
			desc := q.Get("error_description")
			reply(w, "Authentication failed. You can close this window.",
				callbackResult{err: fmt.Errorf("databricks authorization error: %s %s", errParam, desc)})
			return
		}
		if got := q.Get("state"); got != state {
			reply(w, "Authentication failed. You can close this window.",
				callbackResult{err: fmt.Errorf("databricks callback state mismatch")})
			return
		}
		code := q.Get("code")
		if code == "" {
			reply(w, "Authentication failed. You can close this window.",
				callbackResult{err: fmt.Errorf("databricks callback missing authorization code")})
			return
		}
		reply(w, "Authentication successful! You can close this window and return to dotvault.",
			callbackResult{code: code})
	})
	server2 := &http.Server{Handler: mux}
	go server2.Serve(listener)
	defer func() {
		// Bounded shutdown: the callback response is already flushed by the
		// time Run returns, so this normally completes instantly. The deadline
		// guards against a stray hung connection wedging Run's return.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server2.Shutdown(shutdownCtx)
	}()

	// Present the login URL.
	if io.Browser == nil {
		fmt.Fprintf(io.Out, "- Please open %s in your browser.\n", authURL)
	} else if browseErr := io.Browser(authURL); browseErr != nil {
		fmt.Fprintf(io.Out, "  (could not open browser automatically: %v)\n", browseErr)
		fmt.Fprintf(io.Out, "- Please open %s manually.\n", authURL)
	} else {
		fmt.Fprintf(io.Out, "✓ Opened %s in browser\n", authURL)
	}
	fmt.Fprintf(io.Out, "⠼ Waiting for authentication...\n")

	timeout := e.loginTimeout
	if timeout == 0 {
		timeout = databricksLoginTimeout
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var code string
	select {
	case r := <-resultCh:
		if r.err != nil {
			return nil, r.err
		}
		code = r.code
	case <-waitCtx.Done():
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("timed out waiting for databricks login after %s", timeout)
	}

	// Exchange the authorization code for tokens.
	fmt.Fprintf(io.Out, "⠼ Exchanging authorization code...\n")
	tok, status, err := databricksTokenRequest(ctx, client, server.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	})
	if err != nil {
		return nil, fmt.Errorf("databricks token exchange (status %d): %w", status, err)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		return nil, fmt.Errorf("databricks token exchange returned incomplete pair (access present=%t, refresh present=%t); ensure the 'offline_access' scope is requested",
			tok.AccessToken != "", tok.RefreshToken != "")
	}

	now := e.clock()
	result := map[string]string{
		"access_token":  tok.AccessToken,
		"refresh_token": tok.RefreshToken,
		"host":          host,
		"issued_at":     now.UTC().Format(time.RFC3339),
		"expires_at":    now.Add(databricksTokenLifetime(tok)).UTC().Format(time.RFC3339),
	}

	// Best-effort identity lookup; never fatal (mirrors GitHub/JFrog).
	if user, uErr := databricksFetchUser(ctx, client, host, tok.AccessToken); uErr != nil {
		io.Log.Warn("could not fetch databricks username", "error", uErr)
	} else if user != "" {
		result["user"] = user
	}

	return result, nil
}

// Refresh rotates a Databricks access/refresh token pair past its half-life.
// A 401/403 from the token endpoint means the refresh token has been revoked
// upstream (ErrRevoked → re-enrol); any other failure is transient.
func (e *DatabricksEngine) Refresh(ctx context.Context, settings map[string]any, existing map[string]string) (map[string]string, error) {
	host, err := databricksHostFromSettings(settings)
	if err != nil {
		return nil, err
	}
	accountID, err := databricksAccountID(settings)
	if err != nil {
		return nil, err
	}
	clientID := databricksDefaultClientID
	if v, ok := settings["client_id"].(string); ok && v != "" {
		clientID = v
	}
	scopes, err := databricksScopes(settings)
	if err != nil {
		return nil, err
	}

	refresh := existing["refresh_token"]
	if refresh == "" {
		return nil, fmt.Errorf("databricks refresh requires a refresh_token in the existing secret")
	}

	client, err := e.client(settings)
	if err != nil {
		return nil, fmt.Errorf("configure http client: %w", err)
	}

	server, err := databricksDiscover(ctx, client, host, accountID)
	if err != nil {
		return nil, fmt.Errorf("discover databricks oauth endpoints: %w", err)
	}

	tok, status, err := databricksTokenRequest(ctx, client, server.TokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
		"scope":         {strings.Join(scopes, " ")},
	})
	if err != nil {
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			return nil, fmt.Errorf("databricks refresh rejected (status %d): %w", status, ErrRevoked)
		}
		return nil, fmt.Errorf("databricks refresh (status %d): %w", status, err)
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("databricks refresh returned no access token")
	}

	// Databricks may or may not rotate the refresh token. If the response
	// carries a new one, adopt it; otherwise keep the existing token.
	newRefresh := tok.RefreshToken
	if newRefresh == "" {
		newRefresh = refresh
	}

	now := e.clock()
	out := map[string]string{
		"access_token":  tok.AccessToken,
		"refresh_token": newRefresh,
		"host":          host,
		"issued_at":     now.UTC().Format(time.RFC3339),
		"expires_at":    now.Add(databricksTokenLifetime(tok)).UTC().Format(time.RFC3339),
	}
	// Preserve the identity we already resolved at enrolment; the refresh
	// endpoint does not return it and a SCIM call on every rotation is waste.
	if user := existing["user"]; user != "" {
		out["user"] = user
	}
	return out, nil
}

// databricksOAuthServer is the subset of the OAuth Authorization Server
// Metadata document (RFC 8414) that the flow needs.
type databricksOAuthServer struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// databricksDiscover fetches the OAuth metadata document. For a workspace the
// path is {host}/oidc/.well-known/oauth-authorization-server; for account-level
// login an /oidc/accounts/{id} segment is inserted.
func databricksDiscover(ctx context.Context, client *http.Client, host, accountID string) (databricksOAuthServer, error) {
	var discoveryURL string
	if accountID != "" {
		discoveryURL = host + "/oidc/accounts/" + url.PathEscape(accountID) + "/.well-known/oauth-authorization-server"
	} else {
		discoveryURL = host + "/oidc/.well-known/oauth-authorization-server"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return databricksOAuthServer{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return databricksOAuthServer{}, err
	}
	body, err := readAndClose(resp)
	if err != nil {
		return databricksOAuthServer{}, fmt.Errorf("read discovery response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return databricksOAuthServer{}, fmt.Errorf("discovery returned status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var server databricksOAuthServer
	if err := json.Unmarshal(body, &server); err != nil {
		return databricksOAuthServer{}, fmt.Errorf("decode discovery response: %w", err)
	}
	if server.AuthorizationEndpoint == "" || server.TokenEndpoint == "" {
		return databricksOAuthServer{}, fmt.Errorf("discovery response missing authorization_endpoint or token_endpoint")
	}
	return server, nil
}

// databricksTokenResp is the OAuth token endpoint response (RFC 6749) plus
// the error fields returned on a 4xx.
type databricksTokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// databricksTokenRequest POSTs a form-encoded body to the token endpoint.
// Databricks treats databricks-cli as a public client, so credentials live in
// the body (no HTTP Basic). Returns the parsed response, the HTTP status (so
// callers can distinguish revocation from transient errors), and an error on
// any non-200.
func databricksTokenRequest(ctx context.Context, client *http.Client, tokenEndpoint string, form url.Values) (databricksTokenResp, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return databricksTokenResp{}, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return databricksTokenResp{}, 0, err
	}
	body, err := readAndClose(resp)
	if err != nil {
		return databricksTokenResp{}, resp.StatusCode, fmt.Errorf("read token response: %w", err)
	}

	var tok databricksTokenResp
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

// databricksTokenLifetime returns the access-token lifetime from the response,
// defaulting to one hour when expires_in is absent or non-positive (Databricks
// always returns 3600, but a defensive default keeps the half-life refresh
// math sane against an unexpected response).
func databricksTokenLifetime(tok databricksTokenResp) time.Duration {
	if tok.ExpiresIn <= 0 {
		return time.Hour
	}
	return time.Duration(tok.ExpiresIn) * time.Second
}

// databricksFetchUser resolves the signed-in user's name via the SCIM /Me
// endpoint. Best-effort: the access token is opaque to dotvault, so this is
// the only way to surface a human-readable identity.
func databricksFetchUser(ctx context.Context, client *http.Client, host, accessToken string) (string, error) {
	meURL := host + "/api/2.0/preview/scim/v2/Me"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	body, err := readAndClose(resp)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("scim /Me status %d", resp.StatusCode)
	}
	var me struct {
		UserName string `json:"userName"`
	}
	if err := json.Unmarshal(body, &me); err != nil {
		return "", err
	}
	return me.UserName, nil
}

// databricksDefaultListen binds the first free port in the 8020..8040 range on
// the IPv4 loopback and returns the listener plus the http://localhost:<port>
// redirect URI to advertise. Matches the Databricks CLI's port-walk behaviour.
//
// The advertised redirect_uri MUST use the "localhost" host, not "127.0.0.1":
// the public `databricks-cli` OAuth app only registers http://localhost:<port>
// (8020-8040), and Databricks rejects an authorize request whose redirect_uri
// isn't an exact registered match ("redirect_uri ... not registered"). The
// listener itself binds the concrete IPv4 loopback rather than the "localhost"
// name on purpose: net.Listen("tcp", "localhost:p") resolves to a single
// family, so on a dual-stack host it can bind only ::1 while the browser dials
// 127.0.0.1 (or vice versa) and the callback never arrives. Binding 127.0.0.1
// keeps the port-walk concrete and reachable; the browser's Happy-Eyeballs dial
// of "localhost" falls back to 127.0.0.1 when ::1 refuses, so bind and dial
// still meet.
func databricksDefaultListen() (net.Listener, string, error) {
	var lastErr error
	for port := databricksRedirectPortLo; port <= databricksRedirectPortHi; port++ {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			lastErr = err
			continue
		}
		return l, fmt.Sprintf("http://localhost:%d", port), nil
	}
	return nil, "", fmt.Errorf("no free port in range %d-%d for the OAuth redirect listener: %w",
		databricksRedirectPortLo, databricksRedirectPortHi, lastErr)
}

// databricksHostFromSettings reads and normalizes the required `host` setting.
func databricksHostFromSettings(settings map[string]any) (string, error) {
	raw, _ := settings["host"].(string)
	host, err := normalizeDatabricksHost(raw)
	if err != nil {
		return "", err
	}
	return host, nil
}

// normalizeDatabricksHost validates that `raw` is a scheme+host-only URL and
// returns its canonical form. API paths are concatenated onto this value, so
// an embedded path/query/fragment would route requests incorrectly.
func normalizeDatabricksHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("databricks enrolment requires a non-empty 'host' setting (your workspace URL, e.g. https://dbc-xxxx.cloud.databricks.com)")
	}
	u, err := url.Parse(ensureScheme(raw))
	if err != nil {
		return "", fmt.Errorf("parse databricks host: %w", err)
	}
	// Databricks is HTTPS-only (SaaS). Requiring it here matters for secrecy:
	// the discovery, token-exchange, and SCIM calls send the access token as a
	// bearer header, and the host is the base they're concatenated onto — an
	// http:// host would leak the token in cleartext. A bare host (no scheme)
	// is defaulted to https by ensureScheme, so only an explicit http:// is
	// rejected here.
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" {
		return "", fmt.Errorf("databricks host must use https, got %q", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("databricks host must include a host: %q", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("databricks host must not include a query or fragment: %q", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("databricks host must be the workspace base URL without a path (got %q)", raw)
	}
	return (&url.URL{Scheme: scheme, Host: u.Host}).String(), nil
}

// databricksAccountID reads the optional account_id setting (for account-level
// login). Returns "" when unset.
func databricksAccountID(settings map[string]any) (string, error) {
	raw, ok := settings["account_id"]
	if !ok {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("databricks account_id must be a string, got %T", raw)
	}
	return strings.TrimSpace(s), nil
}

// databricksScopes returns the configured scope list, defaulting to
// offline_access + all-apis. A custom list is honoured verbatim, but
// offline_access is always ensured because dotvault relies on the refresh
// token to keep the short-lived access token rotated.
func databricksScopes(settings map[string]any) ([]string, error) {
	raw, ok := settings["scopes"]
	if !ok {
		return databricksDefaultScopes, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("databricks scopes must be a list, got %T", raw)
	}
	scopes := make([]string, 0, len(list)+1)
	hasOffline := false
	for _, s := range list {
		str, ok := s.(string)
		if !ok {
			return nil, fmt.Errorf("databricks scope value must be a string, got %T", s)
		}
		if str == "offline_access" {
			hasOffline = true
		}
		scopes = append(scopes, str)
	}
	if !hasOffline {
		scopes = append([]string{"offline_access"}, scopes...)
	}
	return scopes, nil
}

// databricksRandString returns an n-character URL-safe random string (used for
// the PKCE verifier and the OAuth state), matching the SDK's crypto/rand +
// base64url generator.
func databricksRandString(n int) (string, error) {
	nbytes := n*3/4 + 1
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b)[:n], nil
}
