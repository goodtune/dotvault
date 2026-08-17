package web

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/sshfwd"
)

// uiTestVaultHandler fakes the two Vault KVv2 shapes the UI reads: LIST
// requests (?list=true) and reads of secret/data/users/testuser/<key>.
func uiTestVaultHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("list") == "true" {
			switch {
			case strings.HasSuffix(r.URL.Path, "/users/testuser"):
				json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{"keys": []string{"databricks/", "gh"}},
				})
			case strings.HasSuffix(r.URL.Path, "/users/testuser/databricks"):
				json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{"keys": []string{"prod"}},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}
		if strings.HasSuffix(r.URL.Path, "/users/testuser/gh") {
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data":     map[string]any{"oauth_token": "ghp_secret", "user": "testuser"},
					"metadata": map[string]any{"version": 3},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
}

// uiTestServer builds an authenticated server with the full route table and
// a fake Vault, returning it plus its running httptest frontend.
func uiTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s := testServerWithVault(t, uiTestVaultHandler(t))
	s.cfg.Listen = "127.0.0.1:9000"
	s.vaultAddress = "http://127.0.0.1:8200"
	s.registerRoutes()
	ts := httptest.NewServer(s.middleware(s.mux))
	t.Cleanup(ts.Close)
	return s, ts
}

func uiGet(t *testing.T, ts *httptest.Server, path string) *http.Response {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, err := http.NewRequest("GET", ts.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "127.0.0.1:9000"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func uiBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func TestUIDashboard_RedirectsWhenUnauthenticated(t *testing.T) {
	s := testServer(t)
	s.registerRoutes()
	ts := httptest.NewServer(s.middleware(s.mux))
	t.Cleanup(ts.Close)

	resp := uiGet(t, ts, "/ui/")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}
}

func TestUIDashboard_RendersLayout(t *testing.T) {
	s, ts := uiTestServer(t)
	s.secretViewTextHTML = "<p>welcome text</p>"

	resp := uiGet(t, ts, "/ui/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "'unsafe-eval'") {
		t.Errorf("CSP = %q, want datastar-compatible policy on /ui/", csp)
	}
	body := uiBody(t, resp)
	for _, want := range []string{
		`class="status-bar"`, // SPA header look
		"Connected",
		"Sync Now",
		"Enrolments", "Remotes", "Secrets", // accordion sections
		"welcome text",               // secret_view_text markdown
		`href="/ui/config/"`,         // config in header
		`data-init="@get('/ui/sse')`, // live-update hook
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
}

func TestUISecretsNav_ExpandsAndLists(t *testing.T) {
	_, ts := uiTestServer(t)

	resp := uiGet(t, ts, "/ui/secrets/")
	body := uiBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	// Top-level entries: the databricks folder (collapsed) and the gh leaf.
	if !strings.Contains(body, `href="/ui/secrets/gh"`) {
		t.Errorf("missing gh leaf link")
	}
	if !strings.Contains(body, `href="/ui/secrets/databricks/"`) {
		t.Errorf("missing databricks folder link")
	}
	// Folder contents are not listed until the folder is opened.
	if strings.Contains(body, "prod") {
		t.Errorf("collapsed folder must not reveal children")
	}

	resp = uiGet(t, ts, "/ui/secrets/databricks/")
	body = uiBody(t, resp)
	if !strings.Contains(body, `href="/ui/secrets/databricks/prod"`) {
		t.Errorf("expanded folder missing child link; body: %s", body)
	}
}

func TestUISecretDetail_MasksValues(t *testing.T) {
	_, ts := uiTestServer(t)

	resp := uiGet(t, ts, "/ui/secrets/gh")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := uiBody(t, resp)
	if strings.Contains(body, "ghp_secret") {
		t.Fatalf("page must never carry the secret value")
	}
	for _, want := range []string{
		"Version: 3",
		"oauth_token",
		"View in Vault",
		// data-on:* attribute values are JS-escaped by html/template, so
		// match on escape-stable substrings of the action URLs.
		"reveal?field=oauth_token",
		"copy-field?field=oauth_token",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("secret page missing %q", want)
		}
	}
	// Trailing-slash spelling reaches the same page (bookmarkable form).
	resp = uiGet(t, ts, "/ui/secrets/gh/")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("trailing-slash secret URL: status = %d, want 200", resp.StatusCode)
	}
}

func TestUISecretReveal_PatchesValueAndRemasks(t *testing.T) {
	s, ts := uiTestServer(t)
	_ = s

	resp := uiGet(t, ts, "/ui/fragments/secrets/reveal?path=gh&field=oauth_token&id=0")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := uiBody(t, resp)
	if !strings.Contains(body, "datastar-patch-elements") {
		t.Errorf("expected a datastar patch event, got: %s", body)
	}
	if !strings.Contains(body, "ghp_secret") {
		t.Errorf("reveal fragment missing the value")
	}
	if !strings.Contains(body, "data-init__delay.30s") {
		t.Errorf("revealed cell must re-mask itself after a delay")
	}

	resp = uiGet(t, ts, "/ui/fragments/secrets/mask?path=gh&field=oauth_token&id=0")
	body = uiBody(t, resp)
	if strings.Contains(body, "ghp_secret") {
		t.Errorf("mask fragment must not carry the value")
	}
	if !strings.Contains(body, "masked") {
		t.Errorf("mask fragment missing masked cell")
	}
}

func TestUIWrite_RequiresSameOrigin(t *testing.T) {
	s, ts := uiTestServer(t)
	copied := ""
	s.setClipboard = func(text string) error { copied = text; return nil }

	post := func(origin string) int {
		req, err := http.NewRequest("POST", ts.URL+"/ui/actions/copy-field?path=gh&field=oauth_token&id=0", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "127.0.0.1:9000"
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// No Origin: unlike the peer-action endpoints (whose consumer is curl),
	// UI mutations are browser-only, so absence is rejected.
	if code := post(""); code != http.StatusForbidden {
		t.Errorf("no Origin: status = %d, want 403", code)
	}
	if copied != "" {
		t.Fatalf("clipboard written despite rejected request")
	}
	// Cross-site Origin.
	if code := post("http://evil.example.com"); code != http.StatusForbidden {
		t.Errorf("cross-site Origin: status = %d, want 403", code)
	}
	// Own origin.
	if code := post("http://127.0.0.1:9000"); code != http.StatusOK {
		t.Errorf("same-origin: status = %d, want 200", code)
	}
	if copied != "ghp_secret" {
		t.Errorf("clipboard = %q, want the field value", copied)
	}
}

func TestUISyncAction(t *testing.T) {
	s, ts := uiTestServer(t)
	_ = s

	req, _ := http.NewRequest("POST", ts.URL+"/ui/actions/sync", nil)
	req.Host = "127.0.0.1:9000"
	req.Header.Set("Origin", "http://127.0.0.1:9000")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// No engine wired in the test server: the handler must answer 503, not
	// panic.
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 without engine", resp.StatusCode)
	}
}

func TestUIEnrolCard_ParsesDeviceFlow(t *testing.T) {
	s := testServer(t)
	card := s.buildUIEnrolCard(EnrolStateInfo{
		Key:        "gh",
		Engine:     "github",
		EngineName: "GitHub",
		Status:     "running",
		Output: []string{
			"! First, copy your one-time code: ABCD-1234",
			"- Press Enter to open https://github.com/login/device in your browser...",
			"⠼ Waiting for authentication...",
		},
	}, true)
	if !card.HasDeviceFlow {
		t.Fatalf("expected device flow, got %+v", card)
	}
	if card.DeviceCode != "ABCD-1234" {
		t.Errorf("DeviceCode = %q", card.DeviceCode)
	}
	if card.VerificationURL != "https://github.com/login/device" {
		t.Errorf("VerificationURL = %q", card.VerificationURL)
	}
	if card.ProgressLine != "Waiting for authentication..." {
		t.Errorf("ProgressLine = %q", card.ProgressLine)
	}
	if card.Busy {
		t.Errorf("the running enrolment itself must not be Busy")
	}

	// A redirect-only flow (databricks): URL, no code.
	card = s.buildUIEnrolCard(EnrolStateInfo{
		Key:    "databricks/prod",
		Engine: "databricks",
		Status: "running",
		Output: []string{"Opening https://dbc.example.com/oidc/authorize?x=1 ..."},
	}, false)
	if !card.HasRedirectFlow || card.HasDeviceFlow {
		t.Errorf("expected redirect flow, got %+v", card)
	}
	if card.Title != "prod" {
		t.Errorf("grouped key title = %q, want leaf", card.Title)
	}
}

func TestUIEnrolNav_GroupsByEngineOnlyWhenPlural(t *testing.T) {
	s := testServer(t)
	s.InitEnrolments(t.Context(), nil) // ensure runner nil path is safe
	sec := &uiNavSection{}
	s.fillEnrolNav(sec, "")
	if sec.Note == "" {
		t.Errorf("expected note when no enrolments are configured")
	}

	runner := NewEnrolmentRunner(map[string]config.Enrolment{
		"gh":              {Engine: "github"},
		"databricks/prod": {Engine: "databricks"},
		"databricks/dev":  {Engine: "databricks"},
	})
	s.enrolRunnerMu.Lock()
	s.enrolRunner = runner
	s.enrolRunnerMu.Unlock()

	sec = &uiNavSection{}
	s.fillEnrolNav(sec, "")
	var flat, folders []string
	for _, item := range sec.Items {
		if item.Folder {
			folders = append(folders, item.Name)
		} else {
			flat = append(flat, item.Name)
		}
	}
	if len(folders) != 1 || folders[0] != "databricks" {
		t.Errorf("folders = %v, want [databricks]", folders)
	}
	if len(flat) != 1 || flat[0] != "gh" {
		t.Errorf("flat = %v, want [gh] (single-enrolment engine must not nest)", flat)
	}
}

func TestUIRemotes_UnavailableWithoutRegistry(t *testing.T) {
	_, ts := uiTestServer(t)
	resp := uiGet(t, ts, "/ui/remotes/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := uiBody(t, resp)
	if !strings.Contains(body, "Managed SSH forwards are not configured") {
		t.Errorf("missing unavailable message")
	}
}

func TestUIConfigPage_Renders(t *testing.T) {
	_, ts := uiTestServer(t)
	resp := uiGet(t, ts, "/ui/config/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := uiBody(t, resp)
	for _, want := range []string{
		"Effective Configuration",
		"Download YAML",
		"Download REG",
		"Managed Files",
		`class="sidebar"`, // nav stays on the config page
	} {
		if !strings.Contains(body, want) {
			t.Errorf("config page missing %q", want)
		}
	}
	if strings.Contains(body, "Back to Dashboard") {
		t.Errorf("config page must not have a back button; the nav replaces it")
	}
}

func TestUIRouteLabel(t *testing.T) {
	if got := routeLabel("/ui/secrets/super-secret-name"); got != "/ui/*" {
		t.Errorf("routeLabel = %q, want /ui/*", got)
	}
}

func TestUIConfigJSONShapeUnchanged(t *testing.T) {
	// The handleConfig refactor onto shared view structs must preserve the
	// SPA's wire contract.
	s := testServerWithVault(t, uiTestVaultHandler(t))
	req := httptest.NewRequest("GET", "/api/v1/config", nil)
	w := httptest.NewRecorder()
	s.handleConfig(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	vaultSection, ok := resp["vault"].(map[string]any)
	if !ok {
		t.Fatalf("vault section missing")
	}
	for _, key := range []string{
		"address", "kv_mount", "user_prefix", "auth_method", "auth_mount",
		"auth_role", "tls_skip_verify", "has_ca_cert", "disable_token_renewal",
	} {
		if _, present := vaultSection[key]; !present {
			t.Errorf("vault.%s missing from JSON", key)
		}
	}
	if _, present := resp["remote_config"]; present {
		t.Errorf("remote_config must be omitted when not configured")
	}
	if _, ok := resp["rules"].([]any); !ok {
		t.Errorf("rules is %T, want array", resp["rules"])
	}
	webSection, ok := resp["web"].(map[string]any)
	if !ok {
		t.Fatalf("web section missing")
	}
	// listen_effective was conditionally present in the map-built JSON; the
	// struct translation must keep it omitted while unbound.
	if _, present := webSection["listen_effective"]; present {
		t.Errorf("web.listen_effective must be omitted when no address is bound")
	}
	if _, present := resp["sync"].(map[string]any); !present {
		t.Errorf("sync section missing")
	}
	if _, ok := resp["enrolments"].([]any); !ok {
		t.Errorf("enrolments is %T, want array", resp["enrolments"])
	}

	// With a bound address and a remote-config overlay, both optional pieces
	// must appear — including header *names* only.
	s.listenAddr = "127.0.0.1:12345"
	s.remoteCfg = config.RemoteConfig{
		URL:                "https://cfg.example.com/dotvault.yaml",
		RawRefreshInterval: "5m",
		Headers:            map[string]string{"X-Dotvault-Env": "prod"},
	}
	w = httptest.NewRecorder()
	s.handleConfig(w, req)
	resp = map[string]any{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if got := resp["web"].(map[string]any)["listen_effective"]; got != "127.0.0.1:12345" {
		t.Errorf("web.listen_effective = %v, want the bound address", got)
	}
	rc, ok := resp["remote_config"].(map[string]any)
	if !ok {
		t.Fatalf("remote_config missing when configured")
	}
	if rc["url"] != "https://cfg.example.com/dotvault.yaml" || rc["refresh_interval"] != "5m" {
		t.Errorf("remote_config = %v", rc)
	}
	names, ok := rc["header_names"].([]any)
	if !ok || len(names) != 1 || names[0] != "X-Dotvault-Env" {
		t.Errorf("remote_config.header_names = %v, want [X-Dotvault-Env]", rc["header_names"])
	}
}

// TestUIWrite_AllPostRoutesRequireOrigin pins requireUIWrite onto every /ui/
// POST route: each handler calls the gate individually, so dropping it from
// one would otherwise go undetected.
func TestUIWrite_AllPostRoutesRequireOrigin(t *testing.T) {
	_, ts := uiTestServer(t)
	routes := []string{
		"/ui/actions/sync",
		"/ui/actions/copy-token",
		"/ui/actions/copy-field?path=gh&field=oauth_token&id=0",
		"/ui/enrol/start",
		"/ui/enrol/skip",
		"/ui/enrol/reset",
		"/ui/enrol/secret",
		"/ui/remotes/add",
		"/ui/remotes/somehost/save",
		"/ui/remotes/somehost/delete",
	}
	for _, route := range routes {
		req, err := http.NewRequest("POST", ts.URL+route, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "127.0.0.1:9000"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s without Origin: status = %d, want 403", route, resp.StatusCode)
		}
	}
}

// TestUISSE_StopsOnClientDisconnect pins the SSE loop's exit path: cancelling
// the request context must end the handler rather than leak its goroutine.
func TestUISSE_StopsOnClientDisconnect(t *testing.T) {
	_, ts := uiTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, "GET", ts.URL+"/ui/sse", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "127.0.0.1:9000"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Read the first patch, then hang up; the server side must return.
	buf := make([]byte, 1)
	if _, err := resp.Body.Read(buf); err != nil {
		t.Fatalf("first SSE byte: %v", err)
	}
	cancel()
	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck // error is the expected cancellation
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("SSE body did not close after context cancel")
	}
}

func TestUIParsePort(t *testing.T) {
	cases := []struct {
		raw   string
		want  int
		valid bool
	}{
		{"", 0, true},
		{"22", 22, true},
		{"65535", 65535, true},
		{"0", 0, false},
		{"-1", 0, false},
		{"65536", 0, false},
		{"22abc", 0, false},
		{"2.2", 0, false},
	}
	for _, tc := range cases {
		got, ok := uiParsePort(tc.raw)
		if got != tc.want || ok != tc.valid {
			t.Errorf("uiParsePort(%q) = (%d, %v), want (%d, %v)", tc.raw, got, ok, tc.want, tc.valid)
		}
	}
}

// TestUIEnrolCard_SpentAndPromptStates covers the card states beyond the
// active device/redirect flows: the post-auth "minting"/"exchanging" steps
// collapse the action UI, and a pending passphrase prompt renders the form.
func TestUIEnrolCard_SpentAndPromptStates(t *testing.T) {
	s := testServer(t)
	card := s.buildUIEnrolCard(EnrolStateInfo{
		Key: "jfrog", Engine: "jfrog", EngineName: "JFrog", Status: "running",
		Output: []string{
			"! First, copy your one-time code: XY12",
			"✓ Opened https://jfrog.example.com/ui/login in browser",
			"⠼ Minting dotvault-owned access token...",
		},
	}, false)
	if !card.HasDeviceFlow || !card.CodeSpent {
		t.Errorf("expected spent device flow, got %+v", card)
	}

	// Pending passphrase prompt attaches only to the running card.
	s.enrolPromptMu.Lock()
	s.enrolPromptLabel = "Enter passphrase"
	s.enrolPromptCh = make(chan string, 1)
	s.enrolPromptMu.Unlock()
	card = s.buildUIEnrolCard(EnrolStateInfo{
		Key: "ssh", Engine: "ssh", EngineName: "SSH", Status: "running",
	}, false)
	if !card.PromptPending || card.PromptLabel != "Enter passphrase" {
		t.Errorf("expected pending prompt on running card, got %+v", card)
	}
	card = s.buildUIEnrolCard(EnrolStateInfo{
		Key: "ssh", Engine: "ssh", EngineName: "SSH", Status: "pending",
	}, false)
	if card.PromptPending {
		t.Errorf("non-running card must not show the prompt")
	}
	s.enrolPromptMu.Lock()
	s.enrolPromptCh = nil
	s.enrolPromptLabel = ""
	s.enrolPromptMu.Unlock()
}

// TestUIFragmentURLsAreQueryEncoded pins the property the datastar attribute
// interpolation relies on: fragment URLs are strictly url.Values-encoded, so
// quotes, backslashes, and other JS-string metacharacters in a field or path
// name can never appear raw inside a data-on:* / data-init attribute value.
func TestUIFragmentURLsAreQueryEncoded(t *testing.T) {
	f := uiSecretFieldRefs(`we"ird'pa\th`, `fi'eld"na\me`, 3)
	for _, u := range []string{f.RevealURL, f.MaskURL, f.CopyURL, f.CopyBtnURL} {
		if strings.ContainsAny(u, `'"\`+"`") {
			t.Errorf("fragment URL %q carries raw JS-string metacharacters", u)
		}
	}
	frag, err := uiFragment("revealed-cell", f)
	if err != nil {
		t.Fatal(err)
	}
	// The @get('…') quoting is literal template text; what must never appear
	// is the raw (unencoded) path or field value inside the attribute.
	for _, raw := range []string{`we"ird`, `fi'eld`, `na\me`} {
		if strings.Contains(frag, raw) {
			t.Errorf("revealed-cell carries unencoded value %q: %s", raw, frag)
		}
	}
	if !strings.Contains(frag, "fi%27eld%22na%5Cme") {
		t.Errorf("expected percent-encoded field name in fragment: %s", frag)
	}
}

// TestUISSHLiveRender pins the /ui/sse/ssh patch payload: the nav list plus
// the view's content region, rendered from the same rows as the pages.
func TestUISSHLiveRender(t *testing.T) {
	if err := uiInitTemplates(); err != nil {
		t.Fatal(err)
	}
	s := sshTestServer(t, noopVerifier)
	if _, err := s.sshRegistry.Add(context.Background(), sshfwd.Remote{Host: "example.com"}, sshfwd.AddOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	s.SetSSHRegistry(s.sshRegistry, func() []sshfwd.RemoteStatus {
		return []sshfwd.RemoteStatus{{Host: "example.com", State: "connected", Reconnects: 3}}
	})

	frag, err := s.renderUISSHLive("index", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`id="ui-nav-remotes"`,
		`id="ui-ssh-remotes-panel"`,
		"example.com",
		"Connected",
		"ui-dot-green",
	} {
		if !strings.Contains(frag, want) {
			t.Errorf("index payload missing %q:\n%s", want, frag)
		}
	}

	frag, err = s.renderUISSHLive("detail", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(frag, `id="ui-remote-state"`) || !strings.Contains(frag, "Connected") {
		t.Errorf("detail payload missing state line:\n%s", frag)
	}
	// A host that vanished (removed via the CLI) renders a muted placeholder
	// rather than erroring the stream.
	frag, err = s.renderUISSHLive("detail", "gone.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(frag, "Removed") {
		t.Errorf("missing-host detail payload should render Removed:\n%s", frag)
	}
}

// TestUISSHSSE_PatchesOnStateChange drives the stream end to end: the current
// state is patched immediately on subscribe, and a state flip (as the
// reconnect loop or a CLI mutation would cause) is patched on a later tick.
func TestUISSHSSE_PatchesOnStateChange(t *testing.T) {
	oldInterval := uiSSHStreamInterval
	uiSSHStreamInterval = 50 * time.Millisecond
	t.Cleanup(func() { uiSSHStreamInterval = oldInterval })

	s := testServerWithVault(t, uiTestVaultHandler(t))
	s.cfg.Listen = "127.0.0.1:9000"
	s.sshRegistry = newSSHRegistry(t, noopVerifier)
	if _, err := s.sshRegistry.Add(context.Background(), sshfwd.Remote{Host: "example.com"}, sshfwd.AddOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	var state atomic.Value
	state.Store("connecting")
	s.SetSSHRegistry(s.sshRegistry, func() []sshfwd.RemoteStatus {
		return []sshfwd.RemoteStatus{{Host: "example.com", State: state.Load().(string)}}
	})
	s.registerRoutes()
	ts := httptest.NewServer(s.middleware(s.mux))
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, "GET", ts.URL+"/ui/sse/ssh?view=index", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "127.0.0.1:9000"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// The stream sends the current state immediately; wait for it, then flip
	// the state and expect a follow-up patch reflecting the change.
	readUntil := func(marker string) string {
		t.Helper()
		deadline := time.After(5 * time.Second)
		got := make(chan string, 1)
		go func() {
			buf := make([]byte, 1<<16)
			var acc string
			for {
				n, err := resp.Body.Read(buf)
				acc += string(buf[:n])
				if strings.Contains(acc, marker) || err != nil {
					got <- acc
					return
				}
			}
		}()
		select {
		case acc := <-got:
			if !strings.Contains(acc, marker) {
				t.Fatalf("stream ended before %q arrived; got: %s", marker, acc)
			}
			return acc
		case <-deadline:
			t.Fatalf("no patch containing %q arrived", marker)
			return ""
		}
	}
	initial := readUntil("Connecting")
	if !strings.Contains(initial, "datastar-patch-elements") {
		t.Errorf("expected a datastar patch event, got: %s", initial)
	}
	state.Store("connected")
	followUp := readUntil("ui-dot-green")
	if !strings.Contains(followUp, "Connected") {
		t.Errorf("state-change patch missing the new label; got: %s", followUp)
	}
}

// TestUISSHSSE_RejectsBadViews pins the stream's parameter validation.
func TestUISSHSSE_RejectsBadViews(t *testing.T) {
	_, ts := uiTestServer(t)
	for _, path := range []string{
		"/ui/sse/ssh",                        // missing view
		"/ui/sse/ssh?view=bogus",             // unknown view
		"/ui/sse/ssh?view=detail",            // detail without host
		"/ui/sse/ssh?view=detail&host=a%2Fb", // host that fails ValidateHost
	} {
		resp := uiGet(t, ts, path)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", path, resp.StatusCode)
		}
	}
}

// TestUIRemotesPages_SubscribeToSSHStream pins the wiring that makes the
// live updates exist at all: the pages must embed the /ui/sse/ssh
// subscription span — index and detail with their respective views, and NOT
// the unavailable page, whose stream could never emit.
func TestUIRemotesPages_SubscribeToSSHStream(t *testing.T) {
	// Unavailable (no registry): no subscription.
	_, tsNoReg := uiTestServer(t)
	body := uiBody(t, uiGet(t, tsNoReg, "/ui/remotes/"))
	if strings.Contains(body, "/ui/sse/ssh") {
		t.Errorf("unavailable remotes page must not open the ssh stream")
	}

	// Registry configured: index subscribes with view=index, detail with
	// view=detail and its host.
	s := testServerWithVault(t, uiTestVaultHandler(t))
	s.cfg.Listen = "127.0.0.1:9000"
	s.sshRegistry = newSSHRegistry(t, noopVerifier)
	if _, err := s.sshRegistry.Add(context.Background(), sshfwd.Remote{Host: "example.com"}, sshfwd.AddOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	s.registerRoutes()
	ts := httptest.NewServer(s.middleware(s.mux))
	t.Cleanup(ts.Close)

	body = uiBody(t, uiGet(t, ts, "/ui/remotes/"))
	if !strings.Contains(body, `data-init="@get('/ui/sse/ssh?view=index')"`) {
		t.Errorf("remotes index missing the ssh stream subscription")
	}
	body = uiBody(t, uiGet(t, ts, "/ui/remotes/example.com/"))
	// The query string is HTML-attribute escaped (& -> &amp;), so match the
	// two parameters separately.
	if !strings.Contains(body, "/ui/sse/ssh?host=example.com") || !strings.Contains(body, "view=detail") {
		t.Errorf("remote detail page missing the ssh stream subscription")
	}
}

// TestUISSHSSE_Unauthenticated pins that the auth gate runs before view
// validation: an unauthenticated request gets 401 even with a bad view.
func TestUISSHSSE_Unauthenticated(t *testing.T) {
	s := testServer(t)
	s.registerRoutes()
	ts := httptest.NewServer(s.middleware(s.mux))
	t.Cleanup(ts.Close)
	for _, path := range []string{"/ui/sse/ssh?view=index", "/ui/sse/ssh?view=bogus"} {
		resp := uiGet(t, ts, path)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s unauthenticated: status = %d, want 401", path, resp.StatusCode)
		}
	}
}

// TestUIRemoteDetail_ShowsHostKey pins the host-key section of the detail
// page: a pinned key renders its SHA256 fingerprint plus the revealable full
// key, and a CA-covered remote (no pin) renders the explanatory note.
func TestUIRemoteDetail_ShowsHostKey(t *testing.T) {
	key, fingerprint := testHostKey(t)
	s := testServerWithVault(t, uiTestVaultHandler(t))
	s.cfg.Listen = "127.0.0.1:9000"
	s.sshRegistry = newSSHRegistry(t, fixedVerifier{result: sshfwd.VerifyResult{
		Verified:    true,
		HostKey:     key,
		Fingerprint: fingerprint,
	}})
	if _, err := s.sshRegistry.Add(context.Background(), sshfwd.Remote{Host: "pinned.example.com"},
		sshfwd.AddOptions{AcceptFingerprint: fingerprint}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.sshRegistry.Add(context.Background(), sshfwd.Remote{Host: "ca.example.com"},
		sshfwd.AddOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	s.registerRoutes()
	ts := httptest.NewServer(s.middleware(s.mux))
	t.Cleanup(ts.Close)

	// html/template escapes + as &#43; (UTF-7 XSS normalization), so compare
	// against the entity-decoded page.
	body := html.UnescapeString(uiBody(t, uiGet(t, ts, "/ui/remotes/pinned.example.com/")))
	if !strings.Contains(body, fingerprint) {
		t.Errorf("detail page missing host key fingerprint %q", fingerprint)
	}
	if !strings.Contains(body, strings.TrimSpace(key)) {
		t.Errorf("detail page missing the revealable host key")
	}
	if !strings.Contains(body, "Reveal key") {
		t.Errorf("detail page missing the reveal control")
	}

	body = html.UnescapeString(uiBody(t, uiGet(t, ts, "/ui/remotes/ca.example.com/")))
	if !strings.Contains(body, "No pinned host key") {
		t.Errorf("CA-covered remote missing the no-pin note")
	}
	if strings.Contains(body, "Reveal key") {
		t.Errorf("CA-covered remote must not offer a key reveal")
	}
}

func TestUIHostKeyFingerprint(t *testing.T) {
	key, fingerprint := testHostKey(t)
	if got := uiHostKeyFingerprint(key); got != fingerprint {
		t.Errorf("uiHostKeyFingerprint = %q, want %q", got, fingerprint)
	}
	if got := uiHostKeyFingerprint(""); got != "" {
		t.Errorf("empty key fingerprint = %q, want empty", got)
	}
	if got := uiHostKeyFingerprint("not a key"); got != "" {
		t.Errorf("garbage key fingerprint = %q, want empty", got)
	}
}
