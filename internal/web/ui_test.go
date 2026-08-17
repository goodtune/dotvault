package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
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
}
