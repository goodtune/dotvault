package configsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/configsvc/groups"
	"github.com/goodtune/dotvault/internal/configsvc/store"
)

// fakeAuth authenticates a fixed credential table.
type fakeAuth map[string]string

func (f fakeAuth) Authenticate(_ context.Context, username, password string) error {
	if f[username] == "" || f[username] != password {
		return ErrBadCredentials
	}
	return nil
}

const adminGroup = "dotvault-admins"

// newAdminClient stands up an admin-enabled server (sqlite store, static
// resolver, fake password backend with alice as an admin and bob as a
// non-admin) and a cookie-keeping client.
func newAdminClient(t *testing.T) (store.Store, *httptest.Server, *http.Client) {
	t.Helper()
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.PutGroups(ctx, "alice", []string{adminGroup, "sydney"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutGroups(ctx, "bob", []string{"sydney"}); err != nil {
		t.Fatal(err)
	}

	svc := NewServer(st, groups.NewStatic(st))
	svc.EnableAdmin(AdminConfig{Group: adminGroup, SessionTTL: time.Hour},
		fakeAuth{"alice": "s3cret", "bob": "hunter2"})
	ts := httptest.NewServer(svc.Handler())
	t.Cleanup(ts.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return st, ts, &http.Client{Jar: jar}
}

func login(t *testing.T, ts *httptest.Server, client *http.Client, username, password string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, username, password)
	resp, err := client.Post(ts.URL+"/v1/admin/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func csrfToken(t *testing.T, ts *httptest.Server, client *http.Client) string {
	t.Helper()
	resp, err := client.Get(ts.URL + "/v1/admin/csrf")
	if err != nil {
		t.Fatalf("csrf: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/admin/csrf = %d", resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Token
}

// adminDo issues a request with the client's session cookie and a fresh
// CSRF token.
func adminDo(t *testing.T, ts *httptest.Server, client *http.Client, method, path, contentType, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", csrfToken(t, ts, client))
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestAdminAuthentication(t *testing.T) {
	_, ts, client := newAdminClient(t)

	// Everything is locked down before login.
	for _, path := range []string{"/v1/admin/whoami", "/v1/admin/layers", "/v1/admin/csrf", "/v1/admin/service-accounts"} {
		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("GET %s before login = %d, want 401", path, resp.StatusCode)
		}
	}

	if resp := login(t, ts, client, "alice", "wrong"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login with wrong password = %d, want 401", resp.StatusCode)
	}
	if resp := login(t, ts, client, "mallory", "anything"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login as unknown user = %d, want 401", resp.StatusCode)
	}
	// bob authenticates fine but lacks the admin group.
	if resp := login(t, ts, client, "bob", "hunter2"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("login as non-admin = %d, want 403", resp.StatusCode)
	}

	resp := login(t, ts, client, "alice", "s3cret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login as admin = %d, want 200", resp.StatusCode)
	}

	whoami, err := client.Get(ts.URL + "/v1/admin/whoami")
	if err != nil {
		t.Fatal(err)
	}
	defer whoami.Body.Close()
	var identity Identity
	if err := json.NewDecoder(whoami.Body).Decode(&identity); err != nil {
		t.Fatal(err)
	}
	if identity.Name != "alice" || identity.Kind != identityKindUser {
		t.Fatalf("whoami = %+v", identity)
	}

	// Capture the raw session cookie before logout so we can prove
	// *server-side* invalidation: the MaxAge=-1 response makes the jar drop
	// the cookie anyway, so a jar-based request would 401 even if the
	// server kept the session alive.
	tsURL, _ := url.Parse(ts.URL)
	var rawSession string
	for _, c := range client.Jar.Cookies(tsURL) {
		if c.Name == sessionCookieName {
			rawSession = c.Value
		}
	}
	if rawSession == "" {
		t.Fatal("no session cookie in jar after login")
	}

	resp = adminDo(t, ts, client, http.MethodPost, "/v1/admin/auth/logout", "", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", resp.StatusCode)
	}

	replay, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/admin/whoami", nil)
	replay.AddCookie(&http.Cookie{Name: sessionCookieName, Value: rawSession})
	after, err := http.DefaultClient.Do(replay)
	if err != nil {
		t.Fatal(err)
	}
	after.Body.Close()
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("whoami with replayed pre-logout cookie = %d, want 401 (session must be invalidated server-side)", after.StatusCode)
	}
}

func TestSessionExpiry(t *testing.T) {
	s := newSessionStore(time.Hour)
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }

	id := s.create(Identity{Name: "alice", Kind: identityKindUser})
	if _, ok := s.get(id); !ok {
		t.Fatal("fresh session not found")
	}
	now = now.Add(2 * time.Hour)
	if _, ok := s.get(id); ok {
		t.Fatal("expired session still valid")
	}
}

func TestSessionStoreBounded(t *testing.T) {
	s := newSessionStore(time.Hour)
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }

	for i := 0; i < maxSessions; i++ {
		s.create(Identity{Name: "user", Kind: identityKindUser})
	}
	// All live: the next create resets rather than growing past the cap.
	s.create(Identity{Name: "user", Kind: identityKindUser})
	s.mu.Lock()
	live := len(s.sessions)
	s.mu.Unlock()
	if live != 1 {
		t.Fatalf("sessions after overflow = %d, want 1 (map reset)", live)
	}

	// Refill, expire everything, then one more: the sweep path keeps the
	// new session only.
	for i := 0; i < maxSessions-1; i++ {
		s.create(Identity{Name: "user", Kind: identityKindUser})
	}
	now = now.Add(2 * time.Hour)
	s.create(Identity{Name: "late", Kind: identityKindUser})
	s.mu.Lock()
	live = len(s.sessions)
	s.mu.Unlock()
	if live != 1 {
		t.Fatalf("sessions after sweep = %d, want 1", live)
	}
}

func TestLoginRateLimited(t *testing.T) {
	_, ts, client := newAdminClient(t)
	// Burn the per-address budget with bad credentials; the next attempt is
	// refused before the authenticator runs, even with the right password.
	for i := 0; i < loginLimit; i++ {
		if resp := login(t, ts, client, "alice", "wrong"); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, resp.StatusCode)
		}
	}
	if resp := login(t, ts, client, "alice", "s3cret"); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("attempt past the limit = %d, want 429", resp.StatusCode)
	}
}

func TestLoginLimiterWindowReset(t *testing.T) {
	l := newLoginLimiter()
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }

	for i := 0; i < loginLimit; i++ {
		if !l.allow("10.0.0.1") {
			t.Fatalf("attempt %d within budget refused", i+1)
		}
	}
	if l.allow("10.0.0.1") {
		t.Fatal("attempt past the budget allowed")
	}
	// A different address has its own budget.
	if !l.allow("10.0.0.2") {
		t.Fatal("independent address throttled")
	}
	// The window expires and the budget resets.
	now = now.Add(2 * loginWindow)
	if !l.allow("10.0.0.1") {
		t.Fatal("attempt after window reset refused")
	}
}

func TestCSRFTokenExpiry(t *testing.T) {
	c := newCSRFStore()
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }

	token := c.issue()
	now = now.Add(csrfTokenTTL + time.Minute)
	if c.consume(token) {
		t.Fatal("expired CSRF token accepted")
	}
	// And a fresh one still works exactly once.
	token = c.issue()
	if !c.consume(token) {
		t.Fatal("fresh CSRF token rejected")
	}
	if c.consume(token) {
		t.Fatal("CSRF token accepted twice")
	}
}

func TestAdminCSRFRequiredForSessionMutations(t *testing.T) {
	_, ts, client := newAdminClient(t)
	login(t, ts, client, "alice", "s3cret")

	// No token → 403.
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/v1/admin/layers/global", strings.NewReader("sync:\n  interval: 5m\n"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("PUT without CSRF token = %d, want 403", resp.StatusCode)
	}

	// One-time use: a consumed token is rejected on replay.
	token := csrfToken(t, ts, client)
	for i, want := range []int{http.StatusNoContent, http.StatusForbidden} {
		req, _ := http.NewRequest(http.MethodPut, ts.URL+"/v1/admin/layers/global", strings.NewReader("sync:\n  interval: 5m\n"))
		req.Header.Set("X-CSRF-Token", token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("PUT with token (use %d) = %d, want %d", i+1, resp.StatusCode, want)
		}
	}
}

func TestAdminLayerCRUD(t *testing.T) {
	_, ts, client := newAdminClient(t)
	login(t, ts, client, "alice", "s3cret")

	doc := "rules:\n  - name: r\n    vault_key: k\n    target: {path: ~/r.txt, format: text}\n"
	if resp := adminDo(t, ts, client, http.MethodPut, "/v1/admin/layers/group/sydney", "application/yaml", doc); resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT layer = %d (%s), want 204", resp.StatusCode, body)
	}

	resp := adminDo(t, ts, client, http.MethodGet, "/v1/admin/layers/group/sydney", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET layer = %d, want 200", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != doc {
		t.Fatalf("GET layer = %q, want stored bytes verbatim", got)
	}

	resp = adminDo(t, ts, client, http.MethodGet, "/v1/admin/layers?prefix=group/", "", "")
	var list struct {
		Keys []string `json:"keys"`
	}
	json.NewDecoder(resp.Body).Decode(&list)
	if len(list.Keys) != 1 || list.Keys[0] != "group/sydney" {
		t.Fatalf("layer list = %v", list.Keys)
	}

	// Validation failures surface the daemon's own error text.
	resp = adminDo(t, ts, client, http.MethodPut, "/v1/admin/layers/group/evil", "application/yaml", "vault:\n  address: https://evil\n")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT static-section layer = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "local-only") {
		t.Fatalf("PUT static-section layer body = %q", body)
	}

	for _, key := range []string{"os/Linux", "nonsense", "global/extra"} {
		if resp := adminDo(t, ts, client, http.MethodPut, "/v1/admin/layers/"+key, "application/yaml", "sync:\n  interval: 5m\n"); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("PUT layer key %q = %d, want 400", key, resp.StatusCode)
		}
	}
	// A literal ".." never reaches the PUT handler: the mux 301s to the
	// cleaned path, the client replays it as a GET of the collapsed key,
	// and the GET handler's validation rejects that. Either way: no write.
	if resp := adminDo(t, ts, client, http.MethodPut, "/v1/admin/layers/user/..", "application/yaml", "sync:\n  interval: 5m\n"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT layer key user/.. = %d, want 400 after clean-path redirect", resp.StatusCode)
	}
	// Percent-encoded traversal DOES survive routing (PathValue decodes
	// after matching), so the handler-level validation is load-bearing —
	// on GET and DELETE too, where the Vault store's path.Join would
	// otherwise collapse the ".." into an escape from the layers/ subtree.
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		resp := adminDo(t, ts, client, method, "/v1/admin/layers/group/%2E%2E%2Fescape", "application/yaml", "sync:\n  interval: 5m\n")
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s encoded-traversal layer key = %d, want 400", method, resp.StatusCode)
		}
	}
	for _, path := range []string{"/v1/admin/groups/%2E%2E%2Fescape", "/v1/admin/service-accounts/%2E%2E%2Fescape"} {
		for _, method := range []string{http.MethodGet, http.MethodDelete} {
			if resp := adminDo(t, ts, client, method, path, "", ""); resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s %s = %d, want 400", method, path, resp.StatusCode)
			}
		}
	}

	if resp := adminDo(t, ts, client, http.MethodDelete, "/v1/admin/layers/group/sydney", "", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE layer = %d, want 204", resp.StatusCode)
	}
	if resp := adminDo(t, ts, client, http.MethodGet, "/v1/admin/layers/group/sydney", "", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET deleted layer = %d, want 404", resp.StatusCode)
	}
}

func TestAdminGroupsCRUD(t *testing.T) {
	_, ts, client := newAdminClient(t)
	login(t, ts, client, "alice", "s3cret")

	if resp := adminDo(t, ts, client, http.MethodPut, "/v1/admin/groups/carol", "application/json", `{"groups":["newyork"]}`); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT groups = %d, want 204", resp.StatusCode)
	}
	resp := adminDo(t, ts, client, http.MethodGet, "/v1/admin/groups/carol", "", "")
	var entry struct {
		User   string   `json:"user"`
		Groups []string `json:"groups"`
	}
	json.NewDecoder(resp.Body).Decode(&entry)
	if entry.User != "carol" || len(entry.Groups) != 1 || entry.Groups[0] != "newyork" {
		t.Fatalf("GET groups = %+v", entry)
	}

	if resp := adminDo(t, ts, client, http.MethodPut, "/v1/admin/groups/carol", "application/json", `{"groups":["new/york"]}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT groups with traversal group name = %d, want 400", resp.StatusCode)
	}

	resp = adminDo(t, ts, client, http.MethodGet, "/v1/admin/groups", "", "")
	var users struct {
		Users []string `json:"users"`
	}
	json.NewDecoder(resp.Body).Decode(&users)
	if !contains(users.Users, "carol") || !contains(users.Users, "alice") {
		t.Fatalf("groups list = %v", users.Users)
	}

	if resp := adminDo(t, ts, client, http.MethodDelete, "/v1/admin/groups/carol", "", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE groups = %d, want 204", resp.StatusCode)
	}
	if resp := adminDo(t, ts, client, http.MethodGet, "/v1/admin/groups/carol", "", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET deleted groups = %d, want 404", resp.StatusCode)
	}
}

func TestAdminServiceAccountCRUD(t *testing.T) {
	_, ts, client := newAdminClient(t)
	login(t, ts, client, "alice", "s3cret")

	resp := adminDo(t, ts, client, http.MethodPut, "/v1/admin/service-accounts/terraform", "application/json", `{"description":"IaC pipeline"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT service account = %d, want 200", resp.StatusCode)
	}
	var sa store.ServiceAccount
	json.NewDecoder(resp.Body).Decode(&sa)
	if sa.Name != "terraform" || sa.Disabled || sa.CreatedAt.IsZero() {
		t.Fatalf("created service account = %+v", sa)
	}
	created := sa.CreatedAt

	// Update keeps the creation timestamp (upsert semantics).
	resp = adminDo(t, ts, client, http.MethodPut, "/v1/admin/service-accounts/terraform", "application/json", `{"description":"IaC pipeline","disabled":true}`)
	json.NewDecoder(resp.Body).Decode(&sa)
	if !sa.Disabled || !sa.CreatedAt.Equal(created) {
		t.Fatalf("updated service account = %+v (created %v)", sa, created)
	}

	if resp := adminDo(t, ts, client, http.MethodPut, "/v1/admin/service-accounts/bad..name", "application/json", `{}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT service account with invalid name = %d, want 400", resp.StatusCode)
	}

	resp = adminDo(t, ts, client, http.MethodGet, "/v1/admin/service-accounts", "", "")
	var names struct {
		Names []string `json:"names"`
	}
	json.NewDecoder(resp.Body).Decode(&names)
	if len(names.Names) != 1 || names.Names[0] != "terraform" {
		t.Fatalf("service account list = %v", names.Names)
	}

	if resp := adminDo(t, ts, client, http.MethodDelete, "/v1/admin/service-accounts/terraform", "", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE service account = %d, want 204", resp.StatusCode)
	}
	if resp := adminDo(t, ts, client, http.MethodGet, "/v1/admin/service-accounts/terraform", "", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET deleted service account = %d, want 404", resp.StatusCode)
	}
}

func TestAdminPreview(t *testing.T) {
	st, ts, client := newAdminClient(t)
	login(t, ts, client, "alice", "s3cret")
	putLayer(t, st, "global", "sync:\n  interval: 15m\n")
	putLayer(t, st, "group/sydney", "sync:\n  interval: 5m\n")

	// Resolver-driven: alice is in sydney, so the group layer applies.
	resp := adminDo(t, ts, client, http.MethodGet, "/v1/admin/preview?os=linux&user=alice", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preview = %d, want 200", resp.StatusCode)
	}
	if etag := resp.Header.Get("ETag"); etag == "" {
		t.Fatal("preview carries no ETag")
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "5m") {
		t.Fatalf("preview did not apply resolver groups:\n%s", body)
	}

	// Explicit empty groups bypass the resolver.
	resp = adminDo(t, ts, client, http.MethodGet, "/v1/admin/preview?os=linux&user=alice&groups=", "", "")
	body, _ = io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "15m") {
		t.Fatalf("preview with explicit empty groups still applied group layer:\n%s", body)
	}

	if resp := adminDo(t, ts, client, http.MethodGet, "/v1/admin/preview?os=../etc&user=alice", "", ""); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("preview with traversal os = %d, want 400", resp.StatusCode)
	}
}

func TestAdminLoginNotConfigured(t *testing.T) {
	st := newTestStore(t)
	svc := NewServer(st, groups.NewStatic(st))
	svc.EnableAdmin(AdminConfig{Group: adminGroup, SessionTTL: time.Hour}, nil)
	ts := httptest.NewServer(svc.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/v1/admin/auth/login", "application/json", strings.NewReader(`{"username":"a","password":"b"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("login without password backend = %d, want 404", resp.StatusCode)
	}
}

func TestAdminRoutesAbsentWhenDisabled(t *testing.T) {
	_, ts := newTestServer(t) // plain server, no EnableAdmin
	resp, err := http.Get(ts.URL + "/v1/admin/whoami")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("admin route on non-admin server = %d, want 404", resp.StatusCode)
	}
	resp, err = http.Get(ts.URL + "/admin/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("admin UI on non-admin server = %d, want 404", resp.StatusCode)
	}
}

func TestAdminUIServed(t *testing.T) {
	_, ts, _ := newAdminClient(t)
	resp, err := http.Get(ts.URL + "/admin/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/ = %d, want 200", resp.StatusCode)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); csp != "default-src 'self'" {
		t.Fatalf("CSP = %q", csp)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "dotvault-config") {
		t.Fatal("UI index does not look like the admin page")
	}
}
