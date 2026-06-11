package configsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
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

	// Logout invalidates the session.
	resp = adminDo(t, ts, client, http.MethodPost, "/v1/admin/auth/logout", "", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", resp.StatusCode)
	}
	after, err := client.Get(ts.URL + "/v1/admin/whoami")
	if err != nil {
		t.Fatal(err)
	}
	after.Body.Close()
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("whoami after logout = %d, want 401", after.StatusCode)
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
	// A ".." segment never reaches the handler — net/http cleans the path
	// during routing, so it falls off the route tree entirely. ValidLayerKey
	// still rejects it (covered in its unit test) for non-HTTP callers.
	if resp := adminDo(t, ts, client, http.MethodPut, "/v1/admin/layers/user/..", "application/yaml", "sync:\n  interval: 5m\n"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("PUT layer key user/.. = %d, want 404 (path cleaned before routing)", resp.StatusCode)
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
