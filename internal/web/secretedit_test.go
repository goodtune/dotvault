package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// editVault is a fake Vault holding one user's KVv2 subtree, recording the
// writes and deletes a handler performs so a test can assert that a refusal
// really refused rather than merely reporting one.
type editVault struct {
	mu      sync.Mutex
	secrets map[string]map[string]any
	writes  []string
	deletes []string
	// bodies records the raw bytes of each write, so a test can assert on
	// the JSON the handler actually sent. Decoding and re-inspecting would
	// lose exactly the property worth pinning: json.Number survives to the
	// wire, where a plain decode turns 1000000 back into a float64.
	bodies []string
}

func newEditVault(seed map[string]map[string]any) *editVault {
	v := &editVault{secrets: map[string]map[string]any{}}
	for k, data := range seed {
		v.secrets[k] = data
	}
	return v
}

// rel extracts the path relative to the user root from a KVv2 request path.
func editVaultRel(urlPath string) string {
	const root = "/users/testuser/"
	i := strings.Index(urlPath, root)
	if i < 0 {
		return ""
	}
	return strings.Trim(urlPath[i+len(root):], "/")
}

func (v *editVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	rel := editVaultRel(r.URL.Path)

	switch {
	case r.URL.Query().Get("list") == "true":
		var keys []string
		for k := range v.secrets {
			if rel == "" && !strings.Contains(k, "/") {
				keys = append(keys, k)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}})
	case r.Method == http.MethodDelete:
		v.deletes = append(v.deletes, rel)
		delete(v.secrets, rel)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost, r.Method == http.MethodPut:
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			Data map[string]any `json:"data"`
		}
		json.Unmarshal(raw, &body)
		v.writes = append(v.writes, rel)
		v.bodies = append(v.bodies, string(raw))
		v.secrets[rel] = body.Data
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": 1}})
	default:
		data, ok := v.secrets[rel]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data":     data,
				"metadata": map[string]any{"version": 1},
			},
		})
	}
}

func (v *editVault) wrote() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.writes...)
}

func (v *editVault) deleted() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.deletes...)
}

// editTestServer builds an authenticated server with the given editable
// roots, enrolments and seeded secrets, plus a running frontend.
func editTestServer(t *testing.T, roots []string, enrolments map[string]config.Enrolment, seed map[string]map[string]any) (*Server, *httptest.Server, *editVault) {
	t.Helper()
	fake := newEditVault(seed)
	s := testServerWithVault(t, fake)
	s.cfg.Listen = "127.0.0.1:9000"
	s.cfg.EditablePaths = roots
	s.enrolments = enrolments
	s.registerRoutes()
	ts := httptest.NewServer(s.middleware(s.mux))
	t.Cleanup(ts.Close)
	return s, ts, fake
}

// uiPost issues a same-origin form POST, which is what requireUIWrite demands.
func uiPost(t *testing.T, ts *httptest.Server, path string, form map[string]string) *http.Response {
	t.Helper()
	values := make([]string, 0, len(form))
	for k, v := range form {
		values = append(values, k+"="+urlQueryEscape(v))
	}
	req, err := http.NewRequest("POST", ts.URL+path, strings.NewReader(strings.Join(values, "&")))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "127.0.0.1:9000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://127.0.0.1:9000")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func urlQueryEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == ' ':
			b.WriteByte('+')
		case r == '-' || r == '_' || r == '.' || r == '~' || r == '/' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			b.WriteRune(r)
		default:
			for _, c := range []byte(string(r)) {
				b.WriteString("%")
				const hex = "0123456789ABCDEF"
				b.WriteByte(hex[c>>4])
				b.WriteByte(hex[c&0xf])
			}
		}
	}
	return b.String()
}

// The default — no editable_paths — must leave the UI exactly as read-only as
// it was before the feature existed, routes registered or not.
func TestSecretEditDisabledByDefault(t *testing.T) {
	_, ts, fake := editTestServer(t, nil, nil, map[string]map[string]any{
		"personal/token": {"value": "s3cret"},
	})

	resp := uiPost(t, ts, "/ui/secret-editor/save", map[string]string{
		"create": "0", "path": "personal/token", "document": `{"value":"new"}`,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("save status = %d, want 403", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v with no editable paths configured", got)
	}

	resp = uiGet(t, ts, "/ui/secrets/personal/token")
	if body := uiBody(t, resp); strings.Contains(body, "/ui/secret-editor/edit") {
		t.Error("detail page offers an Edit control with no editable paths configured")
	}
}

// The root of the key space is never editable, whatever the roots say — this
// is the property the whole section exists to hold.
func TestSecretEditRefusesKeySpaceRoot(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"gh": {"oauth_token": "ghp_x"},
	})
	resp := uiPost(t, ts, "/ui/secret-editor/save", map[string]string{
		"create": "0", "path": "gh", "document": `{"oauth_token":"stolen"}`,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for a root-level secret", got)
	}
}

// A path an enrolment owns stays read-only even when it sits inside an
// editable subtree, which is the case the config cannot express on its own.
func TestSecretEditRefusesEnrolmentManagedPath(t *testing.T) {
	enrolments := map[string]config.Enrolment{
		"personal/gh": {Engine: "github"},
	}
	_, ts, fake := editTestServer(t, []string{"personal"}, enrolments, map[string]map[string]any{
		"personal/gh":    {"oauth_token": "ghp_x"},
		"personal/other": {"value": "v"},
	})

	resp := uiPost(t, ts, "/ui/secret-editor/save", map[string]string{
		"create": "0", "path": "personal/gh", "document": `{"oauth_token":"stolen"}`,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("enrolment path save status = %d, want 403", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for an enrolment-managed path", got)
	}

	// Its neighbour in the same subtree is still editable, so the refusal is
	// the enrolment's and not the subtree's.
	resp = uiPost(t, ts, "/ui/secret-editor/save", map[string]string{
		"create": "0", "path": "personal/other", "document": `{"value":"new"}`,
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("neighbour save status = %d, want 303", resp.StatusCode)
	}
}

// The enrolment set is reload-dynamic, so the policy must follow it rather
// than being fixed when the server was constructed.
func TestSecretEditFollowsEnrolmentReload(t *testing.T) {
	s, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/gh": {"oauth_token": "ghp_x"},
	})
	if resp := uiPost(t, ts, "/ui/secret-editor/save", map[string]string{
		"create": "0", "path": "personal/gh", "document": `{"oauth_token":"a"}`,
	}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("pre-reload save status = %d, want 303", resp.StatusCode)
	}

	s.rulesMu.Lock()
	s.enrolments = map[string]config.Enrolment{"personal/gh": {Engine: "github"}}
	s.rulesMu.Unlock()

	if resp := uiPost(t, ts, "/ui/secret-editor/save", map[string]string{
		"create": "0", "path": "personal/gh", "document": `{"oauth_token":"b"}`,
	}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("post-reload save status = %d, want 403", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 1 {
		t.Errorf("wrote %v, want exactly the pre-reload write", got)
	}
}

// Create must not silently replace: a mistyped path landing on an existing
// secret would destroy a credential the user never saw.
func TestSecretCreateRefusesExistingPath(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "original"},
	})
	resp := uiPost(t, ts, "/ui/secret-editor/save", map[string]string{
		"create": "1", "path": "personal/token", "document": `{"value":"clobber"}`,
	})
	// 409, not the generic 422 a form error takes: the form is fine, the
	// path is taken. The UI re-renders either way, but the status is the
	// service layer's own verdict so the JSON API and the browser agree.
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v over an existing secret", got)
	}
}

// A document that fails validation must come back with the user's text
// intact: on this page it may be the only copy of a credential they have.
func TestSecretSaveKeepsDocumentOnValidationError(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	resp := uiPost(t, ts, "/ui/secret-editor/save", map[string]string{
		"create": "0", "path": "personal/token", "document": `{"value": "typed-but-unclosed"`,
	})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "typed-but-unclosed") {
		t.Error("the rejected document was not returned to the user")
	}
}

// Delete removes every version, so it asks the user to type the name back.
func TestSecretDeleteRequiresTypedConfirmation(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})

	resp := uiPost(t, ts, "/ui/secret-editor/delete", map[string]string{
		"path": "personal/token", "confirm": "wrong",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("mis-typed confirm status = %d, want 409", resp.StatusCode)
	}
	if got := fake.deleted(); len(got) != 0 {
		t.Fatalf("deleted %v without a matching confirmation", got)
	}

	resp = uiPost(t, ts, "/ui/secret-editor/delete", map[string]string{
		"path": "personal/token", "confirm": "token",
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("confirmed delete status = %d, want 303", resp.StatusCode)
	}
	// Back to the parent folder, since the secret's own URL would now 404.
	if loc := resp.Header.Get("Location"); loc != "/ui/secrets/personal/" {
		t.Errorf("Location = %q, want /ui/secrets/personal/", loc)
	}
	if got := fake.deleted(); len(got) != 1 || got[0] != "personal/token" {
		t.Errorf("deleted = %v, want [personal/token]", got)
	}
}

// Every /ui/ mutation is Origin-gated; the editor's are no exception.
func TestSecretEditRefusesCrossSitePost(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	req, err := http.NewRequest("POST", ts.URL+"/ui/secret-editor/save",
		strings.NewReader("create=0&path=personal%2Ftoken&document=%7B%22a%22%3A%221%22%7D"))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "127.0.0.1:9000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v on a cross-site POST", got)
	}
}

// The API mutations are CSRF-protected in the ordinary way, unlike the
// peer-action endpoints.
func TestSecretAPIWriteRequiresCSRF(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, nil)
	req, err := http.NewRequest("POST", ts.URL+"/api/v1/secrets/personal/token",
		strings.NewReader(`{"fields":{"value":"v"}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "127.0.0.1:9000"
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		t.Error("a POST with no CSRF token was accepted")
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v without a CSRF token", got)
	}
}

// A path the policy refuses must be refused on the JSON API too, not just in
// the UI — otherwise the read-only presentation is the only control.
func TestSecretAPIRefusesUneditablePath(t *testing.T) {
	s, _, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"gh": {"oauth_token": "ghp_x"},
	})
	req := httptest.NewRequest("PUT", "/api/v1/secrets/gh", strings.NewReader(`{"fields":{"a":"b"}}`))
	w := httptest.NewRecorder()
	s.handleSecretWrite(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for an uneditable path", got)
	}
}

// The body vocabulary mirrors GET ?reveal=true, so a caller can read a
// secret, edit the object it got back, and send it straight here.
func TestSecretAPIWriteRoundTripsRevealShape(t *testing.T) {
	s, _, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "old"},
	})
	req := httptest.NewRequest("PUT", "/api/v1/secrets/personal/token",
		strings.NewReader(`{"fields":{"value":"new","count":1000000}}`))
	w := httptest.NewRecorder()
	s.handleSecretWrite(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if got := fake.wrote(); len(got) != 1 || got[0] != "personal/token" {
		t.Fatalf("wrote = %v, want [personal/token]", got)
	}
	// Large integers reach Vault as written rather than as 1e+06 — the
	// json.Number decoding vaultfs.ParseDocument applies, which is what makes
	// reading a secret and writing it back unchanged lossless.
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if body := fake.bodies[0]; !strings.Contains(body, "1000000") || strings.Contains(body, "1e+06") {
		t.Errorf("write body = %s, want the integer literal 1000000", body)
	}
}

// An empty object is a truncate the caller never finished, not an intentional
// erasure of every field; the mount refuses it and so must this.
func TestSecretAPIRefusesEmptyDocument(t *testing.T) {
	s, _, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	for _, body := range []string{`{"fields":{}}`, `{"fields":null}`, `{}`} {
		w := httptest.NewRecorder()
		s.handleSecretWrite(w, httptest.NewRequest("PUT", "/api/v1/secrets/personal/token", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", body, w.Code)
		}
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for an empty document", got)
	}
}

// The UI is a no-build-step server-rendered surface, so a template that does
// not execute is only visible at runtime. These drive the real templates
// through the shapes a browser actually produces.

func TestSecretEditorPagesRender(t *testing.T) {
	enrolments := map[string]config.Enrolment{"personal/gh": {Engine: "github"}}
	_, ts, _ := editTestServer(t, []string{"personal"}, enrolments, map[string]map[string]any{
		"personal/token": {"value": "s3cret", "count": 1000000},
		"personal/gh":    {"oauth_token": "ghp_x"},
	})

	t.Run("create form", func(t *testing.T) {
		body := uiBody(t, uiGet(t, ts, "/ui/secret-editor/new"))
		// With exactly one editable root the path input starts inside it,
		// rather than making the user guess where a path is allowed to go.
		if !strings.Contains(body, `value="personal/"`) {
			t.Error("create form does not pre-fill the sole editable root")
		}
		if !strings.Contains(body, `action="/ui/secret-editor/save"`) {
			t.Error("create form does not post to the save endpoint")
		}
	})

	t.Run("editor carries the document", func(t *testing.T) {
		body := uiBody(t, uiGet(t, ts, "/ui/secret-editor/edit?path=personal%2Ftoken"))
		if !strings.Contains(body, "s3cret") {
			t.Error("editor does not carry the secret's values")
		}
		// The same lossless rendering the FUSE mount produces.
		if !strings.Contains(body, "1000000") {
			t.Error("editor lost integer precision rendering the document")
		}
	})

	t.Run("editor refuses an enrolment-managed path", func(t *testing.T) {
		resp := uiGet(t, ts, "/ui/secret-editor/edit?path=personal%2Fgh")
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("detail page offers controls only where editable", func(t *testing.T) {
		editable := uiBody(t, uiGet(t, ts, "/ui/secrets/personal/token"))
		if !strings.Contains(editable, "/ui/secret-editor/edit") {
			t.Error("editable secret has no Edit control")
		}
		if !strings.Contains(editable, `action="/ui/secret-editor/delete"`) {
			t.Error("editable secret has no Delete form")
		}

		managed := uiBody(t, uiGet(t, ts, "/ui/secrets/personal/gh"))
		if strings.Contains(managed, "/ui/secret-editor/edit") {
			t.Error("enrolment-managed secret offers an Edit control")
		}
		// Saying why beats silently dropping the controls: the user can see
		// editing work on the secret beside this one.
		if !strings.Contains(managed, "Managed by an enrolment") {
			t.Error("enrolment-managed secret does not explain why it is read-only")
		}
	})

	t.Run("sidebar offers New secret", func(t *testing.T) {
		body := uiBody(t, uiGet(t, ts, "/ui/secrets/"))
		if !strings.Contains(body, "/ui/secret-editor/new") {
			t.Error("Secrets sidebar has no New secret entry")
		}
	})
}

// The whole create gesture as a browser performs it: open the form, post it,
// follow the redirect, and find the secret where the UI says it is.
func TestSecretCreateFlowEndToEnd(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, nil)

	if body := uiBody(t, uiGet(t, ts, "/ui/secret-editor/new")); !strings.Contains(body, "secret-document") {
		t.Fatal("create form did not render its document field")
	}

	resp := uiPost(t, ts, "/ui/secret-editor/save", map[string]string{
		"create": "1", "path": "personal/aws/dev", "document": `{"key_id":"AKIA","secret":"s3cret"}`,
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save status = %d, want 303; body = %s", resp.StatusCode, uiBody(t, resp))
	}
	loc := resp.Header.Get("Location")
	if loc != "/ui/secrets/personal/aws/dev" {
		t.Fatalf("Location = %q, want /ui/secrets/personal/aws/dev", loc)
	}
	if got := fake.wrote(); len(got) != 1 || got[0] != "personal/aws/dev" {
		t.Fatalf("wrote = %v, want [personal/aws/dev]", got)
	}

	// Following the redirect lands on the detail page, which still masks
	// every value — the editor is the only place they appear.
	body := uiBody(t, uiGet(t, ts, loc))
	if !strings.Contains(body, "key_id") {
		t.Error("detail page does not list the new secret's fields")
	}
	if strings.Contains(body, "s3cret") {
		t.Error("detail page leaked a secret value")
	}
}

// A path is always resolved beneath the user's own prefix; a traversal
// attempt is rejected rather than collapsed.
func TestSecretEditRejectsTraversal(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, nil)
	for _, bad := range []string{"personal/../../otheruser/gh", "personal/./x"} {
		resp := uiPost(t, ts, "/ui/secret-editor/save", map[string]string{
			"create": "1", "path": bad, "document": `{"a":"b"}`,
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("path %q: status = %d, want 400", bad, resp.StatusCode)
		}
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for a traversal path", got)
	}
}
