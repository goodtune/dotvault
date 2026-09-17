package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
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
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": v.childrenOf(rel)}})
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

// childrenOf returns the direct children of a folder the way Vault's LIST
// does: leaf names for secrets, trailing-slash names for folders, each once.
// Implemented faithfully rather than approximately because the UI's folder
// page only renders when LIST returns something, so a fake that under-reports
// would silently turn a folder assertion into a "secret not found" page that
// happens to contain whatever the test grepped for.
func (v *editVault) childrenOf(rel string) []string {
	prefix := ""
	if rel != "" {
		prefix = rel + "/"
	}
	seen := map[string]bool{}
	keys := []string{}
	for k := range v.secrets {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		name := strings.TrimPrefix(k, prefix)
		if name == "" {
			continue
		}
		if i := strings.Index(name, "/"); i >= 0 {
			name = name[:i+1] // a folder, per Vault's convention
		}
		if !seen[name] {
			seen[name] = true
			keys = append(keys, name)
		}
	}
	sort.Strings(keys)
	return keys
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

	// enrolRunnerMu, matching getEnrolments and InitEnrolments — rulesMu
	// guards a different field and taking it here would model the wrong
	// discipline for anyone copying this helper.
	s.enrolRunnerMu.Lock()
	s.enrolments = map[string]config.Enrolment{"personal/gh": {Engine: "github"}}
	s.enrolRunnerMu.Unlock()

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
	// Asserted exactly, not as "anything but 201": a != check would also pass
	// on a 404 from a route that was never registered.
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
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

// The JSON API's own success and not-found paths, which the browser tests do
// not reach: the UI only ever creates through the form and replaces through
// the editor, so PUT-on-absent and DELETE have no browser equivalent.
func TestSecretAPILifecycle(t *testing.T) {
	s, _, fake := editTestServer(t, []string{"personal"}, nil, nil)

	t.Run("create returns 201", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleSecretWrite(w, httptest.NewRequest("POST", "/api/v1/secrets/personal/token",
			strings.NewReader(`{"fields":{"value":"v"}}`)))
		if w.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201; body = %s", w.Code, w.Body.String())
		}
	})

	t.Run("replace returns 200", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleSecretWrite(w, httptest.NewRequest("PUT", "/api/v1/secrets/personal/token",
			strings.NewReader(`{"fields":{"value":"v2"}}`)))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
		}
	})

	// Replace is not a create: naming nothing is a 404, so a typo'd path does
	// not quietly conjure a secret somewhere the user did not mean.
	t.Run("replace on an absent path is 404", func(t *testing.T) {
		before := len(fake.wrote())
		w := httptest.NewRecorder()
		s.handleSecretWrite(w, httptest.NewRequest("PUT", "/api/v1/secrets/personal/nothing",
			strings.NewReader(`{"fields":{"value":"v"}}`)))
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
		if got := fake.wrote(); len(got) != before {
			t.Errorf("wrote %v for an absent path", got[before:])
		}
	})

	t.Run("delete removes it", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleSecretDelete(w, httptest.NewRequest("DELETE", "/api/v1/secrets/personal/token", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
		}
		if got := fake.deleted(); len(got) != 1 || got[0] != "personal/token" {
			t.Errorf("deleted = %v, want [personal/token]", got)
		}
	})

	t.Run("delete on an absent path is 404", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleSecretDelete(w, httptest.NewRequest("DELETE", "/api/v1/secrets/personal/token", nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})

	t.Run("delete refuses an uneditable path", func(t *testing.T) {
		before := len(fake.deleted())
		w := httptest.NewRecorder()
		s.handleSecretDelete(w, httptest.NewRequest("DELETE", "/api/v1/secrets/gh", nil))
		if w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", w.Code)
		}
		if got := fake.deleted(); len(got) != before {
			t.Errorf("deleted %v for an uneditable path", got[before:])
		}
	})
}

// With several editable roots the create form leaves the path blank rather
// than picking one arbitrarily, which a user might not notice.
func TestCreateFormPrefillWithSeveralRoots(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal", "scratch"}, nil, nil)
	body := uiBody(t, uiGet(t, ts, "/ui/secret-editor/new"))
	if strings.Contains(body, `value="personal/"`) {
		t.Error("create form picked one of several roots to pre-fill")
	}
	// It still says where a path is allowed to go.
	if !strings.Contains(body, "personal/") || !strings.Contains(body, "scratch/") {
		t.Error("create form does not list the editable roots")
	}
}

// The folder page offers "New secret" for a configured root and inside it,
// but not for a folder outside every root — AllowsWithin over the HTTP
// surface rather than only as a unit test.
func TestFolderPageOffersCreateOnlyWhereAllowed(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
		"other/thing":    {"value": "v"},
	})
	// Matched on the ?path= form, which only the folder page's own button
	// carries: the sidebar's New secret entry is deliberately global and
	// appears on every secrets page, so a bare-path match would pass here
	// whatever the folder template did.
	const folderBtn = "/ui/secret-editor/new?path="
	if body := uiBody(t, uiGet(t, ts, "/ui/secrets/personal/")); !strings.Contains(body, folderBtn) {
		t.Error("editable folder has no New secret control")
	}
	if body := uiBody(t, uiGet(t, ts, "/ui/secrets/other/")); strings.Contains(body, folderBtn) {
		t.Error("folder outside every root offers a New secret control")
	}
}

// The editor's re-render after a refusal is the one page in the UI whose body
// carries plaintext secret material, so it must not be cacheable. net/http
// snapshots the header map at WriteHeader, so a handler that sets the status
// before rendering silently loses the Cache-Control the renderer sets —
// which is exactly what this used to do.
func TestSecretEditorErrorPageIsNotCacheable(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	resp := uiPost(t, ts, "/ui/secret-editor/save", map[string]string{
		"create": "0", "path": "personal/token", "document": `{"value": "unclosed`,
	})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
}

// Same ordering trap on the detail page's refused-delete re-render.
func TestSecretDetailErrorPageKeepsHeaders(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	resp := uiPost(t, ts, "/ui/secret-editor/delete", map[string]string{
		"path": "personal/token", "confirm": "wrong",
	})
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
}

// The API's 201 must still be typed: WriteHeader-then-set-Content-Type is a
// no-op, so this pins the writeJSONStatus call rather than the status alone.
func TestSecretAPIWriteResponseIsTypedJSON(t *testing.T) {
	s, _, _ := editTestServer(t, []string{"personal"}, nil, nil)
	w := httptest.NewRecorder()
	s.handleSecretWrite(w, httptest.NewRequest("POST", "/api/v1/secrets/personal/token",
		strings.NewReader(`{"fields":{"value":"v"}}`)))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
}

// A secret sitting at exactly a configured root is refused because the root
// is a direct child of the key space, not because an enrolment owns it. The
// page must not claim otherwise — inferring the reason from "not editable but
// inside an editable subtree" got this wrong.
func TestSecretAtRootIsNotLabelledEnrolmentManaged(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal": {"value": "v"},
	})
	body := uiBody(t, uiGet(t, ts, "/ui/secrets/personal"))
	if strings.Contains(body, "Managed by an enrolment") {
		t.Error("a secret at a configured root is labelled as enrolment-managed")
	}
	if strings.Contains(body, "/ui/secret-editor/edit") {
		t.Error("a secret at a configured root offers an Edit control")
	}
}

// Trailing content after the JSON envelope must be refused, not silently
// ignored: Decode stops at the first complete value, so a body carrying two
// objects would otherwise write the first.
func TestSecretAPIRefusesTrailingContent(t *testing.T) {
	s, _, fake := editTestServer(t, []string{"personal"}, nil, nil)
	w := httptest.NewRecorder()
	s.handleSecretWrite(w, httptest.NewRequest("POST", "/api/v1/secrets/personal/token",
		strings.NewReader(`{"fields":{"a":"1"}}{"fields":{"b":"2"}}`)))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for a body with trailing content", got)
	}
}

// Opening the editor on a path that holds no secret is a 404 rather than an
// empty form that would create one on save.
func TestSecretEditorOnMissingSecretIs404(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, nil)
	resp := uiGet(t, ts, "/ui/secret-editor/edit?path=personal%2Fnothing")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}
