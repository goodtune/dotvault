package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
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
	// listFails makes every LIST answer 403, standing in for a Vault policy
	// that grants write on a path without granting LIST on the folder above.
	listFails bool
	// deleteFails makes every DELETE answer 403, which is what turns a rename
	// into the half-completed state the orphan path has to handle. A 4xx
	// rather than a 5xx deliberately: the Vault SDK retries 5xx with backoff,
	// which would make this test pay several seconds for nothing.
	deleteFails bool
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
		if v.listFails {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": v.childrenOf(rel)}})
	case r.Method == http.MethodDelete:
		if v.deleteFails {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
			return
		}
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
// It takes url.Values rather than a map because the editor form posts repeated
// field_name/field_value controls, which a map cannot express — and their
// order is load-bearing, since the handler pairs them positionally.
func uiPost(t *testing.T, ts *httptest.Server, path string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", ts.URL+path, strings.NewReader(form.Encode()))
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

// editForm builds a save/create submission: the implicit prefix, the name,
// and one field_name/field_value pair per field. Field order is stable so the
// positional pairing the handler relies on is exercised as a browser would
// produce it.
func editForm(prefix, name string, fields ...string) url.Values {
	v := url.Values{}
	v.Set("prefix", prefix)
	v.Set("name", name)
	for i := 0; i+1 < len(fields); i += 2 {
		v.Add("field_name", fields[i])
		v.Add("field_value", fields[i+1])
	}
	return v
}

// The default — no editable_paths — must leave the UI exactly as read-only as
// it was before the feature existed, routes registered or not.
func TestSecretEditDisabledByDefault(t *testing.T) {
	_, ts, fake := editTestServer(t, nil, nil, map[string]map[string]any{
		"personal/token": {"value": "s3cret"},
	})

	form := editForm("personal", "token", "value", "new")
	form.Set("path", "personal/token")
	resp := uiPost(t, ts, "/ui/secret-editor/save", form)
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
	form := editForm("", "gh", "oauth_token", "stolen")
	form.Set("path", "gh")
	resp := uiPost(t, ts, "/ui/secret-editor/save", form)
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

	managed := editForm("personal", "gh", "oauth_token", "stolen")
	managed.Set("path", "personal/gh")
	resp := uiPost(t, ts, "/ui/secret-editor/save", managed)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("enrolment path save status = %d, want 403", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for an enrolment-managed path", got)
	}

	// Its neighbour in the same subtree is still editable, so the refusal is
	// the enrolment's and not the subtree's.
	neighbour := editForm("personal", "other", "value", "new")
	neighbour.Set("path", "personal/other")
	resp = uiPost(t, ts, "/ui/secret-editor/save", neighbour)
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
	before := editForm("personal", "gh", "oauth_token", "a")
	before.Set("path", "personal/gh")
	if resp := uiPost(t, ts, "/ui/secret-editor/save", before); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("pre-reload save status = %d, want 303", resp.StatusCode)
	}

	// enrolRunnerMu, matching getEnrolments and InitEnrolments — rulesMu
	// guards a different field and taking it here would model the wrong
	// discipline for anyone copying this helper.
	s.enrolRunnerMu.Lock()
	s.enrolments = map[string]config.Enrolment{"personal/gh": {Engine: "github"}}
	s.enrolRunnerMu.Unlock()

	after := editForm("personal", "gh", "oauth_token", "b")
	after.Set("path", "personal/gh")
	if resp := uiPost(t, ts, "/ui/secret-editor/save", after); resp.StatusCode != http.StatusForbidden {
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
	resp := uiPost(t, ts, "/ui/secret-editor/create", editForm("personal", "token", "value", "clobber"))
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

// A submission that fails validation must come back with the user's rows
// intact: on this page they may be the only copy of a credential just typed.
func TestSecretSaveKeepsRowsOnValidationError(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	form := editForm("personal", "", "value", "typed-but-unsaved")
	form.Set("path", "personal/token")
	resp := uiPost(t, ts, "/ui/secret-editor/save", form)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "typed-but-unsaved") {
		t.Error("the rejected field value was not returned to the user")
	}
}

// Delete removes every version, so it asks the user to type the name back.
func TestSecretDeleteRequiresTypedConfirmation(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})

	resp := uiPost(t, ts, "/ui/secret-editor/delete", url.Values{
		"path": {"personal/token"}, "confirm": {"wrong"},
	})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("mis-typed confirm status = %d, want 409", resp.StatusCode)
	}
	if got := fake.deleted(); len(got) != 0 {
		t.Fatalf("deleted %v without a matching confirmation", got)
	}

	resp = uiPost(t, ts, "/ui/secret-editor/delete", url.Values{
		"path": {"personal/token"}, "confirm": {"token"},
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
		body := uiBody(t, uiGet(t, ts, "/ui/secret-editor/new?path=personal"))
		if !strings.Contains(body, `action="/ui/secret-editor/create"`) {
			t.Error("create form does not post to the create endpoint")
		}
		// The prefix is context, not something to retype: it is shown as
		// static text and carried in a hidden field.
		if !strings.Contains(body, `name="prefix"`) {
			t.Error("create form does not carry the prefix")
		}
		if !strings.Contains(body, `name="field_name"`) {
			t.Error("create form renders no field rows")
		}
	})

	// A folder outside every editable subtree cannot be created in, and the
	// form says so rather than rendering something that would be refused.
	t.Run("create form refuses an uneditable folder", func(t *testing.T) {
		if resp := uiGet(t, ts, "/ui/secret-editor/new?path=other"); resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
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

	// The sidebar carries no "New secret" action of its own — creating starts
	// from the folder it lands in, which is why the folders have to be there.
	t.Run("sidebar lists editable roots, not a New secret action", func(t *testing.T) {
		body := uiBody(t, uiGet(t, ts, "/ui/secrets/"))
		if !strings.Contains(body, "/ui/secrets/personal/") {
			t.Error("Secrets sidebar does not list the editable root")
		}
		if strings.Contains(body, "/ui/secret-editor/new\"") {
			t.Error("Secrets sidebar still carries a bare New secret entry")
		}
	})
}

// The whole create gesture as a browser performs it: open the form, post it,
// follow the redirect, and find the secret where the UI says it is.
func TestSecretCreateFlowEndToEnd(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, nil)

	form := uiBody(t, uiGet(t, ts, "/ui/secret-editor/new?path=personal"))
	if !strings.Contains(form, `name="field_name"`) || !strings.Contains(form, `name="field_value"`) {
		t.Fatal("create form did not render field rows")
	}
	// The prefix is implicit: shown, but not something the user retypes.
	if !strings.Contains(form, "personal/") {
		t.Error("create form does not show the implicit prefix")
	}

	resp := uiPost(t, ts, "/ui/secret-editor/create",
		editForm("personal", "aws/dev", "key_id", "AKIA", "secret", "s3cret"))
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create status = %d, want 303; body = %s", resp.StatusCode, uiBody(t, resp))
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
	for _, bad := range []string{"../../otheruser/gh", "./x"} {
		resp := uiPost(t, ts, "/ui/secret-editor/create", editForm("personal", bad, "a", "b"))
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

// An editable root holds nothing until the first secret is written into it,
// so the sidebar has to list it from configuration rather than from a Vault
// listing — a folder you cannot see is a folder you cannot create in.
func TestSidebarListsEditableRootsThatDoNotExistYet(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal", "scratch/notes"}, nil, map[string]map[string]any{
		"gh": {"oauth_token": "ghp_x"},
	})
	body := uiBody(t, uiGet(t, ts, "/ui/secrets/"))
	// A multi-segment root is listed at its full path: the nav nests one
	// level, so naming the whole path is what keeps it one click away.
	for _, want := range []string{"/ui/secrets/personal/", "/ui/secrets/scratch/notes/"} {
		if !strings.Contains(body, want) {
			t.Errorf("sidebar does not link %s", want)
		}
	}
}

// An empty editable folder must render as a folder with a create control,
// not fall through to "secret not found" — that is its normal starting state.
func TestEmptyEditableFolderRendersWithCreateControl(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, nil)
	resp := uiGet(t, ts, "/ui/secrets/personal/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := uiBody(t, resp)
	if !strings.Contains(body, "/ui/secret-editor/new?path=") {
		t.Error("empty editable folder offers no New secret control")
	}
	if strings.Contains(body, "secret not found") {
		t.Error("empty editable folder rendered as a missing secret")
	}
}

// A Vault policy granting write need not grant LIST, and a KVv2 LIST of a
// prefix holding nothing is a 404 besides. Both are the normal state of a
// fresh editable root, so neither may surface as an error on the one folder
// the user is being invited to create in — while a failure anywhere else
// still does.
func TestListFailureToleratedOnlyInsideEditablePaths(t *testing.T) {
	fake := newEditVault(nil)
	fake.listFails = true
	s := testServerWithVault(t, fake)
	s.cfg.Listen = "127.0.0.1:9000"
	s.cfg.EditablePaths = []string{"personal"}
	s.registerRoutes()
	ts := httptest.NewServer(s.middleware(s.mux))
	t.Cleanup(ts.Close)

	if resp := uiGet(t, ts, "/ui/secrets/personal/"); resp.StatusCode != http.StatusOK {
		t.Errorf("editable folder status = %d, want 200", resp.StatusCode)
	}
	if keys, err := s.listSecretKeys(t.Context(), "personal"); err != nil || keys != nil {
		t.Errorf("listSecretKeys(personal) = %v, %v; want nil, nil", keys, err)
	}
	if _, err := s.listSecretKeys(t.Context(), "elsewhere"); err == nil {
		t.Error("a listing failure outside every editable path was swallowed")
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
	form := editForm("personal", "", "value", "v")
	form.Set("path", "personal/token")
	resp := uiPost(t, ts, "/ui/secret-editor/save", form)
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
	resp := uiPost(t, ts, "/ui/secret-editor/delete", url.Values{
		"path": {"personal/token"}, "confirm": {"wrong"},
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

// applyFieldPatch is the heart of "only patch what changed", so its rules are
// pinned directly rather than only through the HTTP surface.
func TestApplyFieldPatch(t *testing.T) {
	orig := func(names ...string) map[string]struct{} {
		m := map[string]struct{}{}
		for _, n := range names {
			m[n] = struct{}{}
		}
		return m
	}

	t.Run("an unchanged submission writes nothing", func(t *testing.T) {
		current := map[string]any{"a": "1", "b": "2"}
		_, changed := applyFieldPatch(current, fieldPatch{
			Submitted: map[string]string{"a": "1", "b": "2"},
			Original:  orig("a", "b"),
		})
		if changed {
			t.Error("changed reported for an identical submission")
		}
	})

	t.Run("a cleared field is deleted", func(t *testing.T) {
		current := map[string]any{"a": "1", "b": "2"}
		got, changed := applyFieldPatch(current, fieldPatch{
			Submitted: map[string]string{"a": "1"},
			Original:  orig("a", "b"),
		})
		if !changed {
			t.Error("changed not reported for a deletion")
		}
		if _, still := got["b"]; still {
			t.Error("b survived being cleared")
		}
	})

	// The reason the editor patches instead of replacing: a field another
	// writer added between the page load and the save is in neither Submitted
	// nor Original, and a whole-document write would silently delete it.
	t.Run("a concurrently added field survives", func(t *testing.T) {
		current := map[string]any{"a": "1", "added_elsewhere": "x"}
		got, _ := applyFieldPatch(current, fieldPatch{
			Submitted: map[string]string{"a": "2"},
			Original:  orig("a"),
		})
		if got["added_elsewhere"] != "x" {
			t.Errorf("concurrently added field = %#v, want preserved", got["added_elsewhere"])
		}
		if got["a"] != "2" {
			t.Errorf("a = %#v, want the submitted value", got["a"])
		}
	})

	// Renaming a *field* (clearing a row's name and typing another) is a
	// delete plus an add, which only works because the two halves are driven
	// by different inputs: the new name comes from Submitted, the old one
	// goes because it is in Original with no row.
	t.Run("renaming a field moves its value", func(t *testing.T) {
		current := map[string]any{"old": "v", "keep": "k"}
		got, changed := applyFieldPatch(current, fieldPatch{
			Submitted: map[string]string{"new": "v", "keep": "k"},
			Original:  orig("old", "keep"),
		})
		if !changed {
			t.Error("a field rename was not reported as a change")
		}
		if _, still := got["old"]; still {
			t.Error("the old field name survived")
		}
		if got["new"] != "v" || got["keep"] != "k" {
			t.Errorf("result = %#v, want the value moved and the neighbour kept", got)
		}
	})

	// A key/value form can only carry strings, so an untouched number must
	// keep its type rather than being rewritten as its own string form.
	t.Run("an untouched non-string value keeps its type", func(t *testing.T) {
		current := map[string]any{"count": json.Number("1000000"), "name": "x"}
		got, changed := applyFieldPatch(current, fieldPatch{
			Submitted: map[string]string{"count": "1000000", "name": "x"},
			Original:  orig("count", "name"),
		})
		if changed {
			t.Error("round-tripping a number through the form counted as a change")
		}
		if _, isString := got["count"].(string); isString {
			t.Error("an untouched number was rewritten as a string")
		}
	})
}

// Saving must write only the difference, and write nothing at all when there
// is none — a no-op save should not mint a KVv2 version.
func TestSecretSavePatchesOnlyWhatChanged(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"user": "gary", "value": "old"},
	})

	unchanged := editForm("personal", "token", "user", "gary", "value", "old")
	unchanged.Set("path", "personal/token")
	unchanged.Add("original_field", "user")
	unchanged.Add("original_field", "value")
	if resp := uiPost(t, ts, "/ui/secret-editor/save", unchanged); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("no-op save status = %d, want 303", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for a save that changed nothing", got)
	}

	changed := editForm("personal", "token", "user", "gary", "value", "new")
	changed.Set("path", "personal/token")
	changed.Add("original_field", "user")
	changed.Add("original_field", "value")
	if resp := uiPost(t, ts, "/ui/secret-editor/save", changed); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save status = %d, want 303", resp.StatusCode)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if got := fake.secrets["personal/token"]; got["value"] != "new" || got["user"] != "gary" {
		t.Errorf("secret = %#v, want value updated and user preserved", got)
	}
}

// Renaming is a copy-then-delete, in that order, so a failure between the two
// leaves the original rather than nothing.
func TestSecretSaveRenames(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	form := editForm("personal", "renamed", "value", "v")
	form.Set("path", "personal/token")
	form.Add("original_field", "value")

	resp := uiPost(t, ts, "/ui/secret-editor/save", form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body = %s", resp.StatusCode, uiBody(t, resp))
	}
	if loc := resp.Header.Get("Location"); loc != "/ui/secrets/personal/renamed" {
		t.Errorf("Location = %q, want the new path", loc)
	}
	if got := fake.wrote(); len(got) != 1 || got[0] != "personal/renamed" {
		t.Errorf("wrote = %v, want [personal/renamed]", got)
	}
	if got := fake.deleted(); len(got) != 1 || got[0] != "personal/token" {
		t.Errorf("deleted = %v, want [personal/token]", got)
	}
}

// A rename onto an occupied path would destroy a credential the user never
// saw, exactly as a create over one would.
func TestSecretSaveRenameRefusesOccupiedPath(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
		"personal/other": {"value": "keep-me"},
	})
	form := editForm("personal", "other", "value", "v")
	form.Set("path", "personal/token")
	form.Add("original_field", "value")

	if resp := uiPost(t, ts, "/ui/secret-editor/save", form); resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v over an occupied rename target", got)
	}
	if got := fake.deleted(); len(got) != 0 {
		t.Errorf("deleted %v on a refused rename", got)
	}
}

// A rename out of the editable subtree is refused by the same policy the
// original path went through — the target is checked, not just the source.
func TestSecretSaveRenameRefusesEscapingTheSubtree(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	form := editForm("", "gh", "value", "v")
	form.Set("path", "personal/token")
	form.Add("original_field", "value")

	if resp := uiPost(t, ts, "/ui/secret-editor/save", form); resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for a rename out of the subtree", got)
	}
}

// A rename whose copy lands but whose delete fails leaves the secret at both
// paths. The user has to be sent to the NEW one — it is there and correct —
// because re-rendering the old path would hide the move and make every retry
// meet the rename-target probe and fail forever.
func TestSecretSaveRenameOrphanSendsUserToTheNewPath(t *testing.T) {
	fake := newEditVault(map[string]map[string]any{"personal/token": {"value": "v"}})
	fake.deleteFails = true
	s := testServerWithVault(t, fake)
	s.cfg.Listen = "127.0.0.1:9000"
	s.cfg.EditablePaths = []string{"personal"}
	s.registerRoutes()
	ts := httptest.NewServer(s.middleware(s.mux))
	t.Cleanup(ts.Close)

	form := editForm("personal", "moved", "value", "v")
	form.Set("path", "personal/token")
	form.Add("original_field", "value")

	resp := uiPost(t, ts, "/ui/secret-editor/save", form)
	body := uiBody(t, resp)
	// The copy succeeded, so the secret exists at the new path.
	if got := fake.wrote(); len(got) != 1 || got[0] != "personal/moved" {
		t.Fatalf("wrote = %v, want [personal/moved]", got)
	}
	// The page shown is the new path's, carrying the complaint — not the old
	// path's, and not a form the user would resubmit into a permanent 409.
	if !strings.Contains(body, "personal/moved") {
		t.Error("the user was not shown the new path")
	}
	if !strings.Contains(body, "could not be removed") {
		t.Error("the leftover copy was not reported")
	}
}

// Clearing every field is refused rather than written: Vault rejects a
// fieldless secret, and an empty form is far more likely a mistake than a
// deliberate erasure. Deleting is its own confirmed gesture.
func TestSecretSaveRefusesEmptyingEveryField(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	form := editForm("personal", "token")
	form.Set("path", "personal/token")
	form.Add("original_field", "value")

	if resp := uiPost(t, ts, "/ui/secret-editor/save", form); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for a submission with no fields", got)
	}
}

// Blank rows are what make "Add field" cheap, so they must cost nothing: the
// form always carries some, and they must not become empty-named fields.
func TestSecretCreateIgnoresBlankRows(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, nil)
	form := editForm("personal", "token", "value", "v", "", "", "  ", "")

	if resp := uiPost(t, ts, "/ui/secret-editor/create", form); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	got := fake.secrets["personal/token"]
	if len(got) != 1 || got["value"] != "v" {
		t.Errorf("secret = %#v, want exactly the one named field", got)
	}
}

// Two rows naming the same field are refused rather than silently collapsed
// to whichever won — the user cannot see which value they kept.
func TestSecretCreateRefusesDuplicateFieldNames(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, nil)
	form := editForm("personal", "token", "value", "a", "value", "b")

	if resp := uiPost(t, ts, "/ui/secret-editor/create", form); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for a duplicate field name", got)
	}
}

// Renaming the secret while changing no field still has to write: the field
// patch reports "nothing changed", and only the rename flag keeps it going.
func TestSecretSaveRenameWithNoFieldChanges(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	form := editForm("personal", "moved", "value", "v")
	form.Set("path", "personal/token")
	form.Add("original_field", "value")

	if resp := uiPost(t, ts, "/ui/secret-editor/save", form); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 1 || got[0] != "personal/moved" {
		t.Errorf("wrote = %v, want [personal/moved]", got)
	}
	if got := fake.deleted(); len(got) != 1 || got[0] != "personal/token" {
		t.Errorf("deleted = %v, want [personal/token]", got)
	}
}

// The add-a-row fragment bounds its index: it is a query parameter, so it is
// caller-supplied like any other.
func TestAddFieldRowRejectsBadIndex(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, nil)
	for _, q := range []string{"", "?i=", "?i=-1", "?i=abc", "?i=999999"} {
		resp := uiGet(t, ts, "/ui/fragments/secret-editor/field-row"+q)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("i=%q: status = %d, want 400", q, resp.StatusCode)
		}
	}
}

// A field value must arrive byte-for-byte: it is typically a credential, and
// only field *names* are trimmed.
func TestSecretCreatePreservesValueWhitespace(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, nil)
	const padded = "  s3cret	with space  "
	form := editForm("personal", "token", "  value  ", padded)

	if resp := uiPost(t, ts, "/ui/secret-editor/create", form); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	got := fake.secrets["personal/token"]
	if got["value"] != padded {
		t.Errorf("value = %q, want the submitted value verbatim", got["value"])
	}
}

// maxFieldRows is the only bound on a scripted POST, so it is pinned rather
// than trusted.
func TestSecretCreateRefusesTooManyRows(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, nil)
	form := url.Values{"prefix": {"personal"}, "name": {"token"}}
	for i := 0; i <= maxFieldRows; i++ {
		form.Add("field_name", "f"+strconv.Itoa(i))
		form.Add("field_value", "v")
	}
	if resp := uiPost(t, ts, "/ui/secret-editor/create", form); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for an oversized submission", got)
	}
}

// Editing a structured value turns it into a string — the form can only carry
// strings, and pretending otherwise would mean guessing at the user's intent.
// Pinned so it stays a documented trade-off rather than drifting into the
// untouched-value path, where a type change would be a silent corruption.
func TestEditingStructuredValueStoresAString(t *testing.T) {
	current := map[string]any{"cfg": map[string]any{"k": "v"}}
	got, changed := applyFieldPatch(current, fieldPatch{
		Submitted: map[string]string{"cfg": `{"k":"other"}`},
		Original:  map[string]struct{}{"cfg": {}},
	})
	if !changed {
		t.Fatal("editing a structured value was not reported as a change")
	}
	if _, isString := got["cfg"].(string); !isString {
		t.Errorf("cfg = %#v, want the submitted string", got["cfg"])
	}
}

// The rows are paired positionally, which only holds if the counts match.
// A mismatched body was not produced by this form, so it is refused rather
// than guessed at — guessing would pair a name with someone else's value.
func TestSecretCreateRefusesUnpairedRows(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, nil)
	form := url.Values{"prefix": {"personal"}, "name": {"token"}}
	form.Add("field_name", "a")
	form.Add("field_name", "b")
	form.Add("field_value", "only-one")

	if resp := uiPost(t, ts, "/ui/secret-editor/create", form); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for an unpaired submission", got)
	}
}

// "Add field" appends a row rather than re-rendering the form, because a
// re-render would discard everything already typed.
func TestAddFieldRowAppendsWithoutReRendering(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, nil)
	body := uiBody(t, uiGet(t, ts, "/ui/fragments/secret-editor/field-row?i=3"))
	if !strings.Contains(body, `name="field_name"`) || !strings.Contains(body, `name="field_value"`) {
		t.Error("field-row fragment does not carry a name/value pair")
	}
	// Appended into the row container, not replacing it — asserting the mode
	// as well as the selector, since a selector alone passes even if
	// WithMode(ElementPatchModeAppend) is dropped and the patch starts
	// replacing everything the user has typed.
	if !strings.Contains(body, "selector #secret-field-rows") {
		t.Errorf("field-row fragment does not target the row container: %s", body)
	}
	if !strings.Contains(body, "mode append") {
		t.Errorf("field-row fragment does not append: %s", body)
	}
	// The button re-points at the next index so repeated clicks keep adding.
	if !strings.Contains(body, "i=4") {
		t.Error("add-field button was not advanced to the next index")
	}
}

// The editor renders one row per existing field, pre-filled, plus the hidden
// original_field markers the patch needs to detect a deletion.
func TestEditorRendersFieldRowsAndOriginals(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"user": "gary", "value": "s3cret"},
	})
	body := uiBody(t, uiGet(t, ts, "/ui/secret-editor/edit?path=personal%2Ftoken"))
	// The leading newline is the one the HTML parser eats (see
	// TestTextareaPreservesLeadingNewline), so the value follows it.
	for _, want := range []string{"\ngary</textarea>", "\ns3cret</textarea>", `name="original_field"`} {
		if !strings.Contains(body, want) {
			t.Errorf("editor body is missing %s", want)
		}
	}
	// The name is editable — that is how a rename is expressed.
	if !strings.Contains(body, `name="name"`) {
		t.Error("editor does not offer an editable name")
	}
}

// A multi-line credential must survive the editor untouched. <input
// type=text> strips CR and LF per the HTML value-sanitization algorithm, so
// rendering a PEM into one and saving anything on the page would silently
// flatten the key — which the SSH enrolment engine writes for real.
func TestSecretEditPreservesMultiLineValues(t *testing.T) {
	const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\nAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----\n"
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/key": {"private_key": pem, "comment": "gary@dotvault"},
	})

	// The editor must carry the newlines to the browser at all, which only a
	// textarea can do.
	body := uiBody(t, uiGet(t, ts, "/ui/secret-editor/edit?path=personal%2Fkey"))
	if !strings.Contains(body, "<textarea") {
		t.Error("editor renders values in an input, which would strip newlines")
	}
	if !strings.Contains(body, "BEGIN OPENSSH PRIVATE KEY") {
		t.Fatal("editor did not carry the multi-line value")
	}

	// A browser submits a textarea with CRLF line endings. Editing only the
	// neighbouring field must leave the key exactly as it was.
	form := url.Values{}
	form.Set("prefix", "personal")
	form.Set("name", "key")
	form.Set("path", "personal/key")
	form.Add("field_name", "private_key")
	form.Add("field_value", strings.ReplaceAll(pem, "\n", "\r\n"))
	form.Add("field_name", "comment")
	form.Add("field_value", "changed")
	form.Add("original_field", "private_key")
	form.Add("original_field", "comment")

	if resp := uiPost(t, ts, "/ui/secret-editor/save", form); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	got := fake.secrets["personal/key"]
	if got["private_key"] != pem {
		t.Errorf("private_key round-tripped to %q, want the original bytes", got["private_key"])
	}
	if got["comment"] != "changed" {
		t.Errorf("comment = %q, want the edited value", got["comment"])
	}
}

// The CRLF the browser adds is undone, so a genuinely edited multi-line value
// is stored with the newlines it appears to have rather than \r\n per line.
func TestNormalizeFormNewlines(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"plain", "plain"},
		{"a\r\nb", "a\nb"},
		{"a\rb", "a\nb"},
		{"a\nb", "a\nb"},
		{"", ""},
	} {
		if got := normalizeFormNewlines(tc.in); got != tc.want {
			t.Errorf("normalizeFormNewlines(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// An enrolment's target is off limits through every route that writes, not
// just the one the UI happens to offer. Notably `personal/gh` is NOT seeded
// here: a configured enrolment that has not run yet is exactly when a user
// might try to create it by hand, and the policy refuses on the configuration
// rather than on what Vault currently holds.
func TestEnrolmentPathsClosedOnEveryWriteRoute(t *testing.T) {
	enrolments := map[string]config.Enrolment{"personal/gh": {Engine: "github"}}
	s, ts, fake := editTestServer(t, []string{"personal"}, enrolments, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})

	t.Run("create at an enrolment path", func(t *testing.T) {
		resp := uiPost(t, ts, "/ui/secret-editor/create", editForm("personal", "gh", "a", "b"))
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("rename onto an enrolment path", func(t *testing.T) {
		f := editForm("personal", "gh", "value", "v")
		f.Set("path", "personal/token")
		f.Add("original_field", "value")
		if resp := uiPost(t, ts, "/ui/secret-editor/save", f); resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("delete an enrolment path", func(t *testing.T) {
		resp := uiPost(t, ts, "/ui/secret-editor/delete", url.Values{
			"path": {"personal/gh"}, "confirm": {"gh"},
		})
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("open the editor on an enrolment path", func(t *testing.T) {
		if resp := uiGet(t, ts, "/ui/secret-editor/edit?path=personal%2Fgh"); resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("API write at an enrolment path", func(t *testing.T) {
		for _, method := range []string{"POST", "PUT"} {
			w := httptest.NewRecorder()
			s.handleSecretWrite(w, httptest.NewRequest(method, "/api/v1/secrets/personal/gh",
				strings.NewReader(`{"fields":{"a":"b"}}`)))
			if w.Code != http.StatusForbidden {
				t.Errorf("%s status = %d, want 403", method, w.Code)
			}
		}
	})

	t.Run("API delete at an enrolment path", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleSecretDelete(w, httptest.NewRequest("DELETE", "/api/v1/secrets/personal/gh", nil))
		if w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})

	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v to an enrolment-managed path", got)
	}
	if got := fake.deleted(); len(got) != 0 {
		t.Errorf("deleted %v at an enrolment-managed path", got)
	}
}

// A <textarea> preserves line breaks in a VALUE, but a name rides an
// <input>, whose value sanitization algorithm strips CR and LF. So a field
// name containing one cannot survive this form: the browser would submit a
// different name than the page rendered, and the save would read that as a
// rename and silently move the field. The editor refuses to open instead.
func TestEditorRefusesNamesItCannotRoundTrip(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"a\nb": "secret-value", "ok": "v"},
	})

	// 409, not 422: nothing is wrong with the request — the stored secret is
	// simply in a shape this form cannot represent.
	resp := uiGet(t, ts, "/ui/secret-editor/edit?path=personal%2Ftoken")
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("editor status = %d, want 409", resp.StatusCode)
	}
	// The complaint counts the offending fields; it never names them.
	if body := uiBody(t, resp); strings.Contains(body, "a\nb") || strings.Contains(body, "secret-value") {
		t.Error("the refusal named the field or leaked its value")
	}

	// And the save path refuses the submission a browser could never have
	// produced, so the field cannot be renamed out from under the user.
	f := url.Values{}
	f.Set("prefix", "personal")
	f.Set("name", "token")
	f.Set("path", "personal/token")
	f.Add("field_name", "ab") // what an <input> would have stripped it to
	f.Add("field_value", "secret-value")
	f.Add("original_field", "a\nb") // what a hidden input would have kept
	if resp := uiPost(t, ts, "/ui/secret-editor/save", f); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("save status = %d, want 400", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v, silently renaming a field", got)
	}
}

// A path segment carrying a line break has the same problem as a field name,
// and is refused rather than written.
func TestSecretNameRejectsLineBreaks(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, nil)
	if resp := uiPost(t, ts, "/ui/secret-editor/create", editForm("personal", "to\nken", "a", "b")); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for a name containing a line break", got)
	}
}

// The HTML parser drops a newline immediately after a <textarea> start tag,
// so the fragment emits one of its own. Without it a value that legitimately
// begins with a newline loses it — silently, and only for those values.
func TestTextareaPreservesLeadingNewline(t *testing.T) {
	if err := uiInitTemplates(); err != nil {
		t.Fatal(err)
	}
	frag, err := uiFragment("secret-field-row", uiFieldRow{Name: "k", Value: "\nleading", Rows: 2})
	if err != nil {
		t.Fatal(err)
	}
	open := strings.Index(frag, "<textarea")
	if open < 0 {
		t.Fatal("no textarea in the field row")
	}
	body := frag[strings.Index(frag[open:], ">")+open+1:]
	if !strings.HasPrefix(body, "\n\n") {
		t.Errorf("textarea body starts %q; the parser will eat the value's own newline", body[:min(8, len(body))])
	}
}

// Every input that can carry a name reaches one validator. Each of these was
// found open in a separate review round, which is why they are pinned
// together: the previous shape checked one field at a time and kept growing
// another hole.
func TestEditorRefusesUnrenderableNamesOnEveryInput(t *testing.T) {
	base := func() url.Values {
		f := editForm("personal", "token", "value", "v")
		f.Set("path", "personal/token")
		f.Add("original_field", "value")
		return f
	}

	for _, tc := range []struct {
		name   string
		mutate func(url.Values)
		route  string
		status int
	}{
		{
			// `prefix` rides a hidden input, which has NO value sanitization
			// algorithm — the easiest half for a hand-made request to reach.
			name:   "create with a line break in the prefix",
			mutate: func(f url.Values) { f.Set("prefix", "personal/a\nb") },
			route:  "/ui/secret-editor/create",
			status: http.StatusUnprocessableEntity,
		},
		{
			name:   "create with a line break in the name",
			mutate: func(f url.Values) { f.Set("name", "to\nken") },
			route:  "/ui/secret-editor/create",
			status: http.StatusUnprocessableEntity,
		},
		{
			// The source path is a hidden input too: unguarded, the 422
			// re-render handed it back beside a stripped name and the second
			// submit was the silent rename this exists to prevent.
			name:   "save with a line break in the hidden path",
			mutate: func(f url.Values) { f.Set("path", "personal/to\nken") },
			route:  "/ui/secret-editor/save",
			status: http.StatusUnprocessableEntity,
		},
		{
			name:   "save renaming to a name with a line break",
			mutate: func(f url.Values) { f.Set("name", "to\nken") },
			route:  "/ui/secret-editor/save",
			status: http.StatusUnprocessableEntity,
		},
		{
			name: "submitted field name with a line break",
			mutate: func(f url.Values) {
				f.Del("field_name")
				f.Add("field_name", "a\nb")
			},
			route:  "/ui/secret-editor/save",
			status: http.StatusBadRequest,
		},
		{
			// The other half of the pair, so reverting either refusal fails a
			// test rather than hiding behind the one that remains.
			name: "previously-rendered field name with a line break",
			mutate: func(f url.Values) {
				f.Del("original_field")
				f.Add("original_field", "a\nb")
			},
			route:  "/ui/secret-editor/save",
			status: http.StatusBadRequest,
		},
		{
			// Surrounding whitespace is the same corruption by a different
			// character: the submit path trims, so an untrimmed original was
			// read as "the user renamed this field".
			name: "previously-rendered field name with surrounding whitespace",
			mutate: func(f url.Values) {
				f.Del("original_field")
				f.Add("original_field", " value")
			},
			route:  "/ui/secret-editor/save",
			status: http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
				"personal/token": {"value": "v"},
			})
			f := base()
			tc.mutate(f)
			if resp := uiPost(t, ts, tc.route, f); resp.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			if got := fake.wrote(); len(got) != 0 {
				t.Errorf("wrote %v", got)
			}
			if got := fake.deleted(); len(got) != 0 {
				t.Errorf("deleted %v", got)
			}
		})
	}
}

// A secret the editor cannot open must not show an Edit button that would
// bounce — kvpath.EditPolicy.Allows is documented as the reason a screen can
// never offer an edit the request refuses, and the editor's own refusal is a
// second gate the policy knows nothing about. Delete stays offered: it needs
// no name rendered back.
func TestDetailPageWithholdsEditWhenTheEditorWouldRefuse(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"a\nb": "v"},
	})
	body := uiBody(t, uiGet(t, ts, "/ui/secrets/personal/token"))
	if strings.Contains(body, "/ui/secret-editor/edit") {
		t.Error("detail page offers an Edit control the editor would refuse")
	}
	if !strings.Contains(body, "Not editable here") {
		t.Error("detail page does not say why editing is withheld")
	}
	// The explanation carries a count, not a name. Asserted on the
	// explanation line rather than the whole body: the detail table has
	// always listed field names (only values are masked), so a body-wide
	// check would be testing the wrong thing.
	if !strings.Contains(body, "Not editable here &mdash; 1 of this secret&#39;s field names") {
		t.Errorf("explanation is not the count form: %s", body)
	}
	if !strings.Contains(body, `action="/ui/secret-editor/delete"`) {
		t.Error("delete was withheld too, though it needs no name rendered back")
	}
}

// checkEditorFields reports how many names are unrenderable, not merely that
// some are — the count is what the message carries, so a bool would let it
// drift to "1" for any number of them.
func TestCheckEditorFieldsCountsThem(t *testing.T) {
	err := checkEditorFields(map[string]any{"a\nb": 1, " c": 2, "ok": 3, "d\re": 4})
	if err == nil {
		t.Fatal("no error for unrenderable field names")
	}
	if !errors.Is(err, errUnrenderableName) {
		t.Errorf("error %v does not wrap errUnrenderableName", err)
	}
	if !strings.Contains(err.Error(), "3 of") {
		t.Errorf("error = %q, want it to count all three", err)
	}
	// Only the control-character names are checked for leakage: " c" would
	// false-positive against ordinary prose ("form cannot"), which would make
	// the assertion about English rather than about the message.
	for _, leaked := range []string{"a\nb", "d\re"} {
		if strings.Contains(err.Error(), leaked) {
			t.Errorf("error names the field %q", leaked)
		}
	}
	if err := checkEditorFields(map[string]any{"fine": 1}); err != nil {
		t.Errorf("checkEditorFields on renderable names = %v, want nil", err)
	}
}

// Every refusal must say where to go instead — the docs promise a pointer to
// the API and the mount, and a dead-end message is how that promise rots.
func TestUnrenderableMessagesNameTheEscapeHatch(t *testing.T) {
	for _, err := range []error{
		checkEditorPath("a\nb"),
		checkEditorFields(map[string]any{"a\nb": 1}),
	} {
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "JSON API") || !strings.Contains(err.Error(), "filesystem mount") {
			t.Errorf("message gives no escape hatch: %q", err)
		}
	}
}

// A secret stored with CRLF must not be rewritten to LF just by being opened
// and saved. The browser submits every textarea as CRLF whatever the value
// held, so the comparison has to normalize both sides or an untouched value
// never matches itself.
func TestCRLFValueSurvivesAnUnrelatedEdit(t *testing.T) {
	const crlf = "line one\r\nline two\r\n"
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/blob": {"body": crlf, "note": "before"},
	})
	f := url.Values{}
	f.Set("prefix", "personal")
	f.Set("name", "blob")
	f.Set("path", "personal/blob")
	f.Add("field_name", "body")
	f.Add("field_value", crlf) // what the browser sends back untouched
	f.Add("field_name", "note")
	f.Add("field_value", "after") // the field actually edited
	f.Add("original_field", "body")
	f.Add("original_field", "note")

	if resp := uiPost(t, ts, "/ui/secret-editor/save", f); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if got := fake.secrets["personal/blob"]["body"]; got != crlf {
		t.Errorf("CRLF value became %q, want it byte-for-byte", got)
	}
	if got := fake.secrets["personal/blob"]["note"]; got != "after" {
		t.Errorf("note = %q, want the edited value", got)
	}
}

// And a no-op save on such a secret writes nothing at all.
func TestCRLFValueNoOpSaveWritesNothing(t *testing.T) {
	const crlf = "a\r\nb"
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/blob": {"body": crlf},
	})
	f := url.Values{}
	f.Set("prefix", "personal")
	f.Set("name", "blob")
	f.Set("path", "personal/blob")
	f.Add("field_name", "body")
	f.Add("field_value", crlf)
	f.Add("original_field", "body")

	if resp := uiPost(t, ts, "/ui/secret-editor/save", f); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for a no-op save on a CRLF value", got)
	}
}
