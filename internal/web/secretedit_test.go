package web

import (
	"encoding/json"
	stdhtml "html"
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
	// versions tracks each secret's KVv2 version so check-and-set can be
	// modelled rather than stubbed — CAS is the guarantee the editor rests
	// on, so a fake that always accepted a write would make every test about
	// it vacuous.
	versions map[string]int
	writes   []string
	deletes  []string
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
	v := &editVault{secrets: map[string]map[string]any{}, versions: map[string]int{}}
	for k, data := range seed {
		v.secrets[k] = data
		v.versions[k] = 1
	}
	return v
}

// setVersion puts a secret at a specific version, so a test can render a page
// and then move the secret on underneath it.
func (v *editVault) setVersion(rel string, version int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.versions[rel] = version
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
		delete(v.versions, rel)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost, r.Method == http.MethodPut:
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			Data    map[string]any `json:"data"`
			Options struct {
				CAS *int `json:"cas"`
			} `json:"options"`
		}
		json.Unmarshal(raw, &body)
		// Vault's own check-and-set: the write lands only if the caller's
		// version is the current one, and cas 0 additionally means "only if
		// absent". The refusal is a 400 whose body names the reason, which
		// is what the client matches on — the status alone is shared with an
		// ordinary malformed request.
		if cas := body.Options.CAS; cas != nil && *cas != v.versions[rel] {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"errors": []string{"check-and-set parameter did not match the current version"},
			})
			return
		}
		v.writes = append(v.writes, rel)
		v.bodies = append(v.bodies, string(raw))
		v.secrets[rel] = body.Data
		v.versions[rel]++
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": v.versions[rel]}})
	default:
		data, ok := v.secrets[rel]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data":     data,
				"metadata": map[string]any{"version": v.versions[rel]},
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

// fieldForm builds one row save: the secret, the version the row was
// rendered from, and the field being written. `was` is set by the caller for
// a rename.
// fieldForm is the *add-row* submission: no `was`, exactly as
// secret-add-row posts. It is the shape that creates a secret's first field
// and that adds a field to an existing one.
func fieldForm(path string, version int, field, value string) url.Values {
	return url.Values{
		"path":    {path},
		"version": {strconv.Itoa(version)},
		"field":   {field},
		"value":   {value},
	}
}

// editForm is the *edit-row* submission: `was` names the field the row was
// rendered from, exactly as secret-row-edit posts. The distinction is
// load-bearing rather than cosmetic — a submission with no `was` claims to
// introduce a field, and introducing one that already exists is refused
// (errFieldExists) rather than silently replacing a credential the user was
// not looking at.
func editForm(path string, version int, field, value string) url.Values {
	f := fieldForm(path, version, field, value)
	f.Set("was", field)
	return f
}

// currentVersion reads the version a page would have been rendered from.
func (v *editVault) currentVersion(rel string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.versions[rel]
}

// The default — no editable_paths — leaves the UI exactly as read-only as it
// was before the feature existed, routes registered or not.
func TestSecretEditDisabledByDefault(t *testing.T) {
	_, ts, fake := editTestServer(t, nil, nil, map[string]map[string]any{
		"personal/token": {"value": "s3cret"},
	})
	if resp := uiPost(t, ts, "/ui/secrets-edit/field", fieldForm("personal/token", 1, "value", "new")); resp.StatusCode != http.StatusForbidden {
		t.Errorf("save status = %d, want 403", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v with no editable paths configured", got)
	}
	if offersEditing(uiBody(t, uiGet(t, ts, "/ui/secrets/personal/token"))) {
		t.Error("detail page offers an edit control with no editable paths configured")
	}
}

// offersEditing reports whether a rendered detail page shows a pencil.
//
// It deliberately does NOT look for the bare URL "/ui/fragments/secrets/
// edit-row": html/template treats a data-on: attribute as JavaScript and
// escapes every slash, so that string can never appear and an assertion
// against it is vacuous however the page renders. Both markers below are
// checked against a page that genuinely offers editing by
// TestDetailPageOffersEditingWhereThePolicyAllows, which is what stops this
// predicate quietly becoming a tautology again.
func offersEditing(body string) bool {
	return strings.Contains(body, "Edit this field") ||
		strings.Contains(body, `\/ui\/fragments\/secrets\/edit-row`)
}

// The other half of every "the page withholds the pencil" assertion: on a
// page that does offer editing, both markers are present. Without this the
// negatives would pass against a page that had simply stopped rendering.
func TestDetailPageOffersEditingWhereThePolicyAllows(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	body := uiBody(t, uiGet(t, ts, "/ui/secrets/personal/token"))
	if !strings.Contains(body, "Edit this field") {
		t.Error("an editable secret renders no pencil")
	}
	if !strings.Contains(body, `\/ui\/fragments\/secrets\/edit-row`) {
		t.Errorf("the pencil does not target the edit-row fragment: %s", body)
	}
	if !offersEditing(body) {
		t.Error("offersEditing does not recognise a page that plainly offers editing")
	}
}

// A secret the policy refuses shows no pencil even when the page beside it
// does — the enrolment-managed case, which is a refusal the user can see a
// reason for rather than a control that 403s.
func TestManagedSecretOffersNoPencil(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"},
		map[string]config.Enrolment{"personal/gh": {Engine: "github"}},
		map[string]map[string]any{"personal/gh": {"oauth_token": "v"}})
	body := uiBody(t, uiGet(t, ts, "/ui/secrets/personal/gh"))
	if offersEditing(body) {
		t.Error("an enrolment-managed secret offers an edit control that would 403")
	}
	if !strings.Contains(body, "Managed by an enrolment") {
		t.Error("the page does not say why editing is withheld")
	}
}

// Writes are check-and-set against the version the row was rendered from, so
// an edit made against a stale view is refused rather than overwriting
// whoever wrote in between. This is the guarantee the whole redesign rests on.
func TestFieldSaveRefusesStaleVersion(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "original"},
	})
	// The user opened the page at version 1; somebody else has since written.
	fake.setVersion("personal/token", 4)

	resp := uiPost(t, ts, "/ui/secrets-edit/field", editForm("personal/token", 1, "value", "mine"))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
	if body := uiBody(t, resp); !strings.Contains(body, "changed while you were editing") {
		t.Error("the refusal does not explain that the secret moved on")
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v over a concurrent change", got)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.secrets["personal/token"]["value"] != "original" {
		t.Error("the concurrent writer's value was clobbered")
	}
}

// The same check makes creation atomic: cas 0 means "only if absent", so a
// create racing another create is settled by Vault rather than by a probe.
func TestCreateIsCheckAndSetAgainstAbsence(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, nil)

	if resp := uiPost(t, ts, "/ui/secrets-edit/field", fieldForm("personal/token", 0, "value", "v")); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("first create status = %d, want 303", resp.StatusCode)
	}
	// A second create at version 0 means "I believe this does not exist",
	// which is now false.
	if resp := uiPost(t, ts, "/ui/secrets-edit/field", fieldForm("personal/token", 0, "value", "other")); resp.StatusCode != http.StatusConflict {
		t.Errorf("second create status = %d, want 409", resp.StatusCode)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if got := fake.secrets["personal/token"]["value"]; got != "v" {
		t.Errorf("value = %q, want the first create to have won", got)
	}
}

// A path inside an editable subtree that holds nothing is not an error: it is
// a secret waiting to be created, and the URL is the whole state.
func TestNonExistentEditablePathRendersAsNew(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, nil)

	resp := uiGet(t, ts, "/ui/secrets/personal/brand-new")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := uiBody(t, resp)
	if !strings.Contains(body, "New secret") {
		t.Error("a not-yet-existing editable path does not present as new")
	}
	if !strings.Contains(body, `action="/ui/secrets-edit/field"`) {
		t.Error("no way to add the first field")
	}
	// Version 0 is what makes the first write a create.
	if !strings.Contains(body, `name="version" value="0"`) {
		t.Error("the add row does not carry version 0")
	}
	// Outside the editable subtree it is still simply missing.
	if resp := uiGet(t, ts, "/ui/secrets/elsewhere/nope"); resp.StatusCode == http.StatusOK &&
		strings.Contains(uiBody(t, resp), "New secret") {
		t.Error("a path outside every editable subtree presents as new")
	}
}

// The full create gesture as a browser performs it: name a secret in the
// folder dialog, land on its URL, add the first field.
func TestCreateFlowFromFolderDialog(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, nil)

	folder := uiBody(t, uiGet(t, ts, "/ui/secrets/personal/"))
	if !strings.Contains(folder, `action="/ui/secrets-edit/goto"`) {
		t.Fatal("folder page has no new-secret dialog")
	}

	resp := uiPost(t, ts, "/ui/secrets-edit/goto", url.Values{
		"folder": {"personal"}, "name": {"aws"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("goto status = %d, want 303", resp.StatusCode)
	}
	// It navigates rather than creating: nothing is written yet.
	if loc := resp.Header.Get("Location"); loc != "/ui/secrets/personal/aws" {
		t.Fatalf("Location = %q, want the secret's own URL", loc)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("naming a secret wrote %v; it should only navigate", got)
	}

	if resp := uiPost(t, ts, "/ui/secrets-edit/field", fieldForm("personal/aws", 0, "key_id", "AKIA")); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("first field status = %d, want 303", resp.StatusCode)
	}
	body := uiBody(t, uiGet(t, ts, "/ui/secrets/personal/aws"))
	if !strings.Contains(body, "key_id") {
		t.Error("the new secret does not list its field")
	}
	if strings.Contains(body, "AKIA") {
		t.Error("the detail page leaked the value it just stored")
	}
}

// The dialog cannot navigate outside the editable subtrees, which is what
// stops it being a way around the policy.
func TestGotoRefusesUneditableTargets(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, map[string]config.Enrolment{
		"personal/gh": {Engine: "github"},
	}, nil)
	for _, tc := range []struct{ folder, name string }{
		{"", "gh"},                  // the key-space root
		{"elsewhere", "thing"},      // outside every subtree
		{"personal", "gh"},          // an enrolment's path
		{"personal", "../escape"},   // traversal
		{"personal", "line\nbreak"}, // a name the editor cannot render
	} {
		resp := uiPost(t, ts, "/ui/secrets-edit/goto", url.Values{
			"folder": {tc.folder}, "name": {tc.name},
		})
		if resp.StatusCode == http.StatusSeeOther {
			t.Errorf("goto %q/%q was allowed", tc.folder, tc.name)
		}
	}
}

// The pencil turns one row editable in place, carrying the version, and
// cancel puts it back — the rest of the table is untouched either way.
func TestRowConvertsBetweenReadOnlyAndEditable(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "s3cret"},
	})
	version := fake.currentVersion("personal/token")

	q := url.Values{"path": {"personal/token"}, "field": {"value"}, "id": {"0"},
		"version": {strconv.Itoa(version)}}.Encode()

	edit := uiBody(t, uiGet(t, ts, "/ui/fragments/secrets/edit-row?"+q))
	if !strings.Contains(edit, "s3cret") {
		t.Error("the editable row does not carry the value")
	}
	if !strings.Contains(edit, `name="version" value="`+strconv.Itoa(version)+`"`) {
		t.Error("the editable row does not carry the version it was rendered from")
	}
	if !strings.Contains(edit, `name="was" value="value"`) {
		t.Error("the editable row does not carry the original field name")
	}

	back := uiBody(t, uiGet(t, ts, "/ui/fragments/secrets/row?"+q))
	if strings.Contains(back, "s3cret") {
		t.Error("cancelling a row left the value on the page")
	}
	if !strings.Contains(back, "masked") {
		t.Error("cancelling a row did not restore the masked cell")
	}
}

// A row on a secret the policy does not permit writing must not open.
func TestEditRowRefusesUneditablePaths(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, map[string]config.Enrolment{
		"personal/gh": {Engine: "github"},
	}, map[string]map[string]any{
		"gh":          {"oauth_token": "x"},
		"personal/gh": {"oauth_token": "y"},
	})
	for _, path := range []string{"gh", "personal/gh"} {
		q := url.Values{"path": {path}, "field": {"oauth_token"}, "id": {"0"}, "version": {"1"}}.Encode()
		if resp := uiGet(t, ts, "/ui/fragments/secrets/edit-row?"+q); resp.StatusCode != http.StatusForbidden {
			t.Errorf("edit-row on %q: status = %d, want 403", path, resp.StatusCode)
		}
	}
}

// Renaming a field is a delete plus an add, expressed by `was` differing from
// the submitted name, and it happens under the same check-and-set.
func TestFieldRename(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"old": "v", "keep": "k"},
	})
	f := fieldForm("personal/token", fake.currentVersion("personal/token"), "new", "v")
	f.Set("was", "old")
	if resp := uiPost(t, ts, "/ui/secrets-edit/field", f); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	got := fake.secrets["personal/token"]
	if _, still := got["old"]; still {
		t.Error("the old field name survived the rename")
	}
	if got["new"] != "v" || got["keep"] != "k" {
		t.Errorf("secret = %#v, want the value moved and the neighbour kept", got)
	}
}

// Removing a field is the same form with delete=1.
func TestFieldDelete(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"drop": "v", "keep": "k"},
	})
	f := fieldForm("personal/token", fake.currentVersion("personal/token"), "drop", "")
	f.Set("delete", "1")
	if resp := uiPost(t, ts, "/ui/secrets-edit/field", f); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	got := fake.secrets["personal/token"]
	if _, still := got["drop"]; still {
		t.Error("the field was not removed")
	}
	if got["keep"] != "k" {
		t.Error("removing a field disturbed its neighbour")
	}
}

// Removing the last field is refused: KVv2 does not store a fieldless secret,
// and deleting the secret is its own confirmed gesture.
func TestRemovingTheLastFieldIsRefused(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"only": "v"},
	})
	f := fieldForm("personal/token", fake.currentVersion("personal/token"), "only", "")
	f.Set("delete", "1")
	if resp := uiPost(t, ts, "/ui/secrets-edit/field", f); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v, emptying a secret", got)
	}
}

// An enrolment's target is off limits through every route that writes. The
// case worth pinning is that `personal/gh` is NOT seeded: a configured
// enrolment that has not run yet is protected too, because the policy reads
// the configuration rather than what Vault currently holds — so the path
// cannot be pre-created out from under the engine that will claim it.
func TestEnrolmentPathsClosedOnEveryWriteRoute(t *testing.T) {
	enrolments := map[string]config.Enrolment{"personal/gh": {Engine: "github"}}
	s, ts, fake := editTestServer(t, []string{"personal"}, enrolments, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})

	t.Run("write a field", func(t *testing.T) {
		if resp := uiPost(t, ts, "/ui/secrets-edit/field", fieldForm("personal/gh", 0, "a", "b")); resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})
	t.Run("rename a field onto it", func(t *testing.T) {
		f := fieldForm("personal/gh", 1, "a", "b")
		f.Set("was", "c")
		if resp := uiPost(t, ts, "/ui/secrets-edit/field", f); resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})
	t.Run("delete it", func(t *testing.T) {
		resp := uiPost(t, ts, "/ui/secrets-edit/delete", url.Values{
			"path": {"personal/gh"}, "confirm": {"gh"},
		})
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})
	t.Run("navigate to it", func(t *testing.T) {
		resp := uiPost(t, ts, "/ui/secrets-edit/goto", url.Values{
			"folder": {"personal"}, "name": {"gh"},
		})
		if resp.StatusCode == http.StatusSeeOther {
			t.Error("the new-secret dialog navigated to an enrolment's path")
		}
	})
	t.Run("API write and delete", func(t *testing.T) {
		for _, method := range []string{"POST", "PUT"} {
			w := httptest.NewRecorder()
			s.handleSecretWrite(w, httptest.NewRequest(method, "/api/v1/secrets/personal/gh",
				strings.NewReader(`{"fields":{"a":"b"}}`)))
			if w.Code != http.StatusForbidden {
				t.Errorf("%s status = %d, want 403", method, w.Code)
			}
		}
		w := httptest.NewRecorder()
		s.handleSecretDelete(w, httptest.NewRequest("DELETE", "/api/v1/secrets/personal/gh", nil))
		if w.Code != http.StatusForbidden {
			t.Errorf("DELETE status = %d, want 403", w.Code)
		}
	})

	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v to an enrolment-managed path", got)
	}
	if got := fake.deleted(); len(got) != 0 {
		t.Errorf("deleted %v at an enrolment-managed path", got)
	}
}

// The key-space root is never editable, whatever the roots say.
func TestKeySpaceRootStaysReadOnly(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"gh": {"oauth_token": "x"},
	})
	if resp := uiPost(t, ts, "/ui/secrets-edit/field", fieldForm("gh", 1, "oauth_token", "stolen")); resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for a root-level secret", got)
	}
}

// The enrolment set is reload-dynamic, so the policy must follow it rather
// than being fixed when the server was constructed.
func TestPolicyFollowsEnrolmentReload(t *testing.T) {
	s, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/gh": {"oauth_token": "a"},
	})
	v := fake.currentVersion("personal/gh")
	if resp := uiPost(t, ts, "/ui/secrets-edit/field", editForm("personal/gh", v, "oauth_token", "b")); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("pre-reload status = %d, want 303", resp.StatusCode)
	}
	s.enrolRunnerMu.Lock()
	s.enrolments = map[string]config.Enrolment{"personal/gh": {Engine: "github"}}
	s.enrolRunnerMu.Unlock()

	v = fake.currentVersion("personal/gh")
	if resp := uiPost(t, ts, "/ui/secrets-edit/field", editForm("personal/gh", v, "oauth_token", "c")); resp.StatusCode != http.StatusForbidden {
		t.Errorf("post-reload status = %d, want 403", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 1 {
		t.Errorf("wrote %v, want only the pre-reload write", got)
	}
}

// An untouched value keeps its stored bytes and its type. A form can only
// carry strings, and every browser submits a textarea as CRLF whatever the
// value held, so both sides are normalized before comparing — otherwise a
// CRLF value would never equal itself and every save would rewrite it.
func TestUntouchedValuesArePreserved(t *testing.T) {
	const crlf = "line one\r\nline two\r\n"
	const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbg==\n-----END OPENSSH PRIVATE KEY-----\n"
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/mix": {"crlf": crlf, "pem": pem, "count": json.Number("1000000"), "note": "before"},
	})
	v := fake.currentVersion("personal/mix")

	// Edit only `note`; everything else is left alone and must survive.
	if resp := uiPost(t, ts, "/ui/secrets-edit/field", editForm("personal/mix", v, "note", "after")); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	got := fake.secrets["personal/mix"]
	if got["crlf"] != crlf {
		t.Errorf("CRLF value became %q", got["crlf"])
	}
	if got["pem"] != pem {
		t.Errorf("PEM became %q", got["pem"])
	}
	if _, isString := got["count"].(string); isString {
		t.Error("an untouched number was rewritten as a string")
	}
	if got["note"] != "after" {
		t.Errorf("note = %q, want the edited value", got["note"])
	}
}

// Re-submitting a multi-line value as the browser sends it (CRLF) counts as
// no change at all, so a save that touches nothing writes nothing.
func TestResubmittingAMultiLineValueIsNotAChange(t *testing.T) {
	const pem = "-----BEGIN KEY-----\nabc\n-----END KEY-----\n"
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/key": {"private_key": pem},
	})
	v := fake.currentVersion("personal/key")
	f := editForm("personal/key", v, "private_key", strings.ReplaceAll(pem, "\n", "\r\n"))
	if resp := uiPost(t, ts, "/ui/secrets-edit/field", f); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if got := fake.secrets["personal/key"]["private_key"]; got != pem {
		t.Errorf("private_key round-tripped to %q, want the original bytes", got)
	}
}

// Names ride <input>s, which strip CR/LF, and the handler trims whitespace —
// so a name that would not survive the round trip is refused everywhere
// rather than silently renaming a field. Each of these was a separate hole.
func TestUnrenderableNamesRefusedOnEveryInput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		form   func(int) url.Values
		status int
	}{
		{
			name:   "submitted field name with a line break",
			form:   func(v int) url.Values { return fieldForm("personal/token", v, "a\nb", "x") },
			status: http.StatusUnprocessableEntity,
		},
		{
			// `was` rides a hidden input, which has no value sanitization
			// algorithm at all — the easiest half for a hand-made request.
			name: "previously-rendered name with a line break",
			form: func(v int) url.Values {
				f := fieldForm("personal/token", v, "value", "x")
				f.Set("was", "a\nb")
				return f
			},
			status: http.StatusUnprocessableEntity,
		},
		{
			// Whitespace is the same corruption by a different character:
			// the submit path trims, so an untrimmed `was` read as a rename.
			name: "previously-rendered name with surrounding whitespace",
			form: func(v int) url.Values {
				f := fieldForm("personal/token", v, "value", "x")
				f.Set("was", " value")
				return f
			},
			status: http.StatusUnprocessableEntity,
		},
		{
			name:   "a secret path with a line break",
			form:   func(v int) url.Values { return fieldForm("personal/to\nken", v, "value", "x") },
			status: http.StatusUnprocessableEntity,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
				"personal/token": {"value": "v"},
			})
			resp := uiPost(t, ts, "/ui/secrets-edit/field", tc.form(fake.currentVersion("personal/token")))
			if resp.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			if got := fake.wrote(); len(got) != 0 {
				t.Errorf("wrote %v", got)
			}
		})
	}
}

// A secret the editor cannot represent must not show a pencil that bounces —
// EditPolicy.Allows is documented as the reason a screen never offers an edit
// the request would refuse, and the editor's own limits are a second gate the
// policy knows nothing about. Delete stays offered: it renders no name back.
func TestDetailPageWithholdsEditingWhenTheRowsCannotRender(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"a\nb": "v"},
	})
	body := uiBody(t, uiGet(t, ts, "/ui/secrets/personal/token"))
	if offersEditing(body) {
		t.Error("detail page offers an edit control the editor would refuse")
	}
	if !strings.Contains(body, "Not editable here") {
		t.Error("detail page does not say why editing is withheld")
	}
	if !strings.Contains(body, `action="/ui/secrets-edit/delete"`) {
		t.Error("delete was withheld too, though it renders no name back")
	}
}

// Delete removes every version, so it asks the user to type the name back.
func TestSecretDeleteRequiresTypedConfirmation(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	if resp := uiPost(t, ts, "/ui/secrets-edit/delete", url.Values{
		"path": {"personal/token"}, "confirm": {"wrong"},
	}); resp.StatusCode != http.StatusConflict {
		t.Errorf("mis-typed confirm status = %d, want 409", resp.StatusCode)
	}
	if got := fake.deleted(); len(got) != 0 {
		t.Fatalf("deleted %v without a matching confirmation", got)
	}
	resp := uiPost(t, ts, "/ui/secrets-edit/delete", url.Values{
		"path": {"personal/token"}, "confirm": {"token"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("confirmed delete status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/ui/secrets/personal/" {
		t.Errorf("Location = %q, want the parent folder", loc)
	}
	if got := fake.deleted(); len(got) != 1 || got[0] != "personal/token" {
		t.Errorf("deleted = %v, want [personal/token]", got)
	}
}

// Every /ui/ mutation is Origin-gated; the editor's are no exception.
func TestFieldSaveRefusesCrossSitePost(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	req, err := http.NewRequest("POST", ts.URL+"/ui/secrets-edit/field",
		strings.NewReader(fieldForm("personal/token", 1, "value", "x").Encode()))
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

// A save with no version is refused rather than defaulted: a missing version
// would silently become 0, which means "create", and a create against an
// existing secret is refused — so the user would see a baffling conflict
// instead of being told what the request lacked.
func TestFieldSaveRequiresAVersion(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	f := fieldForm("personal/token", 1, "value", "x")
	f.Del("version")
	if resp := uiPost(t, ts, "/ui/secrets-edit/field", f); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v with no version", got)
	}
}

// The key space is one folder deep, so a nested name typed into the folder
// dialog is refused rather than navigating to a URL whose page could never
// save. Refused as a policy decision (403), not as a malformed request: the
// path is well-formed, it is simply not somewhere editing is granted.
func TestFolderDialogRefusesANestedName(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, nil)

	resp := uiPost(t, ts, "/ui/secrets-edit/goto", url.Values{
		"folder": {"personal"}, "name": {"aws/dev"},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("goto status = %d, want 403", resp.StatusCode)
	}
	if body := uiBody(t, resp); !strings.Contains(body, "directly inside") {
		t.Errorf("the refusal does not explain the depth rule: %s", body)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("a refused name wrote %v", got)
	}
}

// The same rule on the save path, which a caller can reach without the dialog.
func TestSavingATooDeepSecretIsRefused(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, nil)

	resp := uiPost(t, ts, "/ui/secrets-edit/field", fieldForm("personal/aws/dev", 0, "key_id", "AKIA"))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v below the one legal folder level", got)
	}
}

// And on the JSON API, so the two surfaces agree about depth as they do about
// every other part of the policy.
//
// The handlers are called directly, as the sibling API tests do: routing
// through s.mux would answer 403 for a missing CSRF token long before the
// policy is consulted, and the test would pass against any path at all.
func TestAPIRefusesATooDeepSecret(t *testing.T) {
	body := func() *strings.Reader { return strings.NewReader(`{"fields":{"a":"b"}}`) }
	for _, method := range []string{"POST", "PUT"} {
		s, _, fake := editTestServer(t, []string{"personal"}, nil, nil)
		w := httptest.NewRecorder()
		s.handleSecretWrite(w, httptest.NewRequest(method, "/api/v1/secrets/personal/aws/dev", body()))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s status = %d, want 403; body = %s", method, w.Code, w.Body.String())
		}
		if got := fake.wrote(); len(got) != 0 {
			t.Errorf("%s wrote %v below the one legal folder level", method, got)
		}
	}

	// DELETE too: a path the policy will not write is not one it will remove.
	s, _, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/aws/dev": {"a": "b"},
	})
	w := httptest.NewRecorder()
	s.handleSecretDelete(w, httptest.NewRequest("DELETE", "/api/v1/secrets/personal/aws/dev", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("DELETE status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
	if got := fake.deleted(); len(got) != 0 {
		t.Errorf("DELETE removed %v below the one legal folder level", got)
	}

	// The same request one level shallower succeeds, so the 403 above is the
	// depth rule talking and not something incidental to the request.
	s2, _, _ := editTestServer(t, []string{"personal"}, nil, nil)
	w2 := httptest.NewRecorder()
	s2.handleSecretWrite(w2, httptest.NewRequest("POST", "/api/v1/secrets/personal/aws", body()))
	if w2.Code != http.StatusOK && w2.Code != http.StatusCreated {
		t.Errorf("a legal create got %d; body = %s", w2.Code, w2.Body.String())
	}
}

// The sidebar lists the configured subtrees whether or not Vault has them: a
// subtree holds nothing until the first write, and a folder you cannot see is
// one you cannot create in.
func TestSidebarListsEditableRootsThatDoNotExistYet(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal", "scratch"}, nil, map[string]map[string]any{
		"gh": {"oauth_token": "x"},
	})
	body := uiBody(t, uiGet(t, ts, "/ui/secrets/"))
	for _, want := range []string{"/ui/secrets/personal/", "/ui/secrets/scratch/"} {
		if !strings.Contains(body, want) {
			t.Errorf("sidebar does not link %s", want)
		}
	}
}

// An empty editable folder renders as a folder with the create dialog, not as
// a missing secret — that is its normal starting state.
func TestEmptyEditableFolderRendersWithCreateDialog(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, nil)
	resp := uiGet(t, ts, "/ui/secrets/personal/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body := uiBody(t, resp); !strings.Contains(body, `action="/ui/secrets-edit/goto"`) {
		t.Error("empty editable folder offers no way to create a secret")
	}
}

// A policy granting write need not grant list, and a KVv2 list of an empty
// prefix is a 404 besides. Neither may surface as an error on the one folder
// the user is invited to create in — while a failure elsewhere still does.
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

// The textarea preserves a value that begins with a newline only because the
// fragment emits one of its own: the HTML parser drops a newline immediately
// after the start tag.
func TestTextareaPreservesLeadingNewline(t *testing.T) {
	if err := uiInitTemplates(); err != nil {
		t.Fatal(err)
	}
	frag, err := uiFragment("secret-row-edit", uiFieldRow{Name: "k", Value: "\nleading", Rows: 2})
	if err != nil {
		t.Fatal(err)
	}
	open := strings.Index(frag, "<textarea")
	if open < 0 {
		t.Fatal("no textarea in the editable row")
	}
	body := frag[strings.Index(frag[open:], ">")+open+1:]
	if !strings.HasPrefix(body, "\n\n") {
		t.Errorf("textarea body starts %q; the parser will eat the value's own newline", body[:8])
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

// checkEditorFields counts the unrenderable names rather than merely
// reporting that some exist — the count is what the message carries.
func TestCheckEditorFieldsCountsThem(t *testing.T) {
	err := checkEditorFields(map[string]any{"a\nb": 1, " c": 2, "ok": 3, "d\re": 4})
	if err == nil {
		t.Fatal("no error for unrenderable field names")
	}
	if !strings.Contains(err.Error(), "3 of") {
		t.Errorf("error = %q, want it to count all three", err)
	}
	// Only the control-character names are checked for leakage: " c" would
	// false-positive against ordinary prose ("form cannot").
	for _, leaked := range []string{"a\nb", "d\re"} {
		if strings.Contains(err.Error(), leaked) {
			t.Errorf("error names the field %q", leaked)
		}
	}
	if err := checkEditorFields(map[string]any{"fine": 1}); err != nil {
		t.Errorf("checkEditorFields on renderable names = %v, want nil", err)
	}
}

// The JSON API is unchanged by the in-place editor: it still replaces whole
// documents, which is what a programmatic caller wants and what keeps its
// contract identical to the FUSE mount's.
func TestSecretAPILifecycle(t *testing.T) {
	s, _, fake := editTestServer(t, []string{"personal"}, nil, nil)

	apiReq := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, "/api/v1/secrets/"+path, strings.NewReader(body))
		if method == http.MethodDelete {
			s.handleSecretDelete(w, r)
		} else {
			s.handleSecretWrite(w, r)
		}
		return w
	}

	if w := apiReq("POST", "personal/token", `{"fields":{"value":"v"}}`); w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body = %s", w.Code, w.Body.String())
	}
	// Create is check-and-set against absence, so a second one is refused by
	// Vault rather than by a probe whose window another writer can land in.
	if w := apiReq("POST", "personal/token", `{"fields":{"value":"other"}}`); w.Code != http.StatusConflict {
		t.Errorf("duplicate create status = %d, want 409", w.Code)
	}
	if w := apiReq("PUT", "personal/token", `{"fields":{"value":"v2"}}`); w.Code != http.StatusOK {
		t.Errorf("replace status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if w := apiReq("PUT", "personal/absent", `{"fields":{"value":"v"}}`); w.Code != http.StatusNotFound {
		t.Errorf("replace-on-absent status = %d, want 404", w.Code)
	}
	if w := apiReq("DELETE", "personal/token", ""); w.Code != http.StatusOK {
		t.Errorf("delete status = %d, want 200", w.Code)
	}
	if w := apiReq("DELETE", "personal/token", ""); w.Code != http.StatusNotFound {
		t.Errorf("delete-on-absent status = %d, want 404", w.Code)
	}
	if got := fake.deleted(); len(got) != 1 || got[0] != "personal/token" {
		t.Errorf("deleted = %v, want [personal/token]", got)
	}
}

// An empty object is a truncate the caller never finished, not an intentional
// erasure of every field; the mount refuses it and so does this.
func TestSecretAPIRefusesEmptyDocument(t *testing.T) {
	s, _, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	for _, body := range []string{`{"fields":{}}`, `{"fields":null}`, `{}`,
		`{"fields":{"a":"1"}}{"fields":{"b":"2"}}`} {
		w := httptest.NewRecorder()
		s.handleSecretWrite(w, httptest.NewRequest("PUT", "/api/v1/secrets/personal/token", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", body, w.Code)
		}
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for a refused document", got)
	}
}

// The API's write body mirrors what GET ?reveal=true returns, so a caller can
// read, edit and send the object straight back — losslessly, including large
// integers that a float round trip would approximate.
func TestSecretAPIWriteIsLossless(t *testing.T) {
	s, _, fake := editTestServer(t, []string{"personal"}, nil, nil)
	w := httptest.NewRecorder()
	s.handleSecretWrite(w, httptest.NewRequest("POST", "/api/v1/secrets/personal/token",
		strings.NewReader(`{"fields":{"value":"v","count":1000000}}`)))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if body := fake.bodies[0]; !strings.Contains(body, "1000000") || strings.Contains(body, "1e+06") {
		t.Errorf("write body = %s, want the integer literal", body)
	}
}

// A path the policy refuses is refused on the JSON API too, not just in the
// UI — otherwise the read-only presentation would be the only control.
func TestSecretAPIRefusesUneditablePath(t *testing.T) {
	s, _, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"gh": {"oauth_token": "x"},
	})
	w := httptest.NewRecorder()
	s.handleSecretWrite(w, httptest.NewRequest("PUT", "/api/v1/secrets/gh", strings.NewReader(`{"fields":{"a":"b"}}`)))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v for an uneditable path", got)
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
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v without a CSRF token", got)
	}
}

// A refused save on a secret that does not exist yet must still come back as
// its page: the user is mid-creation, and a bare JSON error on an HTML
// surface both looks broken and drops what they typed.
func TestRefusedSaveOnANewSecretRendersItsPage(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, nil)
	resp := uiPost(t, ts, "/ui/secrets-edit/field",
		fieldForm("personal/brand-new", 0, "a\nb", "v"))
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
	body := uiBody(t, resp)
	if !strings.Contains(body, "<table") {
		t.Error("the refusal is not the secret's page")
	}
	if !strings.Contains(body, "New secret") {
		t.Error("the page does not still present as new")
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v", got)
	}
}

// The edit row ships `was`, an editable name box and a "Remove field" button
// in one form, so a user who renames and *then* removes posts both. Taking
// the two at face value dropped the old field AND whatever now held the new
// name — two fields gone for one gesture.
func TestRemoveAfterRenamingInTheSameRowDropsOnlyThatField(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"old": "v", "other": "keep"},
	})
	f := fieldForm("personal/token", fake.currentVersion("personal/token"), "other", "")
	f.Set("was", "old")
	f.Set("delete", "1")

	if resp := uiPost(t, ts, "/ui/secrets-edit/field", f); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	got := fake.secrets["personal/token"]
	if _, still := got["old"]; still {
		t.Error("the row's own field was not removed")
	}
	if got["other"] != "keep" {
		t.Errorf("secret = %#v, want the unrelated field untouched", got)
	}
}

// Renaming onto a field that already exists would merge two into one with
// nothing said about it, and the one that loses is the one the user was not
// looking at.
func TestRenameOntoAnExistingFieldIsRefused(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"old": "a", "taken": "b"},
	})
	f := fieldForm("personal/token", fake.currentVersion("personal/token"), "taken", "a")
	f.Set("was", "old")

	if resp := uiPost(t, ts, "/ui/secrets-edit/field", f); resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
	if got := fake.wrote(); len(got) != 0 {
		t.Errorf("wrote %v, merging two fields", got)
	}
}

// A pure rename must not rewrite the value: the comparison has to look the
// value up under the name the row was *showing*, which on a rename is still
// the old one. Otherwise renaming a number stored it as a string, and a CRLF
// value flattened — changed without being edited.
func TestRenamingAFieldPreservesItsValueAndType(t *testing.T) {
	const crlf = "a\r\nb"
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"count": json.Number("1000000"), "blob": crlf},
	})
	v := fake.currentVersion("personal/token")

	f := fieldForm("personal/token", v, "total", "1000000")
	f.Set("was", "count")
	if resp := uiPost(t, ts, "/ui/secrets-edit/field", f); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("rename status = %d, want 303", resp.StatusCode)
	}
	fake.mu.Lock()
	got := fake.secrets["personal/token"]
	fake.mu.Unlock()
	if _, isString := got["total"].(string); isString {
		t.Error("renaming a number rewrote it as a string")
	}

	v = fake.currentVersion("personal/token")
	f = fieldForm("personal/token", v, "body", crlf)
	f.Set("was", "blob")
	if resp := uiPost(t, ts, "/ui/secrets-edit/field", f); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("rename status = %d, want 303", resp.StatusCode)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if got := fake.secrets["personal/token"]["body"]; got != crlf {
		t.Errorf("renaming a CRLF value flattened it to %q", got)
	}
}

// cas 0 means "only if absent", so its refusal says the secret exists — not
// that it moved on. Telling the user to reload a page whose content was never
// the problem is a dead end.
func TestCreateOverAnExistingSecretSaysSo(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	resp := uiPost(t, ts, "/ui/secrets-edit/field", fieldForm("personal/token", 0, "value", "other"))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
	body := uiBody(t, resp)
	if strings.Contains(body, "changed while you were editing") {
		t.Error("a create over an existing secret was reported as a stale edit")
	}
	if !strings.Contains(body, "already exists") {
		t.Errorf("the refusal does not say the secret exists: %s", body)
	}
}

// The error re-render takes a path straight off a form body, and it is
// reached from branches that fire before any policy check — so it validates
// the path itself rather than trusting the caller. Without that, a
// non-canonical path reached Vault and had that secret's field names
// rendered back under the refusal.
//
// The spelling matters, and this is why the obvious test is worthless: an
// explicit "../../otheruser/gh" never reaches Vault at all, because the HTTP
// client normalises the dot-dots away long before the request goes out, so
// asserting on it passes with the guard deleted. "personal/./token" is the
// shape that gets through — kvpath.Clean refuses it as non-canonical, while
// the wire normalises it back onto a real secret. Neutering the guard turns
// this test red; asserting on the traversal spelling does not.
func TestRefusalDoesNotRenderAnUnvalidatedPath(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"distinctive_field_name": "v"},
	})
	for _, path := range []string{"personal/./token", "personal//token", "../../otheruser/gh"} {
		f := url.Values{
			"path":    {path},
			"field":   {"value"},
			"value":   {"x"},
			"version": {"not-a-number"}, // fails before the policy check
		}
		resp := uiPost(t, ts, "/ui/secrets-edit/field", f)
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusSeeOther {
			t.Fatalf("%s: status = %d, want a refusal", path, resp.StatusCode)
		}
		body := uiBody(t, resp)
		if strings.Contains(body, "distinctive_field_name") {
			t.Errorf("%s: the refusal read and rendered a secret at an unvalidated path", path)
		}
		if strings.Contains(body, "otheruser") {
			t.Errorf("%s: the refusal rendered a path outside the user's own prefix", path)
		}
	}
}

// A malformed version is rejected rather than quietly becoming 0, which would
// turn an edit into a create. Absent is still 0 — the read-only fragments
// carry no version at all.
func TestRowParamsRejectMalformedVersion(t *testing.T) {
	_, ts, _ := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	for _, v := range []string{"abc", "-1", "1.5"} {
		q := url.Values{"path": {"personal/token"}, "field": {"value"}, "id": {"0"}, "version": {v}}.Encode()
		if resp := uiGet(t, ts, "/ui/fragments/secrets/edit-row?"+q); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("version %q: status = %d, want 400", v, resp.StatusCode)
		}
	}
	// Absent is fine: reveal and friends never send one.
	q := url.Values{"path": {"personal/token"}, "field": {"value"}, "id": {"0"}}.Encode()
	if resp := uiGet(t, ts, "/ui/fragments/secrets/reveal?"+q); resp.StatusCode != http.StatusOK {
		t.Errorf("reveal without a version: status = %d, want 200", resp.StatusCode)
	}
}

// editRowValue fetches the edit-row fragment and returns what the textarea
// was filled with — i.e. exactly what a user who changes nothing submits
// back. It undoes the two encodings between the value and the wire: datastar
// prefixes every line of a patch with "data: elements ", and html/template
// escapes the value into the textarea.
func editRowValue(t *testing.T, ts *httptest.Server, path, field string, version int) string {
	t.Helper()
	q := url.Values{
		"path": {path}, "field": {field}, "id": {"0"},
		"version": {strconv.Itoa(version)},
	}.Encode()
	resp := uiGet(t, ts, "/ui/fragments/secrets/edit-row?"+q)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("edit-row status = %d, want 200", resp.StatusCode)
	}
	lines := strings.Split(uiBody(t, resp), "\n")
	html := make([]string, 0, len(lines))
	for _, line := range lines {
		if rest, ok := strings.CutPrefix(line, "data: elements "); ok {
			html = append(html, rest)
		}
	}
	doc := strings.Join(html, "\n")
	const open = `aria-label="Field value">`
	i := strings.Index(doc, open)
	if i < 0 {
		t.Fatalf("edit-row carries no value textarea: %s", doc)
	}
	rest := doc[i+len(open):]
	j := strings.Index(rest, "</textarea>")
	if j < 0 {
		t.Fatalf("unterminated textarea: %s", doc)
	}
	// The fragment emits one newline of its own, because the HTML parser
	// drops a newline immediately after a textarea start tag. A browser drops
	// it, so this does too.
	return stdhtml.UnescapeString(strings.TrimPrefix(rest[:j], "\n"))
}

// The edit box must be filled by the same function the unchanged-check
// compares against. A second rendering — the page once pretty-printed
// composites with MarshalIndent while the comparison used compact Marshal —
// can never equal the first, so re-saving an untouched object rewrote it as a
// string of indented JSON. One definition, or the check is decorative.
func TestResavingAnUntouchedCompositeKeepsItsType(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/mix": {"obj": map[string]any{"a": "1", "b": "2"}},
	})
	v := fake.currentVersion("personal/mix")

	shown := editRowValue(t, ts, "personal/mix", "obj", v)
	if resp := uiPost(t, ts, "/ui/secrets-edit/field",
		editForm("personal/mix", v, "obj", shown)); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if got, isString := fake.secrets["personal/mix"]["obj"].(string); isString {
		t.Errorf("an untouched object was rewritten as the string %q", got)
	}
}

// The same property for the two scalar shapes a form cannot carry faithfully,
// exercised as the *subject* of the save rather than as a bystander the map
// copy would have preserved anyway.
func TestResavingAnUntouchedValueAsTheSubjectKeepsIt(t *testing.T) {
	const crlf = "one\r\ntwo\r\n"
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/mix": {"count": json.Number("1000000"), "body": crlf},
	})

	for _, field := range []string{"count", "body"} {
		v := fake.currentVersion("personal/mix")
		shown := editRowValue(t, ts, "personal/mix", field, v)
		if resp := uiPost(t, ts, "/ui/secrets-edit/field",
			editForm("personal/mix", v, field, shown)); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("%s: status = %d, want 303", field, resp.StatusCode)
		}
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	got := fake.secrets["personal/mix"]
	if _, isString := got["count"].(string); isString {
		t.Error("an untouched number, re-saved as the subject, became a string")
	}
	if got["body"] != crlf {
		t.Errorf("an untouched CRLF value, re-saved as the subject, became %q", got["body"])
	}
}

// Adding a field that already exists is refused for the same reason a rename
// onto one is: two fields become one with nothing said about it, and the one
// that loses is the one the user was not looking at. Check-and-set cannot
// catch this — the version is current and the write is well-formed.
func TestAddingAFieldThatAlreadyExistsIsRefused(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "original"},
	})
	v := fake.currentVersion("personal/token")

	// The add-row shape: no `was`, so this claims to introduce `value`.
	resp := uiPost(t, ts, "/ui/secrets-edit/field", fieldForm("personal/token", v, "value", "clobber"))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if got := fake.secrets["personal/token"]["value"]; got != "original" {
		t.Errorf("value = %q, want the credential left intact", got)
	}
}

// A secret that existed when the page was rendered and does not now is a
// stale view in exactly the way a moved-on version is — not a 404. The user
// has to look again either way, and "no such secret" invites them to retype
// a path that was never wrong.
func TestSavingIntoASecretDeletedUnderneathReadsAsStale(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "v"},
	})
	v := fake.currentVersion("personal/token")
	fake.mu.Lock()
	delete(fake.secrets, "personal/token")
	fake.mu.Unlock()

	resp := uiPost(t, ts, "/ui/secrets-edit/field", editForm("personal/token", v, "value", "mine"))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
	if body := uiBody(t, resp); !strings.Contains(body, "changed while you were editing") {
		t.Errorf("the refusal does not read as a stale view: %s", body)
	}
}

// The pencil's fragment carries a plaintext value, so it must be no less
// cacheable-proof than the page that carries the same value. datastar sets
// only Cache-Control: no-cache, which permits a store.
func TestValueBearingFragmentsAreNotStorable(t *testing.T) {
	_, ts, fake := editTestServer(t, []string{"personal"}, nil, map[string]map[string]any{
		"personal/token": {"value": "s3cret"},
	})
	v := fake.currentVersion("personal/token")
	q := url.Values{"path": {"personal/token"}, "field": {"value"}, "id": {"0"},
		"version": {strconv.Itoa(v)}}.Encode()

	for _, frag := range []string{"edit-row", "reveal"} {
		resp := uiGet(t, ts, "/ui/fragments/secrets/"+frag+"?"+q)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", frag, resp.StatusCode)
		}
		if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
			t.Errorf("%s: Cache-Control = %q, want no-store", frag, cc)
		}
		resp.Body.Close()
	}
}
