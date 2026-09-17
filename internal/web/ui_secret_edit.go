// Browser surface for secret editing: the editor page, the create form, and
// the form-POST handlers behind them.
//
// The four routes live under /ui/secret-editor/ rather than under
// /ui/secrets/ because the latter's page route is a {path...} wildcard: a
// literal /ui/secrets/edit would win the mux's precedence rules over it and
// so shadow a secret a user had genuinely named "edit". A separate prefix
// costs a little symmetry and removes the collision outright.
//
// These are plain form POSTs answered with a 303 redirect, not datastar SSE
// patches — the CSP forbids the inline <script> tags datastar's Redirect
// helper injects, and a redirect is what makes the result of a save a
// bookmarkable page rather than a patched fragment.
//
// One deliberate departure from the rest of the secrets UI: the editor page
// *does* carry field values in the HTML, where the detail table renders masked
// cells and reveals one field at a time. There is no way to edit a value you
// cannot see, so the invariant is preserved where it can be — reaching the
// editor is an explicit navigation, it is logged exactly as a reveal is, and
// the response is no-store like every other UI page. The detail page itself
// is unchanged: it still shows nothing until asked.
package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/goodtune/dotvault/internal/kvpath"
	"github.com/goodtune/dotvault/internal/vaultfs"
)

// uiSecretEditData is the view model for both the editor and the create form.
// One struct and one template serve both because the two differ in exactly
// two ways — whether the path is fixed and whether a secret must already
// exist — and splitting them would mean maintaining two copies of the same
// JSON textarea, error region and cancel target.
type uiSecretEditData struct {
	uiPageData
	// Path is the secret being edited; empty on the create form, where the
	// user types it into PathField instead.
	Path string
	// Creating selects the create presentation: an editable path input, a
	// "Create" button, and a POST to the create endpoint.
	Creating bool
	// PathField is the create form's path input value — pre-filled with an
	// editable root so the user is starting inside one rather than guessing.
	PathField string
	// Document is the JSON the textarea holds.
	Document string
	// Roots are the configured editable subtrees, listed on the create form
	// so the user can see where a path is allowed to go.
	Roots []string
	// CancelURL returns the user to where the gesture started.
	CancelURL string
	// FormError is a validation or Vault failure to show above the form.
	FormError string
}

// defaultNewSecretPath pre-fills the create form's path input. With exactly
// one editable root the answer is unambiguous; with several, leaving it blank
// is better than picking one arbitrarily and having the user not notice.
func defaultNewSecretPath(roots []string) string {
	if len(roots) == 1 {
		return roots[0] + "/"
	}
	return ""
}

// handleUISecretNew renders the create form. The path it pre-fills comes from
// the ?path= query when the gesture started inside a folder, so "New secret"
// on an editable folder lands you in that folder.
func (s *Server) handleUISecretNew(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIPage(w, r) {
		return
	}
	policy := s.editPolicy()
	if !policy.Enabled() {
		writeError(w, "no editable key spaces are configured", http.StatusForbidden)
		return
	}
	prefill := defaultNewSecretPath(policy.Roots())
	if dir := r.URL.Query().Get("path"); dir != "" && policy.AllowsWithin(dir) {
		clean, err := kvpath.Clean(dir)
		if err == nil {
			prefill = clean + "/"
		}
	}
	s.uiRenderPage(w, "secret_edit", uiSecretEditData{
		uiPageData: s.uiBase(r.Context(), "New secret", "secrets", ""),
		Creating:   true,
		PathField:  prefill,
		// A skeleton rather than an empty box: it shows the shape the
		// textarea wants without the user having to know that a KVv2 data
		// section is a flat-ish JSON object.
		Document:  "{\n  \"\": \"\"\n}\n",
		Roots:     policy.Roots(),
		CancelURL: "/ui/secrets/",
	})
}

// handleUISecretEdit renders the editor for an existing secret.
func (s *Server) handleUISecretEdit(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIPage(w, r) {
		return
	}
	rel := r.URL.Query().Get("path")
	clean, err := s.editPolicy().Allow(rel)
	if err != nil {
		writeError(w, err.Error(), secretEditStatus(err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), secretEditTimeout)
	defer cancel()

	doc, err := s.readEditableDocument(ctx, clean)
	if err != nil {
		if errors.Is(err, errSecretMissing) {
			writeError(w, "secret not found", http.StatusNotFound)
			return
		}
		slog.Error("ui: read secret for edit failed", "path", clean, "error", err)
		writeError(w, "failed to read secret", http.StatusBadGateway)
		return
	}
	// Logged like a reveal, and for the same reason: this is the moment the
	// values leave Vault for a screen, and an operator auditing that should
	// see it whichever gesture caused it.
	slog.Info("secret opened for editing via web UI", "path", clean)
	s.uiRenderPage(w, "secret_edit", s.uiSecretEditPage(ctx, clean, doc))
}

// uiSecretEditPage assembles the editor view model for a known-editable path.
func (s *Server) uiSecretEditPage(ctx context.Context, clean, doc string) uiSecretEditData {
	return uiSecretEditData{
		uiPageData: s.uiBase(ctx, clean, "secrets", clean),
		Path:       clean,
		Document:   doc,
		Roots:      s.editPolicy().Roots(),
		CancelURL:  "/ui/secrets/" + uiEscapePath(clean),
	}
}

// handleUISecretSave commits the editor, for both create and replace. Which
// one it is follows from the "create" form field rather than from whether the
// secret happens to exist, so a create whose path was mistyped onto an
// existing secret is reported instead of silently replacing it.
func (s *Server) handleUISecretSave(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIWrite(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, secretBodyLimit)
	creating := uiFormValue(r, "create") == "1"
	rel := uiFormValue(r, "path")
	doc := uiFormValue(r, "document")

	// Re-rendering the form on failure keeps the user's unsaved document,
	// which on this page may be the only copy of a credential they have just
	// typed. Losing it to a validation error would be unforgivable.
	//
	// The status is the service layer's own verdict rather than a blanket
	// 422, so a policy refusal reads as 403 here exactly as it does on the
	// JSON API. Collapsing them would leave "you may not write here" and
	// "your JSON is malformed" indistinguishable to anything but a human
	// reading the rendered page.
	renderErr := func(status int, msg string) {
		data := uiSecretEditData{
			uiPageData: s.uiBase(r.Context(), "Edit secret", "secrets", ""),
			Creating:   creating,
			Document:   doc,
			Roots:      s.editPolicy().Roots(),
			FormError:  msg,
			CancelURL:  "/ui/secrets/",
		}
		if creating {
			data.PathField = rel
			data.Title = "New secret"
		} else {
			data.Path = rel
			data.Title = rel
			data.CancelURL = "/ui/secrets/" + uiEscapePath(rel)
		}
		w.WriteHeader(status)
		s.uiRenderPage(w, "secret_edit", data)
	}

	if strings.TrimSpace(rel) == "" {
		renderErr(http.StatusUnprocessableEntity, "a path is required")
		return
	}
	data, err := vaultfs.ParseDocument([]byte(doc))
	if err != nil {
		renderErr(http.StatusUnprocessableEntity, "the document must be a JSON object with at least one field")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), secretEditTimeout)
	defer cancel()

	clean, err := s.writeEditableSecret(ctx, rel, data, creating)
	if err != nil {
		renderErr(secretEditStatus(err), err.Error())
		return
	}
	http.Redirect(w, r, "/ui/secrets/"+uiEscapePath(clean), http.StatusSeeOther)
}

// handleUISecretDelete removes a secret and all of its versions. The form
// carries a "confirm" field the user types the secret's leaf name into —
// DeleteKVv2 is a metadata delete with no undelete, so the gesture is made
// deliberate rather than one mis-click.
func (s *Server) handleUISecretDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIWrite(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, sshBodyLimit)
	rel := uiFormValue(r, "path")
	confirm := uiFormValue(r, "confirm")

	clean, err := s.editPolicy().Allow(rel)
	if err != nil {
		writeError(w, err.Error(), secretEditStatus(err))
		return
	}
	if leaf := clean[strings.LastIndex(clean, "/")+1:]; confirm != leaf {
		// Re-render the detail page carrying the complaint rather than a bare
		// error, so the user is still standing in front of the secret.
		s.renderUISecretDetailError(w, r, clean, "type the secret's name ("+leaf+") to confirm deletion")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), secretEditTimeout)
	defer cancel()

	if _, err := s.deleteEditableSecret(ctx, clean); err != nil {
		s.renderUISecretDetailError(w, r, clean, err.Error())
		return
	}
	// The secret is gone, so its own URL would 404; land the user on the
	// parent folder, which is where the next thing they want is.
	target := "/ui/secrets/"
	if i := strings.LastIndex(clean, "/"); i > 0 {
		target += uiEscapePath(clean[:i]) + "/"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
