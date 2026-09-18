// In-place secret editing on the detail page.
//
// There is no separate editor view. /ui/secrets/<path> is the secret, and a
// pencil on a row turns that row from read-only into an input — the same
// gesture shape the eye and clipboard buttons beside it already use. A path
// inside an editable subtree that holds nothing yet renders as an empty
// secret ready to have its first field added, so "create" is just "edit a
// secret that does not exist": the URL is the whole state.
//
// Every write is a **check-and-set against the version the row was rendered
// from**. That is the guarantee the previous design could not make: a
// read-probe-then-write only narrows the window another writer lands in, and
// the losing change disappeared with nothing to show for it. Here Vault
// settles it, so a save made against a stale view is refused and the user is
// told to look again rather than quietly overwriting someone.
//
// Saves are plain form POSTs answered with a 303 back to the secret, not
// datastar patches: the CSP forbids the inline <script> datastar's Redirect
// helper injects, and a redirect re-reads the secret so the page always
// carries a fresh version to check against next time.
package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/goodtune/dotvault/internal/vault"
)

// maxFieldValue caps a submitted field value, so a scripted POST cannot make
// the server assemble an unbounded document. It matches the FUSE mount's own
// per-document ceiling.
const maxFieldValue = 1 << 20 // 1 MiB

// errUnrenderableName reports a name this form cannot show and get back
// unchanged. A sentinel so the refusal reads the same wherever it is raised,
// and so errors.Is can find it.
var errUnrenderableName = errors.New("this form cannot edit a name containing a line break or leading/trailing whitespace without renaming it; use the JSON API or the filesystem mount, which edit it losslessly")

// editorSafeName reports whether the editor can render name into an <input>
// and receive the identical bytes back.
//
// This is the dividing line between the two kinds of text on the page. A
// *value* may contain anything and rides a <textarea>, which preserves it. A
// *name* — a field name, or one segment of the secret's path — is an
// identifier in an <input>, and two things happen to it there: the HTML value
// sanitization algorithm strips CR and LF outright, and the handler trims
// surrounding whitespace so a stray space is not a new field. Either turns a
// name the page rendered into a different name on submit, which a rename-
// aware write then acts on — silently moving a field.
//
// TrimSpace is the predicate rather than an enumerated character set because
// it is the same function the submit path applies, so the two sides agree by
// construction — and it covers U+0085, U+2028 and the rest of unicode.IsSpace
// for free, where a hand-written set missed them.
func editorSafeName(name string) bool {
	return name != "" && name == strings.TrimSpace(name) && !strings.ContainsAny(name, "\r\n")
}

// checkEditorPath rejects a relative path any of whose segments the editor
// cannot round-trip. Every route into an edit funnels through here, because
// checking one input at a time kept leaving a different one open — `prefix`
// and hidden fields have no value sanitization algorithm at all.
//
// The error names nothing: a path segment is as telling as a field name.
func checkEditorPath(rel string) error {
	for _, seg := range strings.Split(rel, "/") {
		if !editorSafeName(seg) {
			return fmt.Errorf("the secret's name: %w", errUnrenderableName)
		}
	}
	return nil
}

// checkEditorFields rejects a secret whose field names the editor cannot
// round-trip, reporting how many rather than which.
func checkEditorFields(fields map[string]any) error {
	n := 0
	for name := range fields {
		if !editorSafeName(name) {
			n++
		}
	}
	if n > 0 {
		return fmt.Errorf("%d of this secret's field names: %w", n, errUnrenderableName)
	}
	return nil
}

// normalizeFormNewlines undoes the line-ending conversion HTML form
// submission performs, so a multi-line secret survives a round trip.
//
// A <textarea> is the only control that can carry a newline at all — the
// value sanitization algorithm for <input type=text> strips CR and LF, so
// rendering a PEM private key into one and saving would silently flatten it.
// Textareas keep the newlines, but the form-submission algorithm normalizes
// them to CRLF on the way out, so the server converts back or every
// multi-line value grows a \r per line.
//
// Byte-for-byte preservation of an unedited value does not rest on this being
// exactly right: applyFieldEdit compares the normalized submission against
// the normalized stored value and keeps the *stored* one when they match.
func normalizeFormNewlines(v string) string {
	if !strings.ContainsAny(v, "\r") {
		return v
	}
	v = strings.ReplaceAll(v, "\r\n", "\n")
	return strings.ReplaceAll(v, "\r", "\n")
}

// uiFieldRow is one row of the secret's field table.
type uiFieldRow struct {
	Name string
	ID   int
	// Value is populated only when the row is rendered revealed or editable;
	// the read-only page never carries it.
	Value string
	// Rows sizes an editable value's <textarea>: one line looks like a text
	// input, a PEM opens tall enough to work with.
	Rows int
	// Version is the secret version this row was rendered from, posted back
	// with any save so Vault can refuse a stale write.
	Version int
	// Path is the secret the row belongs to.
	Path string
	// New marks the blank row that adds a field.
	New bool
	// Editable renders the pencil. It is not decoration: EditPolicy.Allows is
	// documented as the reason a screen never offers an edit the request
	// would refuse, and a pencil on a read-only page — which is every page
	// under the default empty web.editable_paths — is exactly that promise
	// broken. It is set from editableRow, the same predicate the edit-row
	// handler gates on, so the button appears if and only if clicking it
	// works.
	Editable bool

	RevealURL  string
	MaskURL    string
	CopyURL    string
	CopyBtnURL string
	EditURL    string
	CancelURL  string
}

// uiSecretFieldRefs builds the fragment URLs for one row. Every URL is
// strictly url.Values-encoded because these are interpolated into datastar
// attributes, which are evaluated as JavaScript.
func uiSecretFieldRefs(path, field string, id, version int) uiFieldRow {
	q := url.Values{
		"path":    {path},
		"field":   {field},
		"id":      {strconv.Itoa(id)},
		"version": {strconv.Itoa(version)},
	}.Encode()
	return uiFieldRow{
		Name:       field,
		ID:         id,
		Version:    version,
		Path:       path,
		Rows:       1,
		RevealURL:  "/ui/fragments/secrets/reveal?" + q,
		MaskURL:    "/ui/fragments/secrets/mask?" + q,
		CopyURL:    "/ui/actions/copy-field?" + q,
		CopyBtnURL: "/ui/fragments/secrets/copy-btn?" + q,
		EditURL:    "/ui/fragments/secrets/edit-row?" + q,
		CancelURL:  "/ui/fragments/secrets/row?" + q,
	}
}

// valueRows sizes an editable value's textarea without letting a pathological
// value push the rest of the page away.
func valueRows(v string) int {
	if n := strings.Count(v, "\n") + 1; n > 14 {
		return 14
	} else if n > 1 {
		return n
	}
	return 1
}

// uiSecretRowParams extracts the path/field/id/version shared by the row
// fragments. version is optional (the read-only fragments do not need it).
func uiSecretRowParams(r *http.Request) (row uiFieldRow, ok bool) {
	q := r.URL.Query()
	path, field := q.Get("path"), q.Get("field")
	id, err := strconv.Atoi(q.Get("id"))
	if path == "" || field == "" || err != nil || id < 0 ||
		!validateUISecretPath(path) || strings.HasSuffix(path, "/") {
		return uiFieldRow{}, false
	}
	// Absent is 0, which is KVv2's "this does not exist" and the right answer
	// for a row on a secret being created. But a *malformed* version is
	// rejected rather than quietly becoming 0: silently downgrading it would
	// turn an edit into a create and refuse the save for a reason the page
	// never showed. The read-only fragments (reveal, mask, copy) carry no
	// version at all and are unaffected.
	version := 0
	if raw := q.Get("version"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 0 {
			return uiFieldRow{}, false
		}
		version = v
	}
	return uiSecretFieldRefs(path, field, id, version), true
}

// editableRow reports why this row cannot be turned into inputs, or nil if it
// can. It is the single definition consulted by both the handler that does
// the turning and the template flag that offers the gesture, so the pencil
// cannot appear on a row whose edit-row request would be refused.
func (s *Server) editableRow(path, field string) error {
	// Return Allow's own error rather than a flattened ErrNotEditable: a path
	// inside an editable folder but too deep is a different thing to tell a
	// user than one outside every folder, and inventing a sentinel here would
	// be a second definition of a rule the policy already owns.
	if _, err := s.editPolicy().Allow(path); err != nil {
		return err
	}
	if err := checkEditorPath(path); err != nil {
		return err
	}
	if !editorSafeName(field) {
		return fmt.Errorf("this field's name: %w", errUnrenderableName)
	}
	return nil
}

// handleUISecretEditRow turns one read-only row into an editable one. It is a
// datastar patch of that row alone, precisely so the rest of the table — and
// anything already being typed in another row — is left untouched.
func (s *Server) handleUISecretEditRow(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIRead(w) {
		return
	}
	row, ok := uiSecretRowParams(r)
	if !ok {
		writeError(w, "invalid edit request", http.StatusBadRequest)
		return
	}
	if err := s.editableRow(row.Path, row.Name); err != nil {
		writeError(w, err.Error(), secretEditStatus(err))
		return
	}
	row.Editable = true
	ctx, cancel := context.WithTimeout(r.Context(), secretEditTimeout)
	defer cancel()

	// displayFieldValue, deliberately, and not the page's reveal rendering:
	// applyFieldEdit decides "unchanged" by comparing what comes back against
	// exactly this, so filling the box any other way makes that comparison
	// unsatisfiable and every save of an untouched composite rewrites it.
	raw, found, err := s.uiSecretField(ctx, row.Path, row.Name)
	if err != nil {
		slog.Error("ui: read field for edit failed", "path", row.Path, "error", err)
		writeError(w, "failed to read secret", http.StatusBadGateway)
		return
	}
	if !found {
		writeError(w, "field not found", http.StatusNotFound)
		return
	}
	value := displayFieldValue(raw)
	// Logged like a reveal, for the same reason: this is the moment the value
	// leaves Vault for a screen.
	slog.Info("secret field opened for editing via web UI", "path", row.Path)
	row.Value = value
	row.Rows = valueRows(value)
	uiPatchFragment(w, r, "secret-row-edit", row)
}

// handleUISecretRow restores a row to read-only. No Vault read — cancelling
// only needs the identifiers to rebuild the masked form.
func (s *Server) handleUISecretRow(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIRead(w) {
		return
	}
	row, ok := uiSecretRowParams(r)
	if !ok {
		writeError(w, "invalid row request", http.StatusBadRequest)
		return
	}
	// Re-derive rather than trust a posted flag: cancelling must put back the
	// row the page would have rendered, pencil included, and the policy may
	// have changed under it (enrolments reload).
	row.Editable = s.editableRow(row.Path, row.Name) == nil
	uiPatchFragment(w, r, "secret-row", row)
}

// parseFieldEdit reads a row save into a fieldEdit.
func parseFieldEdit(r *http.Request) (path string, e fieldEdit, err error) {
	path = r.PostFormValue("path")
	e.Name = strings.TrimSpace(r.PostFormValue("field"))
	e.Was = r.PostFormValue("was")
	e.Delete = r.PostFormValue("delete") == "1"
	e.Value = normalizeFormNewlines(r.PostFormValue("value"))
	version, convErr := strconv.Atoi(r.PostFormValue("version"))
	if convErr != nil || version < 0 {
		return path, e, errors.New("missing or invalid version")
	}
	e.Version = version
	if e.Name == "" {
		return path, e, errors.New("a field name is required")
	}
	if len(e.Value) > maxFieldValue {
		return path, e, errors.New("value is too large")
	}
	// `was` rides a hidden input, which has no value sanitization algorithm,
	// so it is checked rather than trusted — an unrenderable one is a claim
	// to rename a field the page could never have shown.
	if e.Was != "" && !editorSafeName(e.Was) {
		return path, e, fmt.Errorf("a previously-rendered field name: %w", errUnrenderableName)
	}
	return path, e, nil
}

// handleUISecretFieldSave commits one row: a write, a rename, or a delete,
// each under check-and-set against the version the row was rendered from.
func (s *Server) handleUISecretFieldSave(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIWrite(w, r) {
		return
	}
	// Generous relative to maxFieldValue because form encoding expands a
	// value by up to ~3x: sized tightly, a legitimate 1 MiB value would die
	// as "malformed form submission" before parseFieldEdit could say what
	// was actually wrong with it.
	r.Body = http.MaxBytesReader(w, r.Body, 4*maxFieldValue)
	if err := r.ParseForm(); err != nil {
		writeError(w, "malformed form submission", http.StatusBadRequest)
		return
	}
	path, edit, err := parseFieldEdit(r)
	if err != nil {
		s.renderUISecretDetailError(w, r, path, http.StatusUnprocessableEntity, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), secretEditTimeout)
	defer cancel()

	clean, err := s.writeSecretField(ctx, path, edit)
	if err != nil {
		status := secretEditStatus(err)
		if errors.Is(err, vault.ErrCASMismatch) {
			// Re-render from the *current* state, not the stale one: the
			// user's next attempt has to be made against what is actually
			// stored, or it would be refused again for the same reason.
			s.renderUISecretDetailError(w, r, path, status,
				"this secret changed while you were editing it; your change was not saved — the values below are current")
			return
		}
		s.renderUISecretDetailError(w, r, path, status, err.Error())
		return
	}
	// The canonical path, not the posted spelling: "/personal/token/" would
	// otherwise build "/ui/secrets//personal/token/".
	http.Redirect(w, r, "/ui/secrets/"+uiEscapePath(clean), http.StatusSeeOther)
}

// handleUISecretGoto is the "New secret" gesture: a name typed into the
// folder page's dialog becomes a URL. The secret does not exist yet, and that
// is exactly what makes the page it lands on a create form — there is no
// separate "new" route to keep in step with the real one.
func (s *Server) handleUISecretGoto(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIWrite(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, sshBodyLimit)
	if err := r.ParseForm(); err != nil {
		writeError(w, "malformed form submission", http.StatusBadRequest)
		return
	}
	folder := r.PostFormValue("folder")
	name := strings.TrimSpace(r.PostFormValue("name"))
	target := name
	if folder != "" {
		target = folder + "/" + name
	}
	clean, err := s.editPolicy().Allow(target)
	if err != nil {
		writeError(w, err.Error(), secretEditStatus(err))
		return
	}
	if err := checkEditorPath(clean); err != nil {
		writeError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	http.Redirect(w, r, "/ui/secrets/"+uiEscapePath(clean), http.StatusSeeOther)
}

// handleUISecretDelete removes a secret and all of its versions. The form
// carries a "confirm" field the user types the secret's name into —
// DeleteKVv2 is a metadata delete with no undelete, so the gesture is
// deliberately more than one click.
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
	if _, leaf := uiEditorPrefix(clean); confirm != leaf {
		s.renderUISecretDetailError(w, r, clean, http.StatusConflict,
			"type the secret's name ("+leaf+") to confirm deletion")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), secretEditTimeout)
	defer cancel()

	if _, err := s.deleteEditableSecret(ctx, clean); err != nil {
		s.renderUISecretDetailError(w, r, clean, secretEditStatus(err), err.Error())
		return
	}
	// The secret is gone, so its own URL would 404; land on the parent
	// folder, which is where the next thing the user wants is.
	target := "/ui/secrets/"
	if prefix, _ := uiEditorPrefix(clean); prefix != "" {
		target += uiEscapePath(prefix) + "/"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// uiEditorPrefix splits a relative path into its folder and leaf.
func uiEditorPrefix(rel string) (prefix, name string) {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[:i], rel[i+1:]
	}
	return "", rel
}
