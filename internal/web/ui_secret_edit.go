// Browser surface for secret editing: the create form, the editor, and the
// form-POST handlers behind them.
//
// The routes live under /ui/secret-editor/ rather than under /ui/secrets/
// because the latter's page route is a {path...} wildcard: a literal
// /ui/secrets/edit would win the mux's precedence rules over it and so shadow
// a secret a user had genuinely named "edit". A separate prefix costs a
// little symmetry and removes the collision outright.
//
// Saves are plain form POSTs answered with a 303 redirect, not datastar SSE
// patches — the CSP forbids the inline <script> tags datastar's Redirect
// helper injects, and a redirect is what makes the result of a save a
// bookmarkable page rather than a patched fragment. The one datastar use here
// is "add another field", which appends a row without disturbing the rows
// already typed into.
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
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	datastar "github.com/starfederation/datastar-go/datastar"

	"github.com/goodtune/dotvault/internal/kvpath"
)

// blankCreateRows is how many empty field rows the create form starts with.
// Three covers the common shape (a token, a username, a URL) without a page
// of empty boxes; "Add field" supplies the rest.
const blankCreateRows = 3

// maxFieldRows caps how many rows one submission may carry, so a scripted
// POST cannot make the server assemble an unbounded map. A KVv2 secret with
// more fields than this is not what this form is for.
const maxFieldRows = 256

// uiFieldRow is one name/value pair in the editor form.
type uiFieldRow struct {
	// Index is the row's position, used only to give the inputs distinct DOM
	// ids; the form posts repeated `field_name`/`field_value` names and pairs
	// them positionally, so nothing depends on the number itself.
	Index int
	Name  string
	Value string
	// Rows sizes the value's <textarea>. One line looks like a text input;
	// a PEM opens tall enough to work with.
	Rows int
}

// valueRows sizes a value's textarea: one row for a single-line value, and
// enough for a multi-line one without letting a pathological value push the
// rest of the form off the page.
func valueRows(v string) int {
	n := strings.Count(v, "\n") + 1
	switch {
	case n < 1:
		return 1
	case n > 14:
		return 14
	default:
		return n
	}
}

// errUnrenderableName reports a name this form cannot show and get back
// unchanged. It is a sentinel so the refusal reads the same wherever it is
// raised, and so `errors.Is` can find it.
var errUnrenderableName = errors.New("this form cannot edit a name containing a line break or leading/trailing whitespace without renaming it; use the JSON API or the filesystem mount, which edit it losslessly")

// editorSafeName reports whether the editor can render name into an <input>
// and receive the identical bytes back.
//
// This is the dividing line between the two kinds of text on the form. A
// *value* may contain anything and rides a <textarea>, which preserves it. A
// *name* — a field name, or one segment of the secret's path — is an
// identifier in an <input>, and two things happen to it there: the HTML value
// sanitization algorithm strips CR and LF outright, and the handler trims
// surrounding whitespace so a user's stray space is not a new field. Either
// one turns a name the page rendered into a different name on submit, which
// the patch then reads as a deliberate rename and acts on — silently moving a
// field, or the whole secret.
//
// So the rule is not "no line breaks" but the stronger, honest one: a name
// must survive the round trip exactly. TrimSpace is the predicate rather than
// a hand-written character set because it is the *same* function the submit
// path applies, which is what makes the two sides agree by construction —
// and it happens to cover U+0085, U+2028 and the rest of unicode.IsSpace for
// free, where an enumerated set would have missed them.
func editorSafeName(name string) bool {
	return name != "" && name == strings.TrimSpace(name) && !strings.ContainsAny(name, "\r\n")
}

// checkEditorPath rejects a relative path any of whose segments the editor
// cannot round-trip. Every route into the editor funnels through here — the
// source path, the joined create/rename target, and the page load — because
// the previous shape checked one input at a time and every review found a
// different one still open (`prefix`, the hidden `path`, the untrimmed
// original). One chokepoint beside EditPolicy.Allow is the shape that cannot
// grow another hole.
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
// round-trip, reporting how many rather than which — a field name can itself
// be telling, and this feeds a user-visible message.
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

// normalizeFormNewlines undoes the line-ending conversion HTML form// normalizeFormNewlines undoes the line-ending conversion HTML form
// submission performs, so a multi-line secret survives a round trip.
//
// A <textarea> is the only control that can carry a newline at all — the
// value sanitization algorithm for <input type=text> *strips* CR and LF, so
// rendering a PEM private key into one and saving would silently flatten it.
// Textareas keep the newlines, but the form-submission algorithm normalizes
// them to CRLF on the way out, so the server has to convert back or every
// multi-line value would grow a \r per line.
//
// Byte-for-byte preservation of an *unedited* value does not rest on this
// being exactly right: applyFieldPatch compares the normalized submission
// against the stored value's rendering and, when they match, keeps the stored
// value untouched. This normalization is what makes that comparison succeed.
func normalizeFormNewlines(v string) string {
	if !strings.ContainsAny(v, "\r") {
		return v
	}
	v = strings.ReplaceAll(v, "\r\n", "\n")
	// A lone CR is not something a conforming browser sends, but normalizing
	// it costs nothing and keeps the result free of stray carriage returns.
	return strings.ReplaceAll(v, "\r", "\n")
}

// uiSecretEditData is the view model for both the create form and the editor.
// One struct and one template serve both because they differ in three small
// ways — whether the prefix is fixed, whether the name may be renamed, and
// where the form posts — and splitting them would mean two copies of the same
// row list, error region and cancel target.
type uiSecretEditData struct {
	uiPageData
	// Creating selects the create presentation.
	Creating bool
	// Prefix is the editable folder the secret lives in. It is implicit: the
	// form shows it as static text beside the name input and posts it in a
	// hidden field, so the user types "token" rather than "personal/token".
	Prefix string
	// Name is the secret's name relative to Prefix. On the editor it is
	// editable, and changing it renames the secret.
	Name string
	// Path is the full relative path being edited ("" while creating).
	Path string
	// Rows are the field name/value pairs, including blank rows to fill in.
	Rows []uiFieldRow
	// Original lists the field names the form was rendered from, posted back
	// as hidden inputs so the save can tell a field the user *cleared* from
	// one another writer added since the page loaded. See applyFieldPatch.
	Original []string
	// AddRowURL is the datastar endpoint that appends one more blank row.
	AddRowURL string
	// CancelURL returns the user to where the gesture started.
	CancelURL string
	// FormError is a validation or Vault failure to show above the form.
	FormError string
}

// uiEditorPrefix splits a relative path into its folder and leaf. The folder
// is the implicit prefix the form shows as static text; the leaf is what the
// user edits.
func uiEditorPrefix(rel string) (prefix, name string) {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[:i], rel[i+1:]
	}
	return "", rel
}

// uiFieldRows turns a secret's data into sorted form rows, followed by the
// requested number of blank ones.
func uiFieldRows(fields map[string]any, blanks int) []uiFieldRow {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]uiFieldRow, 0, len(names)+blanks)
	for _, name := range names {
		value := displayFieldValue(fields[name])
		rows = append(rows, uiFieldRow{Index: len(rows), Name: name, Value: value, Rows: valueRows(value)})
	}
	for i := 0; i < blanks; i++ {
		rows = append(rows, uiFieldRow{Index: len(rows), Rows: 1})
	}
	return rows
}

// addRowURL builds the datastar endpoint that appends row `next`.
func addRowURL(next int) string {
	return "/ui/fragments/secret-editor/field-row?" + url.Values{"i": {strconv.Itoa(next)}}.Encode()
}

// handleUISecretNew renders the create form for a folder inside an editable
// subtree. The folder comes from ?path= — the "New secret" control on a
// folder page — and becomes the form's implicit prefix.
func (s *Server) handleUISecretNew(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIPage(w, r) {
		return
	}
	policy := s.editPolicy()
	dir := r.URL.Query().Get("path")
	if !policy.AllowsWithin(dir) {
		// Either nothing is editable, or the named folder is outside every
		// configured subtree. Both are the same answer to the user: you
		// cannot create a secret here.
		writeError(w, "secrets cannot be created here", http.StatusForbidden)
		return
	}
	// AllowsWithin has already established the folder is a valid relative
	// path, so Clean cannot fail — the error branch would be unreachable.
	prefix, _ := kvpath.Clean(dir)
	rows := uiFieldRows(nil, blankCreateRows)
	s.uiRenderPage(w, "secret_edit", uiSecretEditData{
		uiPageData: s.uiBase(r.Context(), "New secret", "secrets", prefix+"/"),
		Creating:   true,
		Prefix:     prefix,
		Rows:       rows,
		AddRowURL:  addRowURL(len(rows)),
		CancelURL:  "/ui/secrets/" + uiEscapePath(prefix) + "/",
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

	fields, err := s.readEditableFields(ctx, clean)
	if err != nil {
		if errors.Is(err, errSecretMissing) {
			writeError(w, "secret not found", http.StatusNotFound)
			return
		}
		slog.Error("ui: read secret for edit failed", "path", clean, "error", err)
		writeError(w, "failed to read secret", http.StatusBadGateway)
		return
	}
	// Refuse before rendering rather than corrupting on save. 409 rather than
	// 422: nothing is wrong with the request, the stored secret is simply in
	// a shape this form cannot represent.
	if err := errors.Join(checkEditorPath(clean), checkEditorFields(fields)); err != nil {
		writeError(w, err.Error(), http.StatusConflict)
		return
	}
	// Logged like a reveal, and for the same reason: this is the moment the
	// values leave Vault for a screen, and an operator auditing that should
	// see it whichever gesture caused it.
	slog.Info("secret opened for editing via web UI", "path", clean)
	s.uiRenderPage(w, "secret_edit", s.uiSecretEditPage(ctx, clean, fields))
}

// uiSecretEditPage assembles the editor view model for a known-editable path.
func (s *Server) uiSecretEditPage(ctx context.Context, clean string, fields map[string]any) uiSecretEditData {
	prefix, name := uiEditorPrefix(clean)
	// One blank row so adding a field needs no extra click in the common case.
	rows := uiFieldRows(fields, 1)
	original := make([]string, 0, len(fields))
	for k := range fields {
		original = append(original, k)
	}
	sort.Strings(original)
	return uiSecretEditData{
		uiPageData: s.uiBase(ctx, clean, "secrets", clean),
		Prefix:     prefix,
		Name:       name,
		Path:       clean,
		Rows:       rows,
		Original:   original,
		AddRowURL:  addRowURL(len(rows)),
		CancelURL:  "/ui/secrets/" + uiEscapePath(clean),
	}
}

// handleUISecretFieldRow appends one blank field row to the open form. It is
// a datastar append rather than a re-render of the whole form precisely
// because a re-render would discard everything already typed.
func (s *Server) handleUISecretFieldRow(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIRead(w) {
		return
	}
	i, err := strconv.Atoi(r.URL.Query().Get("i"))
	if err != nil || i < 0 || i >= maxFieldRows {
		writeError(w, "invalid row request", http.StatusBadRequest)
		return
	}
	row, err := uiFragment("secret-field-row", uiFieldRow{Index: i, Rows: 1})
	if err != nil {
		writeError(w, "failed to render fragment", http.StatusInternalServerError)
		return
	}
	// The button re-points itself at the next index, so repeated clicks keep
	// producing distinct rows.
	btn, err := uiFragment("secret-add-field-btn", uiSecretEditData{AddRowURL: addRowURL(i + 1)})
	if err != nil {
		writeError(w, "failed to render fragment", http.StatusInternalServerError)
		return
	}
	sse := datastar.NewSSE(w, r)
	if err := sse.PatchElements(row,
		datastar.WithSelector("#secret-field-rows"),
		datastar.WithMode(datastar.ElementPatchModeAppend),
	); err != nil {
		slog.Debug("append field row failed", "error", err)
		return
	}
	if err := sse.PatchElements(btn); err != nil {
		slog.Debug("patch add-field button failed", "error", err)
	}
}

// parseFieldRows reads the repeated field_name/field_value inputs into a
// patch. Rows are paired positionally, which the browser guarantees by
// submitting same-named controls in document order; a mismatch means the body
// was not produced by this form and is refused rather than guessed at.
//
// A row whose name is blank is dropped, so the blank rows the form always
// carries cost the user nothing.
func parseFieldRows(r *http.Request) (fieldPatch, error) {
	names := r.PostForm["field_name"]
	values := r.PostForm["field_value"]
	if len(names) != len(values) {
		return fieldPatch{}, errors.New("field names and values do not pair up")
	}
	if len(names) > maxFieldRows {
		return fieldPatch{}, errors.New("too many fields")
	}
	p := fieldPatch{Submitted: make(map[string]string, len(names)), Original: map[string]struct{}{}}
	for i, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !editorSafeName(name) {
			// Unreachable from a browser (the input strips line breaks and
			// TrimSpace has just run), so this is a hand-made request.
			// Refusing keeps the round trip honest rather than storing a name
			// the form could never render back.
			return fieldPatch{}, fmt.Errorf("a submitted field name: %w", errUnrenderableName)
		}
		if _, dup := p.Submitted[name]; dup {
			// Content-free by the same rule the rest of this path follows: a
			// field name can itself be telling, and an error string is one
			// refactor away from a log line.
			return fieldPatch{}, errors.New("two rows name the same field")
		}
		p.Submitted[name] = normalizeFormNewlines(values[i])
	}
	for _, name := range r.PostForm["original_field"] {
		if name == "" {
			continue
		}
		if !editorSafeName(name) {
			// The editor refuses to render such a secret, so a browser could
			// never produce this marker — and a marker naming a field the
			// form could not have shown is a claim to delete something the
			// user was never given the chance to see. The check is the same
			// one the submitted names get, deliberately: when the two sides
			// disagreed about whitespace, a stored " a" came back as "a" and
			// was silently renamed.
			return fieldPatch{}, fmt.Errorf("a previously-rendered field name: %w", errUnrenderableName)
		}
		p.Original[name] = struct{}{}
	}
	return p, nil
}

// handleUISecretCreate commits the create form.
func (s *Server) handleUISecretCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIWrite(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, secretBodyLimit)
	if err := r.ParseForm(); err != nil {
		writeError(w, "malformed form submission", http.StatusBadRequest)
		return
	}
	prefix := r.PostFormValue("prefix")
	name := strings.TrimSpace(r.PostFormValue("name"))
	patch, parseErr := parseFieldRows(r)

	// Re-rendering keeps what the user typed, which on this page may be the
	// only copy of a credential they have just entered. Losing it to a
	// validation error would be unforgivable.
	renderErr := func(status int, msg string) {
		rows := uiRowsFromForm(r)
		data := uiSecretEditData{
			uiPageData: s.uiBase(r.Context(), "New secret", "secrets", prefix+"/"),
			Creating:   true,
			Prefix:     prefix,
			Name:       name,
			Rows:       rows,
			AddRowURL:  addRowURL(len(rows)),
			CancelURL:  "/ui/secrets/" + uiEscapePath(prefix) + "/",
			FormError:  msg,
		}
		s.uiRenderPageStatus(w, "secret_edit", data, status)
	}

	if parseErr != nil {
		renderErr(http.StatusBadRequest, parseErr.Error())
		return
	}
	if name == "" {
		renderErr(http.StatusUnprocessableEntity, "a name is required")
		return
	}
	if err := checkEditorPath(joinSecretPath(prefix, name)); err != nil {
		// The joined path, not just the name: `prefix` rides a hidden input,
		// which has no sanitization algorithm at all, so it is the half a
		// hand-made request reaches most easily.
		renderErr(http.StatusUnprocessableEntity, err.Error())
		return
	}
	if len(patch.Submitted) == 0 {
		renderErr(http.StatusBadRequest, errNoFields.Error())
		return
	}
	data := make(map[string]any, len(patch.Submitted))
	for k, v := range patch.Submitted {
		data[k] = v
	}
	ctx, cancel := context.WithTimeout(r.Context(), secretEditTimeout)
	defer cancel()

	clean, err := s.writeEditableSecret(ctx, joinSecretPath(prefix, name), data, true)
	if err != nil {
		renderErr(secretEditStatus(err), err.Error())
		return
	}
	http.Redirect(w, r, "/ui/secrets/"+uiEscapePath(clean), http.StatusSeeOther)
}

// handleUISecretSave commits the editor, including a rename when the name
// changed. Only the difference is written — see applyFieldPatch.
func (s *Server) handleUISecretSave(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIWrite(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, secretBodyLimit)
	if err := r.ParseForm(); err != nil {
		writeError(w, "malformed form submission", http.StatusBadRequest)
		return
	}
	path := r.PostFormValue("path")
	prefix := r.PostFormValue("prefix")
	name := strings.TrimSpace(r.PostFormValue("name"))
	patch, parseErr := parseFieldRows(r)

	renderErr := func(status int, msg string) {
		rows := uiRowsFromForm(r)
		data := uiSecretEditData{
			uiPageData: s.uiBase(r.Context(), path, "secrets", path),
			Prefix:     prefix,
			Name:       name,
			Path:       path,
			Rows:       rows,
			Original:   boundedStrings(r.PostForm["original_field"], maxFieldRows),
			AddRowURL:  addRowURL(len(rows)),
			CancelURL:  "/ui/secrets/" + uiEscapePath(path),
			FormError:  msg,
		}
		s.uiRenderPageStatus(w, "secret_edit", data, status)
	}

	if parseErr != nil {
		renderErr(http.StatusBadRequest, parseErr.Error())
		return
	}
	if name == "" {
		renderErr(http.StatusUnprocessableEntity, "a name is required")
		return
	}
	// Both ends: the path being edited (a hidden input, unsanitized) and the
	// target the submission names.
	if err := errors.Join(checkEditorPath(path), checkEditorPath(joinSecretPath(prefix, name))); err != nil {
		renderErr(http.StatusUnprocessableEntity, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), secretEditTimeout)
	defer cancel()

	// An unchanged name yields the same path, which patchEditableSecret reads
	// as "no rename" — so the rename branch costs nothing in the common case.
	target, _, err := s.patchEditableSecret(ctx, path, joinSecretPath(prefix, name), patch)
	if err != nil {
		if errors.Is(err, errRenameOrphan) {
			// The secret really is at the new path, so that is where the user
			// belongs — re-rendering the old one would hide the move and make
			// a retry hit the rename probe forever. The complaint rides the
			// new path's detail page.
			s.renderUISecretDetailError(w, r, target, http.StatusBadGateway, err.Error())
			return
		}
		renderErr(secretEditStatus(err), err.Error())
		return
	}
	http.Redirect(w, r, "/ui/secrets/"+uiEscapePath(target), http.StatusSeeOther)
}

// uiRowsFromForm rebuilds the row list from a submission, so a re-render
// after an error shows exactly what the user had — including rows they added
// with "Add field" and the ones they left blank.
func uiRowsFromForm(r *http.Request) []uiFieldRow {
	names := r.PostForm["field_name"]
	values := r.PostForm["field_value"]
	// Bounded, because the one error that *guarantees* this runs is "too
	// many fields": re-rendering every row of an oversized body would turn
	// the refusal into the amplification it exists to prevent.
	if len(names) > maxFieldRows {
		names = names[:maxFieldRows]
	}
	rows := make([]uiFieldRow, 0, len(names)+1)
	for i, name := range names {
		row := uiFieldRow{Index: i, Name: name, Rows: 1}
		if i < len(values) {
			row.Value = normalizeFormNewlines(values[i])
			row.Rows = valueRows(row.Value)
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		rows = uiFieldRows(nil, blankCreateRows)
	}
	return rows
}

// boundedStrings caps a slice echoed back into a re-rendered form, for the
// same reason uiRowsFromForm bounds its rows.
func boundedStrings(in []string, max int) []string {
	if len(in) > max {
		return in[:max]
	}
	return in
}

// joinSecretPath composes the implicit prefix and the user-typed name. The
// prefix is never empty in practice (the key-space root is not editable), but
// the guard keeps the result free of a leading slash regardless.
func joinSecretPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "/" + name
}

// handleUISecretDelete removes a secret and all of its versions. The form
// carries a "confirm" field the user types the secret's name into —
// DeleteKVv2 is a metadata delete with no undelete, so the gesture is made
// deliberate rather than one mis-click.
func (s *Server) handleUISecretDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIWrite(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, secretBodyLimit)
	rel := uiFormValue(r, "path")
	confirm := uiFormValue(r, "confirm")

	clean, err := s.editPolicy().Allow(rel)
	if err != nil {
		writeError(w, err.Error(), secretEditStatus(err))
		return
	}
	if _, leaf := uiEditorPrefix(clean); confirm != leaf {
		// Re-render the detail page carrying the complaint rather than a bare
		// error, so the user is still standing in front of the secret.
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
	// The secret is gone, so its own URL would 404; land the user on the
	// parent folder, which is where the next thing they want is.
	target := "/ui/secrets/"
	if prefix, _ := uiEditorPrefix(clean); prefix != "" {
		target += uiEscapePath(prefix) + "/"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
