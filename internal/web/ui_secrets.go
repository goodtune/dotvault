package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/kvpath"
	"github.com/goodtune/dotvault/internal/vault"
)

// validateUISecretPath applies the same defence-in-depth rules as
// handleSecrets: relative to the user prefix, no absolute paths, no ".."
// segments.
func validateUISecretPath(p string) bool {
	if strings.HasPrefix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// handleUISecretsIndex renders /ui/secrets/ — the dashboard content with the
// Secrets accordion section expanded.
func (s *Server) handleUISecretsIndex(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIPage(w, r) {
		return
	}
	data := struct{ uiPageData }{s.uiBase(r.Context(), "Secrets", "secrets", "")}
	s.uiRenderPage(w, "dashboard", data)
}

// handleUISecret renders /ui/secrets/<key> (secret detail) or
// /ui/secrets/<folder>/ (folder listing). The URL shape declares the
// intent, and the first Vault operation follows it: a trailing slash means
// LIST first — issuing a blind GET on a folder path is a 40x under real
// Vault policies (a KVv2 data read and a metadata list are different
// capabilities), and the previous read-first order surfaced that as an
// error banner before the folder listing was ever attempted. Each shape
// still falls back to the other interpretation afterwards, so both
// spellings of either kind stay bookmarkable.
func (s *Server) handleUISecret(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIPage(w, r) {
		return
	}
	rawPath := r.PathValue("path")
	if !validateUISecretPath(rawPath) {
		writeError(w, "invalid secret path", http.StatusBadRequest)
		return
	}
	trimmed := strings.TrimSuffix(rawPath, "/")
	isFolderURL := strings.HasSuffix(rawPath, "/")
	if trimmed == "" {
		http.Redirect(w, r, "/ui/secrets/", http.StatusSeeOther)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// allowEmpty says whether an empty listing still means "this is a folder".
	// It is true only for a URL that *says* folder (a trailing slash) inside
	// an editable subtree: that is the normal state of a configured root
	// nobody has written to yet, and it is where the user needs the "New
	// secret" control. For a slash-less URL an empty listing means the
	// opposite — no folder here — and must fall through, or every
	// not-yet-existing secret would render as an empty folder instead of as
	// itself.
	canCreate := s.editPolicy().AllowsWithin(trimmed)
	list := func(allowEmpty bool) bool {
		children, err := s.listSecretKeys(ctx, trimmed)
		if err != nil {
			// Fall through to the read, but leave a trace: a transient LIST
			// failure here would otherwise be masked by whatever the read
			// then reports as the cause.
			slog.Warn("ui: list secrets failed", "path", trimmed, "error", err)
			return false
		}
		if len(children) == 0 && !allowEmpty {
			return false
		}
		s.renderUISecretFolder(w, ctx, trimmed, children)
		return true
	}

	if isFolderURL && list(canCreate) {
		return
	}

	secret, err := s.vault.ReadKVv2(ctx, s.kvMount, s.userKVPrefix()+trimmed)
	if err == nil && secret != nil {
		s.renderUISecretDetail(w, ctx, trimmed, secret.Version, secret.Data)
		return
	}
	// A slash-less URL naming a folder still resolves (the fallback in the
	// other direction).
	if !isFolderURL && list(false) {
		return
	}

	// Nothing here, but the path is one the user may write: that is not a
	// missing page, it is a secret that does not exist yet. Rendering it as
	// an empty secret at version 0 is what makes "create" and "edit" one
	// surface — the URL is the whole state, and the first field written at
	// version 0 is a check-and-set create.
	if err == nil && !isFolderURL && s.editPolicy().Allows(trimmed) {
		s.renderUISecretDetail(w, ctx, trimmed, 0, nil)
		return
	}

	data := struct{ uiPageData }{s.uiBase(ctx, trimmed, "secrets", rawPath)}
	if err != nil {
		slog.Error("ui: read secret failed", "path", trimmed, "error", err)
		data.Error = "failed to read secret"
	} else {
		data.Error = "secret not found"
	}
	s.uiRenderPage(w, "dashboard", data)
}

// uiSecretDetailData is the /ui/secrets/<key> view model. The editing fields
// are all derived from one kvpath.EditPolicy call, so the controls a screen
// offers and the refusals the handlers behind them issue cannot disagree.
type uiSecretDetailData struct {
	uiPageData
	Path           string
	VaultSecretURL string
	SecretVersion  int
	Fields         []uiFieldRow
	// New marks a path inside an editable subtree that holds no secret yet.
	// It is not a different page: the URL is the whole state, so a secret
	// that does not exist renders as one with no fields and an open row to
	// add the first. That is what makes "create" and "edit" one surface
	// rather than two that drift.
	New bool
	// AddRow is the blank row for adding a field.
	AddRow uiFieldRow
	// Editable enables the Edit and Delete controls.
	Editable bool
	// Managed marks a secret that sits inside an editable subtree but is an
	// enrolment's target. Saying so beats silently omitting the controls: the
	// user would otherwise see editing work on the secret beside this one and
	// have no way to learn why it does not work here.
	Managed bool
	// EditBlocked, when set, is why the Edit control is withheld on a secret
	// the policy *does* permit writing: its name or one of its field names is
	// a shape the form cannot round-trip. Delete is still offered, since it
	// needs no name rendered back.
	//
	// It exists because kvpath.EditPolicy.Allows is documented as the reason a
	// screen can never offer an edit the request would refuse — and the
	// editor's own refusal is a second gate the policy knows nothing about.
	// Rendering the button anyway would have made that promise false.
	EditBlocked string
	// Leaf is the final path segment, which the delete form asks the user to
	// type back. DeleteKVv2 removes every version with no undelete, so the
	// gesture is deliberately more than one click.
	Leaf      string
	FormError string
}

// uiSecretDetail builds the detail view model for a secret. It is the one
// place the view's editing state is derived, so the detail page and the
// re-render after a refused delete cannot disagree about whether a secret is
// editable.
func (s *Server) uiSecretDetail(ctx context.Context, path string, version int, fields map[string]any) uiSecretDetailData {
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)
	editable, managed := s.secretEditability(path)
	blocked := ""
	if editable {
		if err := errors.Join(checkEditorPath(path), checkEditorFields(fields)); err != nil {
			blocked = err.Error()
		}
	}
	// The pencil rides the row, so the gate has to as well: a row-level flag
	// is what stops a read-only page — every page under the default empty
	// web.editable_paths — from offering an edit its own handler would 403.
	// EditBlocked withholds it for the whole secret, since a name the form
	// cannot round-trip is a property of the document, not of one row.
	rowsEditable := editable && blocked == ""
	rows := make([]uiFieldRow, 0, len(names))
	for i, name := range names {
		row := uiSecretFieldRefs(path, name, i, version)
		row.Editable = rowsEditable
		rows = append(rows, row)
	}
	return uiSecretDetailData{
		uiPageData:     s.uiBase(ctx, path, "secrets", path),
		Path:           path,
		VaultSecretURL: s.uiVaultSecretURL(path),
		SecretVersion:  version,
		Fields:         rows,
		Leaf:           path[strings.LastIndex(path, "/")+1:],
		Editable:       editable,
		Managed:        managed,
		EditBlocked:    blocked,
		New:            version == 0,
		AddRow:         uiFieldRow{Path: path, ID: len(rows), Version: version, Rows: 1, New: true},
	}
}

func (s *Server) renderUISecretDetail(w http.ResponseWriter, ctx context.Context, path string, version int, fields map[string]any) {
	s.uiRenderPage(w, "secret", s.uiSecretDetail(ctx, path, version, fields))
}

// renderUISecretDetailError re-renders the detail page carrying a complaint,
// used when a delete is refused (a mistyped confirmation, a Vault failure).
// Re-reading the secret rather than threading state through a redirect keeps
// the user in front of the thing they were acting on, with its live version
// number. The status is the caller's, not a fixed 409: a Vault failure and a
// mistyped confirmation are not the same answer.
func (s *Server) renderUISecretDetailError(w http.ResponseWriter, r *http.Request, path string, status int, msg string) {
	// Validate here rather than trusting the caller. This is the one render
	// that takes a path straight off a form body, and it is reached from
	// error branches that fire *before* the policy check — so an unvalidated
	// path walked out of the user's own prefix and had that secret's version
	// and field names rendered back under the refusal. The read path applies
	// the same rule (validateUISecretPath) before it ever reaches Vault.
	clean, err := kvpath.Clean(path)
	if err != nil || clean == "" {
		writeError(w, msg, status)
		return
	}
	path = clean

	ctx, cancel := context.WithTimeout(r.Context(), secretEditTimeout)
	defer cancel()

	secret, err := s.vault.ReadKVv2(ctx, s.kvMount, s.userKVPrefix()+path)
	switch {
	case err == nil && secret != nil:
		// Normal case: re-render the secret as it now stands.
	case err == nil && s.editPolicy().Allows(path):
		// Nothing there yet. That is not "no page to return to" — it is a
		// secret being created, and its page is where the complaint belongs.
		// Falling through to a bare JSON error here put a raw error body on
		// an HTML surface and dropped whatever the user had typed.
		secret = &vault.Secret{}
	default:
		// Genuinely unreadable, so there is no page to return to; report the
		// original complaint rather than masking it with a read failure.
		writeError(w, msg, status)
		return
	}
	data := s.uiSecretDetail(ctx, path, secret.Version, secret.Data)
	data.FormError = msg
	s.uiRenderPageStatus(w, "secret", data, status)
}

func (s *Server) renderUISecretFolder(w http.ResponseWriter, ctx context.Context, folder string, children []string) {
	entries := make([]uiNavItem, 0, len(children))
	for _, child := range children {
		if strings.HasSuffix(child, "/") {
			continue
		}
		entries = append(entries, uiNavItem{
			Name: child,
			Icon: "🔑",
			Href: "/ui/secrets/" + uiEscapePath(folder+"/"+child),
		})
	}
	data := struct {
		uiPageData
		Folder  string
		Entries []uiNavItem
		// CanCreate offers "New secret" pre-filled with this folder, which
		// is a weaker question than whether the folder's own path is
		// editable — a configured root is not itself an editable secret, but
		// secrets may certainly be created inside it.
		CanCreate bool
	}{
		uiPageData: s.uiBase(ctx, folder, "secrets", folder+"/"),
		Folder:     folder,
		Entries:    entries,
		CanCreate:  s.editPolicy().AllowsWithin(folder),
	}
	s.uiRenderPage(w, "folder", data)
}

// uiSecretField reads one field of the user's secret and returns it raw, so
// the caller decides how to render it.
func (s *Server) uiSecretField(ctx context.Context, path, field string) (any, bool, error) {
	secret, err := s.vault.ReadKVv2(ctx, s.kvMount, s.userKVPrefix()+path)
	if err != nil || secret == nil {
		return nil, false, err
	}
	v, ok := secret.Data[field]
	if !ok {
		return nil, false, nil
	}
	return v, true, nil
}

// uiSecretFieldValue reads one field and renders it for a screen. It routes
// through displayFieldValue rather than pretty-printing composites of its
// own, so this page, the edit box, and the FUSE mount all show one value.
// Two renderings is not a cosmetic difference here: the editor's
// unchanged-check compares a submission against displayFieldValue, so a
// second, prettier rendering would make an untouched composite look edited
// and rewrite it as a string.
func (s *Server) uiSecretFieldValue(ctx context.Context, path, field string) (string, bool, error) {
	v, found, err := s.uiSecretField(ctx, path, field)
	if err != nil || !found {
		return "", found, err
	}
	return displayFieldValue(v), true, nil
}

// handleUISecretReveal patches the field's value cell with the revealed
// value plus an "open eye" button. The revealed cell re-masks itself after
// 30 seconds (a delayed @get of the mask fragment), so a revealed secret
// does not sit on screen indefinitely.
func (s *Server) handleUISecretReveal(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIRead(w) {
		return
	}
	row, ok := uiSecretRowParams(r)
	if !ok {
		writeError(w, "invalid reveal request", http.StatusBadRequest)
		return
	}
	path, field := row.Path, row.Name
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	value, found, err := s.uiSecretFieldValue(ctx, path, field)
	if err != nil {
		slog.Error("ui: reveal read failed", "path", path, "error", err)
		writeError(w, "failed to read secret", http.StatusInternalServerError)
		return
	}
	if !found {
		writeError(w, "field not found", http.StatusNotFound)
		return
	}
	slog.Info("secret revealed via web UI", "path", path)
	row.Value = value
	cell, err1 := uiFragment("revealed-cell", row)
	eye, err2 := uiFragment("eye-btn-open", row)
	if err1 != nil || err2 != nil {
		writeError(w, "failed to render fragment", http.StatusInternalServerError)
		return
	}
	uiPatchElements(w, r, cell+eye)
}

// handleUISecretMask restores the masked cell and closed-eye button. No
// Vault read — it only needs the identifiers to rebuild the fragment.
func (s *Server) handleUISecretMask(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIRead(w) {
		return
	}
	row, ok := uiSecretRowParams(r)
	if !ok {
		writeError(w, "invalid mask request", http.StatusBadRequest)
		return
	}
	cell, err1 := uiFragment("masked-cell", row)
	eye, err2 := uiFragment("eye-btn", row)
	if err1 != nil || err2 != nil {
		writeError(w, "failed to render fragment", http.StatusInternalServerError)
		return
	}
	uiPatchElements(w, r, cell+eye)
}

// handleUISecretCopy puts a secret field's value on this machine's clipboard
// server-side — the value never travels to the browser, which is both more
// reliable than navigator.clipboard and keeps the secret out of the page.
func (s *Server) handleUISecretCopy(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIWrite(w, r) {
		return
	}
	if s.setClipboard == nil {
		writeError(w, "clipboard not available", http.StatusServiceUnavailable)
		return
	}
	row, ok := uiSecretRowParams(r)
	if !ok {
		writeError(w, "invalid copy request", http.StatusBadRequest)
		return
	}
	path, field := row.Path, row.Name
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	value, found, err := s.uiSecretFieldValue(ctx, path, field)
	if err != nil {
		slog.Error("ui: copy read failed", "path", path, "error", err)
		writeError(w, "failed to read secret", http.StatusInternalServerError)
		return
	}
	if !found {
		writeError(w, "field not found", http.StatusNotFound)
		return
	}
	if err := s.uiCopyToClipboard(value); err != nil {
		writeError(w, err.Error(), http.StatusBadGateway)
		return
	}
	slog.Info("secret field copied to clipboard via web UI", "path", path)
	uiPatchFragment(w, r, "copy-btn-done", row)
}

func (s *Server) handleUISecretCopyBtn(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIRead(w) {
		return
	}
	row, ok := uiSecretRowParams(r)
	if !ok {
		writeError(w, "invalid request", http.StatusBadRequest)
		return
	}
	uiPatchFragment(w, r, "copy-btn", row)
}
