package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// uiSecretField is one row of the secret detail table plus the fragment URLs
// its datastar actions target. Value is populated only when rendering the
// revealed cell; the page itself never carries secret values.
//
// The URL fields are interpolated inside data-on:* attribute values, which
// html/template escapes as JavaScript strings (\/ and \u0026 escapes).
// That context detection is correct — datastar evaluates the attribute as a
// real JS expression, so the escapes decode back to the intended URL.
type uiSecretField struct {
	Name       string
	ID         int
	Value      string
	RevealURL  string
	MaskURL    string
	CopyURL    string
	CopyBtnURL string
}

func uiSecretFieldRefs(path, field string, id int) uiSecretField {
	q := url.Values{
		"path":  {path},
		"field": {field},
		"id":    {strconv.Itoa(id)},
	}.Encode()
	return uiSecretField{
		Name:       field,
		ID:         id,
		RevealURL:  "/ui/fragments/secrets/reveal?" + q,
		MaskURL:    "/ui/fragments/secrets/mask?" + q,
		CopyURL:    "/ui/actions/copy-field?" + q,
		CopyBtnURL: "/ui/fragments/secrets/copy-btn?" + q,
	}
}

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

	list := func() bool {
		children, err := s.vault.ListKVv2(ctx, s.kvMount, s.userKVPrefix()+trimmed+"/")
		if err != nil {
			// Fall through to the read, but leave a trace: a transient LIST
			// failure here would otherwise be masked by whatever the read
			// then reports as the cause.
			slog.Warn("ui: list secrets failed", "path", trimmed, "error", err)
			return false
		}
		if len(children) == 0 {
			return false
		}
		s.renderUISecretFolder(w, ctx, trimmed, children)
		return true
	}

	if isFolderURL && list() {
		return
	}

	secret, err := s.vault.ReadKVv2(ctx, s.kvMount, s.userKVPrefix()+trimmed)
	if err == nil && secret != nil {
		s.renderUISecretDetail(w, ctx, trimmed, secret.Version, secret.Data)
		return
	}
	// A slash-less URL naming a folder still resolves (the fallback in the
	// other direction).
	if !isFolderURL && list() {
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
	Fields         []uiSecretField
	// Editable enables the Edit and Delete controls.
	Editable bool
	// Managed marks a secret that sits inside an editable subtree but is an
	// enrolment's target. Saying so beats silently omitting the controls: the
	// user would otherwise see editing work on the secret beside this one and
	// have no way to learn why it does not work here.
	Managed bool
	// Leaf is the final path segment, which the delete form asks the user to
	// type back. DeleteKVv2 removes every version with no undelete, so the
	// gesture is deliberately more than one click.
	Leaf      string
	EditURL   string
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
	rows := make([]uiSecretField, 0, len(names))
	for i, name := range names {
		rows = append(rows, uiSecretFieldRefs(path, name, i))
	}
	editable, managed := s.secretEditability(path)
	return uiSecretDetailData{
		uiPageData:     s.uiBase(ctx, path, "secrets", path),
		Path:           path,
		VaultSecretURL: s.uiVaultSecretURL(path),
		SecretVersion:  version,
		Fields:         rows,
		Leaf:           path[strings.LastIndex(path, "/")+1:],
		EditURL:        "/ui/secret-editor/edit?" + url.Values{"path": {path}}.Encode(),
		Editable:       editable,
		Managed:        managed,
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
	ctx, cancel := context.WithTimeout(r.Context(), secretEditTimeout)
	defer cancel()

	secret, err := s.vault.ReadKVv2(ctx, s.kvMount, s.userKVPrefix()+path)
	if err != nil || secret == nil {
		// The secret is unreadable now, so there is no detail page to return
		// to; report the original complaint plainly rather than masking it
		// with a read failure.
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
		NewURL    string
	}{
		uiPageData: s.uiBase(ctx, folder, "secrets", folder+"/"),
		Folder:     folder,
		Entries:    entries,
		CanCreate:  s.editPolicy().AllowsWithin(folder),
		NewURL:     "/ui/secret-editor/new?" + url.Values{"path": {folder}}.Encode(),
	}
	s.uiRenderPage(w, "folder", data)
}

// uiSecretFieldValue reads one field of the user's secret and returns its
// display form: strings verbatim, everything else pretty-printed JSON.
func (s *Server) uiSecretFieldValue(ctx context.Context, path, field string) (string, bool, error) {
	secret, err := s.vault.ReadKVv2(ctx, s.kvMount, s.userKVPrefix()+path)
	if err != nil || secret == nil {
		return "", false, err
	}
	v, ok := secret.Data[field]
	if !ok {
		return "", false, nil
	}
	if str, isStr := v.(string); isStr {
		return str, true, nil
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprint(v), true, nil
	}
	return string(b), true, nil
}

// uiSecretFragmentParams extracts and validates the path/field/id query
// parameters shared by the reveal/mask/copy fragment endpoints.
func uiSecretFragmentParams(r *http.Request) (path, field string, id int, ok bool) {
	q := r.URL.Query()
	path, field = q.Get("path"), q.Get("field")
	id, err := strconv.Atoi(q.Get("id"))
	if path == "" || field == "" || err != nil || id < 0 || !validateUISecretPath(path) || strings.HasSuffix(path, "/") {
		return "", "", 0, false
	}
	return path, field, id, true
}

// handleUISecretReveal patches the field's value cell with the revealed
// value plus an "open eye" button. The revealed cell re-masks itself after
// 30 seconds (a delayed @get of the mask fragment), so a revealed secret
// does not sit on screen indefinitely.
func (s *Server) handleUISecretReveal(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIRead(w) {
		return
	}
	path, field, id, ok := uiSecretFragmentParams(r)
	if !ok {
		writeError(w, "invalid reveal request", http.StatusBadRequest)
		return
	}
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
	f := uiSecretFieldRefs(path, field, id)
	f.Value = value
	cell, err1 := uiFragment("revealed-cell", f)
	eye, err2 := uiFragment("eye-btn-open", f)
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
	path, field, id, ok := uiSecretFragmentParams(r)
	if !ok {
		writeError(w, "invalid mask request", http.StatusBadRequest)
		return
	}
	f := uiSecretFieldRefs(path, field, id)
	cell, err1 := uiFragment("masked-cell", f)
	eye, err2 := uiFragment("eye-btn", f)
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
	path, field, id, ok := uiSecretFragmentParams(r)
	if !ok {
		writeError(w, "invalid copy request", http.StatusBadRequest)
		return
	}
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
	uiPatchFragment(w, r, "copy-btn-done", uiSecretFieldRefs(path, field, id))
}

func (s *Server) handleUISecretCopyBtn(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIRead(w) {
		return
	}
	path, field, id, ok := uiSecretFragmentParams(r)
	if !ok {
		writeError(w, "invalid request", http.StatusBadRequest)
		return
	}
	uiPatchFragment(w, r, "copy-btn", uiSecretFieldRefs(path, field, id))
}
