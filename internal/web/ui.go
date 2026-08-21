// The main site, served under /ui/ with real, bookmarkable URLs. Every page
// is rendered from Go html/template; interactivity (live "last updated",
// secret reveal/copy, the enrolment progress poll, managed-forward state)
// comes from datastar (https://data-star.dev) patching server-rendered
// fragments over SSE.
//
// The chrome-less surfaces that sit in front of it — the login view and the
// first-run enrolment wizard — live in ui_login.go and ui_setup.go and share
// this file's template machinery through the "standalone" shell.
//
// Request posture:
//   - Page GETs require the daemon to be authenticated; an unauthenticated
//     browser is redirected to the login view at /.
//   - Fragment GETs return 401 JSON when unauthenticated (a datastar patch
//     request has no use for a redirect).
//   - Mutating POSTs require a same-origin Origin header (requireUIWrite).
//     Browsers attach Origin to every POST — fetch and form submits alike —
//     so requiring it and matching it against the daemon's own origin is a
//     robust CSRF control for a browser-only surface, equivalent in effect
//     to an issue-then-spend CSRF token but compatible with
//     server-rendered forms and multiple tabs. (The peer-action endpoints
//     accept an *absent* Origin because curl is their consumer; these
//     endpoints have no non-browser consumer, so absence is rejected.)
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	datastar "github.com/starfederation/datastar-go/datastar"
)

//go:embed uitmpl/*.tmpl
var uiTmplFS embed.FS

// uiAssetsFS embeds the /ui/ static assets. datastar.js is the vendored
// Datastar v1.0.2 browser bundle, fetched from
// https://cdn.jsdelivr.net/gh/starfederation/datastar@v1.0.2/bundles/datastar.js
// — to re-vendor, download the new tag's bundle to uiassets/datastar.js and
// re-verify the /ui/ pages. The Go SDK (github.com/starfederation/datastar-go,
// in go.mod and covered by dependabot's gomod entry) versions independently
// of the browser bundle; both speak the Datastar v1 SSE protocol.
//
//go:embed uiassets/*
var uiAssetsFS embed.FS

var uiFuncs = template.FuncMap{
	"orDash": func(s string) string {
		if s == "" {
			return "—"
		}
		return s
	},
	"yesNo": func(b bool) string {
		if b {
			return "Yes"
		}
		return "No"
	},
	"join": strings.Join,
	"enrolStatusTag": func(status string) string {
		switch status {
		case "complete":
			return "config-tag-ok"
		case "failed":
			return "config-tag-err"
		case "running":
			return "config-tag-info"
		case "skipped":
			return "config-tag-muted"
		default:
			return ""
		}
	},
	"settingRows": uiSettingRows,
}

// uiSharedTmpl is every template file that defines shared blocks (the layout
// skeleton, the nav, the datastar-patched fragments). Each page set is these
// plus one page file contributing its "content" block.
var uiSharedTmpl = []string{
	"uitmpl/layout.tmpl",
	"uitmpl/standalone.tmpl",
	"uitmpl/nav.tmpl",
	"uitmpl/fragments.tmpl",
	"uitmpl/enrol_card.tmpl",
}

// uiPages maps a page name to its parsed template set; uiFragments serves the
// standalone fragments datastar patches into a page (buttons, table cells,
// the enrolment card). Both are parsed by uiInitTemplates, called from
// registerSSRUIRoutes — deliberately NOT at package init with template.Must,
// which would panic every binary importing internal/web (the CLI included)
// for a defect in a surface that only exists on a web-enabled daemon.
// A parse failure disables the browser surface and is logged rather than
// taking the daemon down with it.
var (
	uiPages     map[string]*template.Template
	uiFragments *template.Template
	uiTmplOnce  sync.Once
	uiTmplErr   error
)

func uiInitTemplates() error {
	uiTmplOnce.Do(func() {
		frags, err := template.New("fragments").Funcs(uiFuncs).ParseFS(uiTmplFS, uiSharedTmpl...)
		if err != nil {
			uiTmplErr = err
			return
		}
		names := []string{
			"dashboard", "secret", "folder", "enrolments",
			"enrol_detail", "remotes", "remote_detail", "config",
			// Chrome-less pages: they render through "standalone" rather
			// than "layout" (see uiRenderStandalone).
			"login", "login_ldap", "setup",
		}
		pages := make(map[string]*template.Template, len(names))
		for _, name := range names {
			files := append(append([]string(nil), uiSharedTmpl...), "uitmpl/"+name+".tmpl")
			t, err := template.New(name).Funcs(uiFuncs).ParseFS(uiTmplFS, files...)
			if err != nil {
				uiTmplErr = err
				return
			}
			pages[name] = t
		}
		uiFragments = frags
		uiPages = pages
	})
	return uiTmplErr
}

// uiNavItem is one row in the sidebar accordion — a leaf link or an
// expandable folder.
type uiNavItem struct {
	Name        string
	Href        string
	Icon        string
	Dot         string // "" or green/orange/red/grey
	DotTitle    string
	Selected    bool
	Folder      bool
	Expanded    bool
	Children    []uiNavItem
	Note        string
	NoteIsError bool
}

// uiNavSection is one accordion section (Enrolments / Remotes / Secrets).
type uiNavSection struct {
	Label    string
	Href     string
	Active   bool
	Expanded bool
	// ItemsID, when set, becomes the id of the section's <ul> so an SSE
	// stream can re-patch the whole item list (the Remotes section uses
	// "ui-nav-remotes").
	ItemsID     string
	Items       []uiNavItem
	Note        string
	NoteIsError bool
}

// uiPageData is the base view model every page embeds; the layout and nav
// templates render from it.
type uiPageData struct {
	Title          string
	Version        string
	Authenticated  bool
	VaultURL       string
	Updated        string
	Error          string
	Sections       []uiNavSection
	SecretViewText template.HTML
	// OAuthRules lists the sync rules whose OAuth authorisation the user
	// still has to grant; the layout renders one banner each.
	OAuthRules []uiOAuthRule
	// SSHStream, when non-empty, is the /ui/sse/ssh subscription URL the
	// layout opens for this page, so managed-forward state (nav dots, the
	// remotes table, a remote's detail state line) live-updates — including
	// changes made asynchronously by the CLI or the reconnect loop. Set only
	// on pages that render that state.
	SSHStream string
}

// uiOAuthRule is one dashboard OAuth banner: a rule that declares an OAuth
// provider, linked to the authorisation flow that grants it.
type uiOAuthRule struct {
	Label    string
	StartURL string
}

// uiOAuthRules builds the banner rows from the configured rules.
func (s *Server) uiOAuthRules() []uiOAuthRule {
	var out []uiOAuthRule
	for _, rule := range s.getRules() {
		if rule.OAuth == nil {
			continue
		}
		label := rule.OAuth.Provider
		if label == "" {
			label = rule.Name
		}
		out = append(out, uiOAuthRule{
			Label:    label,
			StartURL: "/api/v1/oauth/" + url.PathEscape(rule.Name) + "/start",
		})
	}
	return out
}

// registerSSRUIRoutes wires the main site under /ui/. Called from
// registerUIRoutes, so it exists only when the loopback TCP listener does.
func (s *Server) registerSSRUIRoutes() {
	if err := uiInitTemplates(); err != nil {
		slog.Error("failed to parse ui templates; /ui/ routes disabled", "error", err)
		return
	}
	assets, err := fs.Sub(uiAssetsFS, "uiassets")
	if err != nil {
		slog.Error("failed to create sub-filesystem for ui assets", "error", err)
		return
	}
	// http.FileServer derives Content-Type from mime.TypeByExtension, which
	// on Windows consults the registry — where installers routinely rewrite
	// .js to text/plain, and the global nosniff header would then make the
	// browser refuse the one script /ui/ depends on. Pin the two extensions
	// the embedded assets use so the platform's MIME table can't break them.
	mime.AddExtensionType(".js", "text/javascript; charset=utf-8")
	mime.AddExtensionType(".css", "text/css; charset=utf-8")
	s.mux.Handle("GET /ui/assets/", http.StripPrefix("/ui/assets/", http.FileServer(http.FS(assets))))

	// Pages.
	s.mux.HandleFunc("GET /ui/{$}", s.handleUIDashboard)
	s.mux.HandleFunc("GET /ui/secrets/{$}", s.handleUISecretsIndex)
	s.mux.HandleFunc("GET /ui/secrets/{path...}", s.handleUISecret)
	s.mux.HandleFunc("GET /ui/enrolments/{$}", s.handleUIEnrolmentsIndex)
	s.mux.HandleFunc("GET /ui/enrolments/{engine}/{key...}", s.handleUIEnrolDetail)
	s.mux.HandleFunc("GET /ui/remotes/{$}", s.handleUIRemotesIndex)
	s.mux.HandleFunc("GET /ui/remotes/{host}", s.handleUIRemoteDetail)
	s.mux.HandleFunc("GET /ui/remotes/{host}/{$}", s.handleUIRemoteDetail)
	s.mux.HandleFunc("GET /ui/config/{$}", s.handleUIConfig)

	// Live updates + datastar-patched fragments.
	s.mux.HandleFunc("GET /ui/sse", s.handleUISSE)
	s.mux.HandleFunc("GET /ui/sse/ssh", s.handleUISSHSSE)
	s.mux.HandleFunc("GET /ui/fragments/sync-btn", s.handleUISyncBtnFragment)
	s.mux.HandleFunc("GET /ui/fragments/copy-token-btn", s.handleUICopyTokenBtnFragment)
	s.mux.HandleFunc("GET /ui/fragments/secrets/reveal", s.handleUISecretReveal)
	s.mux.HandleFunc("GET /ui/fragments/secrets/mask", s.handleUISecretMask)
	s.mux.HandleFunc("GET /ui/fragments/secrets/copy-btn", s.handleUISecretCopyBtn)
	s.mux.HandleFunc("GET /ui/fragments/enrol-card", s.handleUIEnrolCardFragment)

	// Mutations (same-origin POSTs; see requireUIWrite).
	s.mux.HandleFunc("POST /ui/actions/sync", s.handleUIActionSync)
	s.mux.HandleFunc("POST /ui/actions/copy-token", s.handleUIActionCopyToken)
	s.mux.HandleFunc("POST /ui/actions/copy-field", s.handleUISecretCopy)
	s.mux.HandleFunc("POST /ui/enrol/start", s.handleUIEnrolStart)
	s.mux.HandleFunc("POST /ui/enrol/skip", s.handleUIEnrolSkip)
	s.mux.HandleFunc("POST /ui/enrol/reset", s.handleUIEnrolReset)
	s.mux.HandleFunc("POST /ui/enrol/secret", s.handleUIEnrolSecret)
	s.mux.HandleFunc("POST /ui/remotes/add", s.handleUIRemoteAdd)
	s.mux.HandleFunc("POST /ui/remotes/{host}/save", s.handleUIRemoteSave)
	s.mux.HandleFunc("POST /ui/remotes/{host}/delete", s.handleUIRemoteDelete)
}

func (s *Server) uiAuthenticated() bool {
	return s.vault != nil && s.vault.Token() != ""
}

// requireUIPage gates a page GET: an unauthenticated browser is sent to the
// root, which owns every login flow (OIDC redirects, LDAP MFA, token entry,
// the mtls bootstrap) — see ui_login.go.
func (s *Server) requireUIPage(w http.ResponseWriter, r *http.Request) bool {
	if !s.uiAuthenticated() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return false
	}
	return true
}

// requireUIRead gates a fragment GET (a datastar patch request — a redirect
// would be patched into the DOM, so answer 401 instead).
func (s *Server) requireUIRead(w http.ResponseWriter) bool {
	if !s.uiAuthenticated() {
		writeError(w, "not authenticated", http.StatusUnauthorized)
		return false
	}
	return true
}

// requireUIWrite gates every /ui/ mutation. Browsers attach an Origin header
// to all POSTs (fetch and form submits alike), so requiring one that names
// this daemon's own origin rejects any cross-site request — the CSRF control
// for this surface. Absence is rejected too, unlike the peer-action
// endpoints: those exist for curl over a forwarded socket, while these have
// no non-browser consumer.
func (s *Server) requireUIWrite(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || !s.originAllowed(origin) {
		writeError(w, "cross-site requests are not allowed", http.StatusForbidden)
		return false
	}
	return s.requireUIRead(w)
}

// uiRenderPage executes a page inside the main site's chrome (header, nav).
func (s *Server) uiRenderPage(w http.ResponseWriter, page string, data any) {
	s.uiRender(w, page, "layout", data)
}

// uiRenderStandalone executes a page inside the chrome-less shell used by the
// login view and the first-run wizard — the surfaces that exist before there
// is a dashboard to frame them.
func (s *Server) uiRenderStandalone(w http.ResponseWriter, page string, data any) {
	s.uiRender(w, page, "standalone", data)
}

// uiRender executes a page template set through the named shell. Render
// errors after the first byte cannot become a clean 500, so the page is
// rendered to a buffer first.
func (s *Server) uiRender(w http.ResponseWriter, page, shell string, data any) {
	tmpl, ok := uiPages[page]
	if !ok {
		writeError(w, "unknown page", http.StatusInternalServerError)
		return
	}
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, shell, data); err != nil {
		slog.Error("render ui page failed", "page", page, "error", err)
		writeError(w, "failed to render page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, b.String())
}

// uiFragment renders a named fragment template to a string for
// datastar.PatchElements.
func uiFragment(name string, data any) (string, error) {
	var b strings.Builder
	if err := uiFragments.ExecuteTemplate(&b, name, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

// uiPatchElements sends rendered elements as a datastar patch-elements SSE
// response. A write failure just means the client went away mid-patch, so it
// is logged at debug and not surfaced.
func uiPatchElements(w http.ResponseWriter, r *http.Request, elements string) {
	sse := datastar.NewSSE(w, r)
	if err := sse.PatchElements(elements); err != nil {
		slog.Debug("patch elements failed", "error", err)
	}
}

// uiPatchFragment renders one fragment and sends it as a datastar
// patch-elements SSE response.
func uiPatchFragment(w http.ResponseWriter, r *http.Request, name string, data any) {
	frag, err := uiFragment(name, data)
	if err != nil {
		slog.Error("render ui fragment failed", "fragment", name, "error", err)
		writeError(w, "failed to render fragment", http.StatusInternalServerError)
		return
	}
	uiPatchElements(w, r, frag)
}

// uiBase assembles the shared view model. active names the expanded nav
// section, selected the highlighted entry within it.
func (s *Server) uiBase(ctx context.Context, title, active, selected string) uiPageData {
	return uiPageData{
		Title:          title,
		Version:        s.version,
		Authenticated:  s.uiAuthenticated(),
		VaultURL:       uiSafeVaultURL(s.vaultAddress),
		Updated:        time.Now().Format("15:04:05"),
		Sections:       s.buildUINav(ctx, active, selected),
		OAuthRules:     s.uiOAuthRules(),
		SecretViewText: template.HTML(s.secretViewTextHTML),
	}
}

// uiSafeVaultURL checks before linking to the Vault UI: only
// http(s) addresses become anchors.
func uiSafeVaultURL(addr string) string {
	lower := strings.ToLower(addr)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return addr
	}
	return ""
}

// uiEscapePath percent-encodes each segment of a relative path for use in a
// URL, preserving the slashes between segments.
func uiEscapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	return strings.Join(segs, "/")
}

// uiVaultSecretURL builds a deep
// link into the Vault UI for this user's secret (or folder listing, when
// secretPath ends with a slash).
func (s *Server) uiVaultSecretURL(secretPath string) string {
	base := uiSafeVaultURL(s.vaultAddress)
	if base == "" || s.kvMount == "" || s.username == "" {
		return ""
	}
	base = strings.TrimRight(base, "/")
	action := "show"
	if secretPath == "" || strings.HasSuffix(secretPath, "/") {
		action = "list"
	}
	userPath := uiEscapePath(strings.Trim(s.userPrefix+s.username, "/"))
	fullPath := userPath
	if seg := uiEscapePath(strings.Trim(secretPath, "/")); seg != "" {
		fullPath = userPath + "/" + seg
	}
	return fmt.Sprintf("%s/ui/vault/secrets/%s/%s/%s", base, url.PathEscape(s.kvMount), action, fullPath)
}

// buildUINav assembles the accordion. Sections render collapsed until their
// route is active; the expanded section's contents come from the same
// services the API handlers use. A section whose backing lookup fails renders
// an inline error note rather than failing the page.
func (s *Server) buildUINav(ctx context.Context, active, selected string) []uiNavSection {
	sections := []uiNavSection{
		{Label: "Enrolments", Href: "/ui/enrolments/"},
		{Label: "Remotes", Href: "/ui/remotes/"},
		{Label: "Secrets", Href: "/ui/secrets/"},
	}
	for i := range sections {
		switch sections[i].Label {
		case "Enrolments":
			if active == "enrolments" {
				sections[i].Active, sections[i].Expanded = true, true
				s.fillEnrolNav(&sections[i], selected)
			}
		case "Remotes":
			if active == "remotes" {
				sections[i].Active, sections[i].Expanded = true, true
				// The list carries an id so /ui/sse/ssh can re-patch it as
				// live connection state changes (see nav-remotes-list).
				sections[i].ItemsID = "ui-nav-remotes"
				s.fillRemotesNav(&sections[i], selected)
			}
		case "Secrets":
			if active == "secrets" {
				sections[i].Active, sections[i].Expanded = true, true
				s.fillSecretsNav(ctx, &sections[i], selected)
			}
		}
	}
	return sections
}

// fillSecretsNav lists this user's KV entries, expanding the folder on the
// path to the selected secret (one folder level, matching the enrolment key
// grammar).
func (s *Server) fillSecretsNav(ctx context.Context, sec *uiNavSection, selected string) {
	keys, err := s.vault.ListKVv2(ctx, s.kvMount, s.userKVPrefix())
	if err != nil {
		sec.Note, sec.NoteIsError = "failed to list secrets", true
		slog.Warn("ui: list secrets for nav failed", "error", err)
		return
	}
	if len(keys) == 0 {
		sec.Note = "No secrets found"
		return
	}
	// The folder to expand: an explicit folder selection ("foo/") or the
	// parent of a selected nested secret ("foo/bar").
	expandFolder := ""
	if strings.HasSuffix(selected, "/") {
		expandFolder = strings.TrimSuffix(selected, "/")
	} else if i := strings.IndexByte(selected, '/'); i > 0 {
		expandFolder = selected[:i]
	}
	for _, entry := range keys {
		if strings.HasSuffix(entry, "/") {
			name := strings.TrimSuffix(entry, "/")
			item := uiNavItem{Name: name, Folder: true}
			if name == expandFolder {
				item.Expanded = true
				item.Href = "/ui/secrets/"
				children, err := s.vault.ListKVv2(ctx, s.kvMount, s.userKVPrefix()+entry)
				switch {
				case err != nil:
					item.Note, item.NoteIsError = "failed to list", true
				case len(children) == 0:
					item.Note = "(empty)"
				default:
					for _, child := range children {
						if strings.HasSuffix(child, "/") {
							// Vault can nest deeper, but dotvault's key grammar
							// is at most one level; deeper folders are not
							// navigable here.
							continue
						}
						childPath := name + "/" + child
						item.Children = append(item.Children, uiNavItem{
							Name:     child,
							Icon:     "🔑",
							Href:     "/ui/secrets/" + uiEscapePath(childPath),
							Selected: childPath == selected,
						})
					}
				}
			} else {
				item.Href = "/ui/secrets/" + uiEscapePath(name) + "/"
			}
			sec.Items = append(sec.Items, item)
			continue
		}
		sec.Items = append(sec.Items, uiNavItem{
			Name:     entry,
			Icon:     "🔑",
			Href:     "/ui/secrets/" + uiEscapePath(entry),
			Selected: entry == selected,
		})
	}
}

// uiEnrolDot maps an enrolment status to its quick-glance dot.
func uiEnrolDot(status string) (dot, title string) {
	switch status {
	case "complete":
		return "green", "enrolled successfully"
	case "running":
		return "orange", "in progress"
	case "failed":
		return "red", "an error occurred"
	default: // pending, skipped
		return "grey", "not started"
	}
}

// fillEnrolNav groups enrolments by engine. An engine with a single
// enrolment renders as a leaf; only engines with more than one nest into a
// folder (per the design brief).
func (s *Server) fillEnrolNav(sec *uiNavSection, selected string) {
	runner := s.getEnrolRunner()
	if runner == nil {
		sec.Note = "No enrolments configured"
		return
	}
	states := runner.States()
	if len(states) == 0 {
		sec.Note = "No enrolments configured"
		return
	}
	// Group by engine, preserving the runner's (key-sorted) order.
	var engines []string
	byEngine := map[string][]EnrolStateInfo{}
	for _, st := range states {
		if _, seen := byEngine[st.Engine]; !seen {
			engines = append(engines, st.Engine)
		}
		byEngine[st.Engine] = append(byEngine[st.Engine], st)
	}
	selectedEngine := ""
	if i := strings.IndexByte(selected, '#'); i >= 0 {
		selectedEngine, selected = selected[:i], selected[i+1:]
	}
	leaf := func(st EnrolStateInfo) uiNavItem {
		dot, title := uiEnrolDot(st.Status)
		return uiNavItem{
			Name:     st.Key,
			Icon:     "🎫",
			Href:     "/ui/enrolments/" + url.PathEscape(st.Engine) + "/" + uiEscapePath(st.Key) + "/",
			Dot:      dot,
			DotTitle: title,
			Selected: st.Key == selected && st.Engine == selectedEngine,
		}
	}
	for _, engine := range engines {
		group := byEngine[engine]
		if len(group) == 1 {
			sec.Items = append(sec.Items, leaf(group[0]))
			continue
		}
		item := uiNavItem{Name: engine, Folder: true}
		if engine == selectedEngine {
			item.Expanded = true
			item.Href = "/ui/enrolments/"
			for _, st := range group {
				item.Children = append(item.Children, leaf(st))
			}
		} else {
			item.Href = "/ui/enrolments/" + url.PathEscape(engine) + "/"
		}
		sec.Items = append(sec.Items, item)
	}
}

// uiRemoteDot maps a remote's effective state to its quick-glance dot:
// green = enabled+connected, orange = enabled+connecting, red =
// enabled+disconnected, grey = disabled.
func uiRemoteDot(state string) string {
	switch state {
	case "connected":
		return "green"
	case "connecting", "reconnecting":
		return "orange"
	case "disabled":
		return "grey"
	default: // offline, authentication-error, host-key-error
		return "red"
	}
}

func (s *Server) fillRemotesNav(sec *uiNavSection, selected string) {
	rows, unavailable, err := s.uiRemoteRows()
	switch {
	case unavailable:
		sec.Note = "Managed SSH forwards are not configured"
		return
	case err != nil:
		sec.Note, sec.NoteIsError = "failed to list remotes", true
		return
	case len(rows) == 0:
		sec.Note = "No remotes configured"
		return
	}
	sec.Items = uiRemotesNavItems(rows, selected)
}

// uiRemotesNavItems builds the Remotes nav rows from remote state; shared by
// the page-render nav and the /ui/sse/ssh live patch of the same list.
func uiRemotesNavItems(rows []uiRemoteRow, selected string) []uiNavItem {
	items := make([]uiNavItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, uiNavItem{
			Name:     row.Host,
			Icon:     "🖥️",
			Href:     row.Href,
			Dot:      row.Dot,
			DotTitle: row.StateLabel,
			Selected: row.Host == selected,
		})
	}
	return items
}

// handleUIDashboard renders /ui/ — the index page. The content column shows
// the configured secret_view_text markdown.
func (s *Server) handleUIDashboard(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIPage(w, r) {
		return
	}
	data := struct{ uiPageData }{s.uiBase(r.Context(), "", "", "")}
	s.uiRenderPage(w, "dashboard", data)
}

// handleUISSE is the live-update stream every page opens once (via the
// hidden #ui-live span's data-init). It patches the header's "Updated" time
// and connection pill every few seconds until the client goes away or the
// daemon shuts down.
func (s *Server) handleUISSE(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIRead(w) {
		return
	}
	sse := datastar.NewSSE(w, r)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	send := func() bool {
		updated, err := uiFragment("updated-span", time.Now().Format("15:04:05"))
		if err != nil {
			return false
		}
		pill, err := uiFragment("conn-pill", s.uiAuthenticated())
		if err != nil {
			return false
		}
		return sse.PatchElements(updated+pill) == nil
	}
	if !send() {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.shutdownCtx.Done():
			return
		case <-ticker.C:
			if !send() {
				return
			}
		}
	}
}

// handleUIActionSync triggers an immediate sync, mirroring POST /api/v1/sync.
func (s *Server) handleUIActionSync(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIWrite(w, r) {
		return
	}
	if s.engine == nil {
		writeError(w, "sync engine not available", http.StatusServiceUnavailable)
		return
	}
	slog.Info("sync triggered via web UI")
	s.engine.TriggerSync()
	uiPatchFragment(w, r, "sync-btn-done", nil)
}

func (s *Server) handleUISyncBtnFragment(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIRead(w) {
		return
	}
	uiPatchFragment(w, r, "sync-btn", nil)
}

// handleUIActionCopyToken places the daemon's Vault token on this machine's
// clipboard server-side, with no trip through browser JS. Loopback-only means the daemon host and
// the browser host are the same machine.
func (s *Server) handleUIActionCopyToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIWrite(w, r) {
		return
	}
	if s.needsReauth() {
		writeError(w, "not authenticated (re-authentication pending)", http.StatusUnauthorized)
		return
	}
	if s.setClipboard == nil {
		writeError(w, "clipboard not available", http.StatusServiceUnavailable)
		return
	}
	token := s.vault.Token()
	if err := s.uiCopyToClipboard(token); err != nil {
		writeError(w, err.Error(), http.StatusBadGateway)
		return
	}
	slog.Info("vault token copied to clipboard via web UI", "username", s.username)
	uiPatchFragment(w, r, "copy-token-btn-done", nil)
}

func (s *Server) handleUICopyTokenBtnFragment(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIRead(w) {
		return
	}
	uiPatchFragment(w, r, "copy-token-btn", nil)
}

// uiCopyToClipboard funnels UI copy actions through the same single-flight +
// bounded-wait + scrubbed-error discipline the remote-clipboard endpoint
// uses. The error returned is scrubbed of the value and safe to surface.
func (s *Server) uiCopyToClipboard(value string) error {
	timedOut, err := guardedLaunch(&s.clipboardMu, clipboardSetTimeout, func() error {
		return s.setClipboard(value)
	})
	switch {
	case errors.Is(err, errLauncherBusy):
		return fmt.Errorf("a clipboard write is already in progress; try again shortly")
	case timedOut:
		return fmt.Errorf("timed out writing to the clipboard (it may still be set)")
	case err != nil:
		redacted := strings.ReplaceAll(err.Error(), value, "<value>")
		slog.Warn("ui clipboard copy failed", "error", redacted)
		return fmt.Errorf("failed to set clipboard: %s", redacted)
	}
	return nil
}

// uiSettingRow is one row of an enrolment's redacted settings table on the
// config page.
type uiSettingRow struct {
	Key   string
	Value string
	JSON  bool
	Code  bool
}

// uiSettingRows formats redacted enrolment settings for the config page: scalar values in code style, flat lists joined, structured
// values as pretty JSON.
func uiSettingRows(settings map[string]any) []uiSettingRow {
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := make([]uiSettingRow, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, uiSettingRow{Key: k, Value: uiFormatSetting(settings[k]), JSON: uiSettingIsJSON(settings[k]), Code: uiSettingIsCode(settings[k])})
	}
	return rows
}

func uiSettingIsJSON(v any) bool {
	switch vv := v.(type) {
	case nil:
		return false
	case []any:
		for _, item := range vv {
			if item != nil {
				if _, ok := item.(map[string]any); ok {
					return true
				}
			}
		}
		return false
	case map[string]any:
		return true
	default:
		return false
	}
}

func uiSettingIsCode(v any) bool {
	switch v.(type) {
	case nil, []any, map[string]any:
		return false
	default:
		return true
	}
}

func uiFormatSetting(v any) string {
	switch vv := v.(type) {
	case nil:
		return "—"
	case []any:
		if uiSettingIsJSON(v) {
			return uiJSONIndent(vv)
		}
		parts := make([]string, len(vv))
		for i, item := range vv {
			parts[i] = fmt.Sprint(item)
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		return uiJSONIndent(vv)
	default:
		return fmt.Sprint(vv)
	}
}

func uiJSONIndent(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// uiFormValue trims a posted form field.
func uiFormValue(r *http.Request, name string) string {
	return strings.TrimSpace(r.PostFormValue(name))
}

// uiParsePort validates a port form field: empty
// means "use the default" (returned as 0), otherwise a whole number between
// 1 and 65535 with no trailing garbage.
func uiParsePort(raw string) (int, bool) {
	if raw == "" {
		return 0, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 || n > 65535 {
		return 0, false
	}
	return n, true
}
