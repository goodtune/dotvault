package web

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	datastar "github.com/starfederation/datastar-go/datastar"
	"golang.org/x/crypto/ssh"

	"github.com/goodtune/dotvault/internal/sshfwd"
)

// uiRemoteRow is one managed remote joined with its live connection state,
// as rendered in the sidebar, the remotes table, and the detail page.
type uiRemoteRow struct {
	Host         string
	Port         int
	RemoteSocket string
	Enabled      bool
	State        string
	StateLabel   string
	PillClass    string
	Dot          string
	Reconnects   string
	LastError    string
	Href         string
	// HostKey is the pinned host key in authorized-key form ("" when trust
	// comes from a configured certificate authority instead); the detail
	// page shows its fingerprint and reveals the full key on demand. Not a
	// credential — it is the host's public key, the same value `dotvault ssh
	// list` and GET /api/v1/ssh/remotes already serve.
	HostKey            string
	HostKeyFingerprint string
}

// uiRemoteStateLabel maps a forward's state onto its display label.
func uiRemoteStateLabel(state string) string {
	switch state {
	case "connected":
		return "Connected"
	case "connecting":
		return "Connecting"
	case "reconnecting":
		return "Reconnecting"
	case "offline":
		return "Offline"
	case "authentication-error":
		return "Authentication error"
	case "host-key-error":
		return "Host key error"
	case "disabled":
		return "Disabled"
	default:
		return state
	}
}

// uiRemotePillClass maps a forward's state onto its pill styling.
func uiRemotePillClass(state string) string {
	switch state {
	case "connected":
		return "ssh-pill ssh-pill-ok"
	case "connecting", "reconnecting":
		return "ssh-pill ssh-pill-info"
	case "authentication-error", "host-key-error":
		return "ssh-pill ssh-pill-err"
	case "disabled":
		return "ssh-pill ssh-pill-muted"
	default:
		return "ssh-pill"
	}
}

// uiRemoteRows lists the configured remotes joined with live state.
// unavailable reports the documented "managed forwards not configured" case,
// distinct from a listing failure.
func (s *Server) uiRemoteRows() (rows []uiRemoteRow, unavailable bool, err error) {
	reg := s.sshRegistrySnapshot()
	if reg == nil {
		return nil, true, nil
	}
	remotes, err := reg.List()
	if err != nil {
		return nil, false, err
	}
	live := map[string]sshfwd.RemoteStatus{}
	if statusFn := s.sshStatusSnapshot(); statusFn != nil {
		for _, st := range statusFn() {
			live[st.Host] = st
		}
	}
	rows = make([]uiRemoteRow, 0, len(remotes))
	for _, rem := range remotes {
		row := uiRemoteRow{
			Host:               rem.Host,
			Port:               rem.PortOrDefault(),
			RemoteSocket:       rem.RemoteSocket,
			Enabled:            rem.EnabledOrDefault(),
			Reconnects:         "—",
			Href:               "/ui/remotes/" + url.PathEscape(rem.Host) + "/",
			HostKey:            rem.HostKey,
			HostKeyFingerprint: uiHostKeyFingerprint(rem.HostKey),
		}
		if st, ok := live[rem.Host]; ok {
			row.State = st.State
			row.Reconnects = strconv.Itoa(st.Reconnects)
			row.LastError = st.LastError
		} else if row.Enabled {
			// No live entry yet (just added, or config not yet reconciled) —
			// fall back on the config's own enabled flag.
			row.State = "offline"
		} else {
			row.State = "disabled"
		}
		row.StateLabel = uiRemoteStateLabel(row.State)
		row.PillClass = uiRemotePillClass(row.State)
		row.Dot = uiRemoteDot(row.State)
		rows = append(rows, row)
	}
	return rows, false, nil
}

// uiHostKeyFingerprint derives the SHA256 fingerprint of a pinned host key
// (authorized-key form). An empty or unparsable key yields "" — the template
// then falls back to showing the raw value, so a hand-edited ssh.yaml entry
// is still visible rather than hidden behind a parse error.
func uiHostKeyFingerprint(authorizedKey string) string {
	if authorizedKey == "" {
		return ""
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}

// uiHostKeyConfirm carries a pending host-key confirmation through a page
// re-render: the fingerprint shown to the user and exactly the candidate
// that produced it, so "Trust and add" re-submits precisely what was shown.
type uiHostKeyConfirm struct {
	Host        string
	Fingerprint string
	Candidate   uiRemoteCandidate
}

type uiRemoteCandidate struct {
	Host         string
	PortRaw      string
	RemoteSocket string
}

// uiRemotesPageData is the /ui/remotes/ view model.
type uiRemotesPageData struct {
	uiPageData
	Unavailable bool
	Remotes     []uiRemoteRow
	FormOpen    bool
	FormError   string
	FormHost    string
	FormPort    string
	FormSocket  string
	Confirm     *uiHostKeyConfirm
}

func (s *Server) uiRemotesPage(r *http.Request) uiRemotesPageData {
	data := uiRemotesPageData{
		uiPageData: s.uiBase(r.Context(), "Remotes", "remotes", ""),
	}
	rows, unavailable, err := s.uiRemoteRows()
	data.Remotes = rows
	data.Unavailable = unavailable
	if err != nil {
		data.Error = err.Error()
	}
	if !unavailable {
		// With managed forwards unconfigured the page is a static
		// explanation — don't open a stream that could never emit.
		data.SSHStream = uiSSHStreamURL("index", "")
	}
	return data
}

// handleUIRemotesIndex renders /ui/remotes/: the remotes table plus the
// initially-hidden add form the Add button reveals.
func (s *Server) handleUIRemotesIndex(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIPage(w, r) {
		return
	}
	s.uiRenderPage(w, "remotes", s.uiRemotesPage(r))
}

// handleUIRemoteAdd is the form-POST counterpart of POST /api/v1/ssh/remotes,
// carrying the same host-key confirmation protocol: an unpinned key
// re-renders the page with the fingerprint and a deliberate "Trust and add"
// gesture; nothing is persisted until that second submit echoes the
// fingerprint back.
func (s *Server) handleUIRemoteAdd(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIWrite(w, r) {
		return
	}
	reg := s.sshRegistrySnapshot()
	if reg == nil {
		writeError(w, "managed SSH forwards are not configured", http.StatusServiceUnavailable)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, sshBodyLimit)
	host := uiFormValue(r, "host")
	portRaw := uiFormValue(r, "port")
	socket := uiFormValue(r, "remote_socket")
	acceptFingerprint := uiFormValue(r, "accept_fingerprint")

	renderErr := func(msg string) {
		data := s.uiRemotesPage(r)
		data.FormOpen = true
		data.FormError = msg
		data.FormHost, data.FormPort, data.FormSocket = host, portRaw, socket
		s.uiRenderPage(w, "remotes", data)
	}

	if host == "" {
		renderErr("host is required")
		return
	}
	port, ok := uiParsePort(portRaw)
	if !ok {
		renderErr("port must be a whole number between 1 and 65535")
		return
	}

	remote := sshfwd.Remote{Host: host, Port: port, RemoteSocket: socket}
	opts := sshfwd.AddOptions{AcceptFingerprint: acceptFingerprint}
	if _, err := reg.Add(r.Context(), remote, opts); err != nil {
		var confirm *sshfwd.HostKeyConfirmation
		if errors.Is(err, sshfwd.ErrConfirmHostKey) && errors.As(err, &confirm) {
			data := s.uiRemotesPage(r)
			data.Confirm = &uiHostKeyConfirm{
				Host:        confirm.Host,
				Fingerprint: confirm.Fingerprint,
				Candidate:   uiRemoteCandidate{Host: host, PortRaw: portRaw, RemoteSocket: socket},
			}
			s.uiRenderPage(w, "remotes", data)
			return
		}
		renderErr(err.Error())
		return
	}
	slog.Info("ssh remote added via web UI", "host", host)
	http.Redirect(w, r, "/ui/remotes/", http.StatusSeeOther)
}

// uiRemoteFromPath validates the {host} wildcard (see handleSSHPatch for why
// the mux hands it over unescaped) and finds its configured row.
func (s *Server) uiRemoteFromPath(w http.ResponseWriter, r *http.Request) (uiRemoteRow, bool) {
	host := r.PathValue("host")
	if err := sshfwd.ValidateHost(host); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return uiRemoteRow{}, false
	}
	rows, unavailable, err := s.uiRemoteRows()
	if unavailable {
		writeError(w, "managed SSH forwards are not configured", http.StatusServiceUnavailable)
		return uiRemoteRow{}, false
	}
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return uiRemoteRow{}, false
	}
	for _, row := range rows {
		if row.Host == host {
			return row, true
		}
	}
	http.Redirect(w, r, "/ui/remotes/", http.StatusSeeOther)
	return uiRemoteRow{}, false
}

// uiRemoteDetailData is the /ui/remotes/<host>/ view model.
type uiRemoteDetailData struct {
	uiPageData
	Remote       uiRemoteRow
	FormError    string
	SaveAction   string
	DeleteAction string
}

func (s *Server) renderUIRemoteDetail(w http.ResponseWriter, r *http.Request, row uiRemoteRow, formError string) {
	data := uiRemoteDetailData{
		uiPageData:   s.uiBase(r.Context(), row.Host, "remotes", row.Host),
		Remote:       row,
		FormError:    formError,
		SaveAction:   "/ui/remotes/" + url.PathEscape(row.Host) + "/save",
		DeleteAction: "/ui/remotes/" + url.PathEscape(row.Host) + "/delete",
	}
	data.SSHStream = uiSSHStreamURL("detail", row.Host)
	s.uiRenderPage(w, "remote_detail", data)
}

// handleUIRemoteDetail renders /ui/remotes/<host>/ — the per-remote
// configuration form.
func (s *Server) handleUIRemoteDetail(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIPage(w, r) {
		return
	}
	row, ok := s.uiRemoteFromPath(w, r)
	if !ok {
		return
	}
	s.renderUIRemoteDetail(w, r, row, r.URL.Query().Get("err"))
}

// handleUIRemoteSave applies the detail form via the same Registry.Patch the
// JSON API and CLI use.
func (s *Server) handleUIRemoteSave(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIWrite(w, r) {
		return
	}
	row, ok := s.uiRemoteFromPath(w, r)
	if !ok {
		return
	}
	reg := s.sshRegistrySnapshot()
	if reg == nil {
		writeError(w, "managed SSH forwards are not configured", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, sshBodyLimit)
	portRaw := uiFormValue(r, "port")
	socket := uiFormValue(r, "remote_socket")
	// An unchecked checkbox posts nothing, so absence means false — the
	// enabled switch is always an explicit choice on this form.
	enabled := r.PostFormValue("enabled") == "true"

	port, okPort := uiParsePort(portRaw)
	if !okPort {
		s.renderUIRemoteDetail(w, r, row, "port must be a whole number between 1 and 65535")
		return
	}

	if _, err := reg.Patch(r.Context(), row.Host, sshfwd.Patch{
		Enabled:      &enabled,
		RemoteSocket: &socket,
		Port:         &port,
	}); err != nil {
		s.renderUIRemoteDetail(w, r, row, err.Error())
		return
	}
	slog.Info("ssh remote updated via web UI", "host", row.Host)
	http.Redirect(w, r, "/ui/remotes/"+url.PathEscape(row.Host)+"/", http.StatusSeeOther)
}

// handleUIRemoteDelete removes the remote and returns to the list.
func (s *Server) handleUIRemoteDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIWrite(w, r) {
		return
	}
	row, ok := s.uiRemoteFromPath(w, r)
	if !ok {
		return
	}
	reg := s.sshRegistrySnapshot()
	if reg == nil {
		writeError(w, "managed SSH forwards are not configured", http.StatusServiceUnavailable)
		return
	}
	if _, err := reg.Remove(r.Context(), row.Host); err != nil {
		s.renderUIRemoteDetail(w, r, row, err.Error())
		return
	}
	slog.Info("ssh remote removed via web UI", "host", row.Host)
	http.Redirect(w, r, "/ui/remotes/", http.StatusSeeOther)
}

// uiSSHStreamInterval is the cadence at which /ui/sse/ssh re-reads the
// managed-forward state. Reads are cheap (Registry.List is a small file
// read, the status query an in-memory snapshot), and patches only go out on
// change. A var so tests can shorten it.
var uiSSHStreamInterval = 2 * time.Second

// uiSSHStreamMaxFailures is how many consecutive render failures the stream
// tolerates (one is usually ssh.yaml mid-rewrite) before closing instead of
// presenting stale state as live.
const uiSSHStreamMaxFailures = 5

// uiSSHStreamURL builds the /ui/sse/ssh subscription URL a page embeds. view
// selects which content region the stream patches alongside the nav list:
// "index" (the remotes table) or "detail" (one remote's state line).
func uiSSHStreamURL(view, host string) string {
	q := url.Values{"view": {view}}
	if host != "" {
		q.Set("host", host)
	}
	return "/ui/sse/ssh?" + q.Encode()
}

// renderUISSHLive renders the patch payload for one /ui/sse/ssh tick: the
// nav Remotes list plus the view's content region. The caller diffs the
// returned string against the last sent payload so unchanged state sends
// nothing.
func (s *Server) renderUISSHLive(view, host string) (string, error) {
	rows, unavailable, err := s.uiRemoteRows()
	if err != nil {
		return "", err
	}
	if unavailable {
		// No registry wired (managed forwards not configured): the pages
		// render a static explanation and there is nothing to live-update.
		return "", nil
	}
	selected := ""
	if view == "detail" {
		selected = host
	}
	nav, err := uiFragment("nav-remotes-list", uiRemotesNavItems(rows, selected))
	if err != nil {
		return "", err
	}
	switch view {
	case "detail":
		row := uiRemoteRow{
			Host:       host,
			State:      "disabled",
			StateLabel: "Removed",
			PillClass:  "ssh-pill ssh-pill-muted",
			Dot:        "grey",
		}
		for _, r := range rows {
			if r.Host == host {
				row = r
				break
			}
		}
		state, err := uiFragment("remote-state", row)
		if err != nil {
			return "", err
		}
		return nav + state, nil
	default: // index
		panel, err := uiFragment("remotes-panel", rows)
		if err != nil {
			return "", err
		}
		return nav + panel, nil
	}
}

// handleUISSHSSE is the managed-forward live stream: any page that renders
// SSH forward state subscribes (via the layout's #ui-ssh-stream span) and
// receives patches whenever a remote's connection state, configuration, or
// membership changes — whether the change came from this page, another tab,
// the CLI (which mutates through the daemon's API), or the daemon's own
// reconnect loop. State is polled server-side and patches are sent only on
// change, so an idle stream is silent.
func (s *Server) handleUISSHSSE(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIRead(w) {
		return
	}
	view := r.URL.Query().Get("view")
	if view != "index" && view != "detail" {
		writeError(w, "invalid view", http.StatusBadRequest)
		return
	}
	host := r.URL.Query().Get("host")
	if view == "detail" {
		if err := sshfwd.ValidateHost(host); err != nil {
			writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	sse := datastar.NewSSE(w, r)
	ticker := time.NewTicker(uiSSHStreamInterval)
	defer ticker.Stop()

	last := ""
	failures := 0
	send := func() bool {
		frag, err := s.renderUISSHLive(view, host)
		if err != nil {
			// A single failure is usually ssh.yaml mid-rewrite — retry. A
			// run of them means the source is genuinely broken; close the
			// stream rather than silently presenting stale state as live.
			failures++
			if failures >= uiSSHStreamMaxFailures {
				slog.Warn("ui: ssh live stream closing after repeated render failures", "error", err)
				return false
			}
			slog.Debug("ui: ssh live render failed", "error", err)
			return true
		}
		failures = 0
		if frag == "" || frag == last {
			return true
		}
		last = frag
		return sse.PatchElements(frag) == nil
	}
	// Send the current state immediately. It usually duplicates what the
	// page just rendered (an idempotent patch, invisible to the user), but
	// it closes the gap where state changed between the page render and the
	// stream opening — silently priming the diff instead would swallow that
	// first change.
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
