package web

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"

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
}

// uiRemoteStateLabel mirrors the SPA's STATE_LABELS lookup.
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

// uiRemotePillClass mirrors the SPA's statePillClass lookup.
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
			Host:         rem.Host,
			Port:         rem.PortOrDefault(),
			RemoteSocket: rem.RemoteSocket,
			Enabled:      rem.EnabledOrDefault(),
			Reconnects:   "—",
			Href:         "/ui/remotes/" + url.PathEscape(rem.Host) + "/",
		}
		if st, ok := live[rem.Host]; ok {
			row.State = st.State
			row.Reconnects = strconv.Itoa(st.Reconnects)
			row.LastError = st.LastError
		} else if row.Enabled {
			// No live entry yet (just added, or config not yet reconciled) —
			// fall back on the config's own enabled flag, matching the SPA.
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
