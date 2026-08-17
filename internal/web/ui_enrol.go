package web

import (
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// uiEnrolCard is the view model for the server-rendered enrolment card. The
// output parsing (device code, verification URL, progress line) is the Go
// port of the SPA's enrol-card.jsx heuristics, so the two surfaces recognise
// the same engine output shapes.
type uiEnrolCard struct {
	Key             string
	Engine          string
	EngineName      string
	Title           string
	EngineDesc      string
	Status          string
	Error           string
	HelpText        template.HTML
	Output          []string
	DeviceCode      string
	VerificationURL string
	ProgressLine    string
	HasDeviceFlow   bool
	HasRedirectFlow bool
	CodeSpent       bool
	RedirectSpent   bool
	PromptPending   bool
	PromptLabel     string
	// FragmentURL is interpolated inside a data-on-interval attribute, which
	// html/template escapes as a JavaScript string — correct, since datastar
	// evaluates the attribute as a real JS expression.
	FragmentURL string
	PageURL     string
	Busy        bool
}

var (
	uiDeviceCodeRe = regexp.MustCompile(`one-time code:\s*(\S+)`)
	uiHTTPURLRe    = regexp.MustCompile(`https?://\S+`)
	uiMintingRe    = regexp.MustCompile(`(?i)minting`)
	uiExchangeRe   = regexp.MustCompile(`(?i)exchang|minting`)
)

// uiEngineDescription mirrors the SPA's engineDescription lookup.
func uiEngineDescription(engine string) string {
	switch engine {
	case "github":
		return "OAuth token via device flow"
	case "jfrog":
		return "Refreshable access token via web login"
	case "databricks":
		return "OAuth U2M token via browser login"
	case "ghp":
		return "CLI session token via device flow"
	case "ssh":
		return "Ed25519 key generation"
	case "copy":
		return "Mirror an existing Vault secret"
	default:
		return engine
	}
}

// uiEnrolPageURL is the canonical detail-page URL for an enrolment.
func uiEnrolPageURL(engine, key string) string {
	return "/ui/enrolments/" + url.PathEscape(engine) + "/" + uiEscapePath(key) + "/"
}

// buildUIEnrolCard assembles the card view from an enrolment's live state.
func (s *Server) buildUIEnrolCard(st EnrolStateInfo, anyRunning bool) uiEnrolCard {
	title := st.EngineName
	if i := strings.IndexByte(st.Key, '/'); i >= 0 {
		// Grouped keys title on the leaf, matching the SPA's grouped cards.
		title = st.Key[i+1:]
	}
	card := uiEnrolCard{
		Key:         st.Key,
		Engine:      st.Engine,
		EngineName:  st.EngineName,
		Title:       title,
		EngineDesc:  uiEngineDescription(st.Engine),
		Status:      st.Status,
		Error:       st.Error,
		HelpText:    template.HTML(st.HelpTextHTML),
		Output:      st.Output,
		FragmentURL: "/ui/fragments/enrol-card?" + url.Values{"key": {st.Key}}.Encode(),
		PageURL:     uiEnrolPageURL(st.Engine, st.Key),
		Busy:        anyRunning && st.Status != "running",
	}
	for _, line := range st.Output {
		if m := uiDeviceCodeRe.FindStringSubmatch(line); m != nil {
			card.DeviceCode = m[1]
		}
		if m := uiHTTPURLRe.FindString(line); m != "" {
			card.VerificationURL = strings.TrimRight(m, ".,;:")
		}
	}
	for i := len(st.Output) - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(st.Output[i])
		if strings.HasPrefix(trimmed, "⠼") {
			card.ProgressLine = strings.TrimSpace(strings.TrimPrefix(trimmed, "⠼"))
			break
		}
	}
	card.HasDeviceFlow = card.DeviceCode != "" && card.VerificationURL != ""
	card.HasRedirectFlow = card.VerificationURL != "" && card.DeviceCode == ""
	card.CodeSpent = card.ProgressLine != "" && uiMintingRe.MatchString(card.ProgressLine)
	card.RedirectSpent = card.ProgressLine != "" && uiExchangeRe.MatchString(card.ProgressLine)
	if st.Status == "running" {
		s.enrolPromptMu.RLock()
		if s.enrolPromptCh != nil {
			card.PromptPending = true
			card.PromptLabel = s.enrolPromptLabel
		}
		s.enrolPromptMu.RUnlock()
	}
	return card
}

// uiEnrolState looks up one enrolment's state plus whether any enrolment is
// currently running.
func (s *Server) uiEnrolState(key string) (EnrolStateInfo, bool, error) {
	runner := s.getEnrolRunner()
	if runner == nil {
		return EnrolStateInfo{}, false, ErrEnrolNotFound
	}
	st, err := runner.GetState(key)
	if err != nil {
		return EnrolStateInfo{}, false, err
	}
	return st, runner.AnyRunning(), nil
}

// handleUIEnrolmentsIndex renders /ui/enrolments/ with the Enrolments
// accordion expanded.
func (s *Server) handleUIEnrolmentsIndex(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIPage(w, r) {
		return
	}
	data := struct{ uiPageData }{s.uiBase(r.Context(), "Enrolments", "enrolments", "")}
	s.uiRenderPage(w, "enrolments", data)
}

// handleUIEnrolDetail renders /ui/enrolments/<engine>/<key>/ — the page the
// enrolment actually runs on. With an empty key it renders the index with
// that engine's folder expanded (the accordion's expand gesture).
func (s *Server) handleUIEnrolDetail(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIPage(w, r) {
		return
	}
	engine := r.PathValue("engine")
	key := strings.TrimSuffix(r.PathValue("key"), "/")
	if key == "" {
		data := struct{ uiPageData }{s.uiBase(r.Context(), "Enrolments", "enrolments", engine+"#")}
		s.uiRenderPage(w, "enrolments", data)
		return
	}
	st, anyRunning, err := s.uiEnrolState(key)
	if err != nil || st.Engine != engine {
		data := struct{ uiPageData }{s.uiBase(r.Context(), "Enrolments", "enrolments", "")}
		data.Error = "enrolment not found"
		s.uiRenderPage(w, "enrolments", data)
		return
	}
	card := s.buildUIEnrolCard(st, anyRunning)
	if msg := r.URL.Query().Get("err"); msg != "" {
		card.Error = msg
	}
	data := struct {
		uiPageData
		Card uiEnrolCard
	}{
		uiPageData: s.uiBase(r.Context(), st.Key, "enrolments", engine+"#"+key),
		Card:       card,
	}
	if msg := r.URL.Query().Get("err"); msg != "" {
		data.Error = msg
	}
	s.uiRenderPage(w, "enrol_detail", data)
}

// handleUIEnrolCardFragment re-renders the card for the running-state poll.
func (s *Server) handleUIEnrolCardFragment(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIRead(w) {
		return
	}
	key := r.URL.Query().Get("key")
	st, anyRunning, err := s.uiEnrolState(key)
	if err != nil {
		writeError(w, "enrolment not found", http.StatusNotFound)
		return
	}
	uiPatchFragment(w, r, "enrol-card", s.buildUIEnrolCard(st, anyRunning))
}

// uiEnrolAction wraps the shared form-POST plumbing of the start/skip/reset
// handlers: gate, look up, act, redirect back to the detail page (with the
// error carried in the query when the action was refused).
func (s *Server) uiEnrolAction(w http.ResponseWriter, r *http.Request, act func(runner *EnrolmentRunner, key string) error) {
	if !s.requireUIWrite(w, r) {
		return
	}
	key := uiFormValue(r, "key")
	runner := s.getEnrolRunner()
	if runner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}
	st, err := runner.GetState(key)
	if err != nil {
		writeError(w, "enrolment not found", http.StatusNotFound)
		return
	}
	target := uiEnrolPageURL(st.Engine, st.Key)
	if err := act(runner, key); err != nil {
		target += "?err=" + url.QueryEscape(err.Error())
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *Server) handleUIEnrolStart(w http.ResponseWriter, r *http.Request) {
	s.uiEnrolAction(w, r, func(runner *EnrolmentRunner, key string) error {
		err := runner.Start(
			s.shutdownCtx, key, s.vault,
			s.kvMount, s.userKVPrefix(), s.username,
			s.EnrolPromptSecret,
		)
		if err != nil {
			slog.Warn("ui: enrolment start refused", "key", key, "error", err)
		}
		return err
	})
}

func (s *Server) handleUIEnrolSkip(w http.ResponseWriter, r *http.Request) {
	s.uiEnrolAction(w, r, func(runner *EnrolmentRunner, key string) error {
		return runner.Skip(key)
	})
}

func (s *Server) handleUIEnrolReset(w http.ResponseWriter, r *http.Request) {
	s.uiEnrolAction(w, r, func(runner *EnrolmentRunner, key string) error {
		return runner.Reset(key)
	})
}

// handleUIEnrolSecret is the form-POST counterpart of the SPA's
// /api/v1/enrol/secret: it hands the submitted passphrase to the engine
// blocked in EnrolPromptSecret, then returns to the detail page.
func (s *Server) handleUIEnrolSecret(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIWrite(w, r) {
		return
	}
	key := uiFormValue(r, "key")
	value := r.PostFormValue("value")
	target := "/ui/enrolments/"
	if st, _, err := s.uiEnrolState(key); err == nil {
		target = uiEnrolPageURL(st.Engine, st.Key)
	}

	if err := s.deliverEnrolPrompt(value); err != nil {
		http.Redirect(w, r, target+"?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
