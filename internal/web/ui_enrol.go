package web

import (
	"encoding/hex"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// uiEnrolCard is the view model for the server-rendered enrolment card. The
// output parsing (device code, verification URL, progress line) is the Go
// port of the heuristics the previous Preact card used, so the recognised
// engine output shapes did not change with the rewrite.
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
	// ElementID is this card's DOM id, unique per enrolment key: the setup
	// wizard renders every card at once, so a fixed id would make each SSE
	// patch land on whichever card happened to be first. Hex-encoding the
	// key keeps it collision-free (keys may contain "/" and other characters
	// an id cannot carry) and stable across renders, which is what lets a
	// patch find its own card.
	ElementID string
	// ActionBase prefixes this card's form actions, selecting where the
	// shared enrolment actions return to: the enrolment's own page under
	// /ui/enrol, or the wizard under /setup. Always one of two fixed,
	// server-chosen strings — never request-derived, so it cannot become a
	// redirect the caller controls.
	ActionBase string
}

var (
	uiDeviceCodeRe = regexp.MustCompile(`one-time code:\s*(\S+)`)
	uiHTTPURLRe    = regexp.MustCompile(`https?://\S+`)
	uiMintingRe    = regexp.MustCompile(`(?i)minting`)
	uiExchangeRe   = regexp.MustCompile(`(?i)exchang|minting`)
)

// uiEngineDescription is the one-line summary shown beside an engine.
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

// Sentinels for deliverEnrolPrompt; their text is the user-facing message.
var (
	errNoPendingPrompt = errors.New("no pending prompt")
	errPromptAnswered  = errors.New("prompt already answered")
)

// deliverEnrolPrompt hands a submitted secret value to the engine blocked in
// EnrolPromptSecret. It owns the lock/select/clear protocol over
// enrolPromptCh so the form endpoints on both surfaces (the enrolment page
// and the wizard) cannot drift apart.
func (s *Server) deliverEnrolPrompt(value string) error {
	s.enrolPromptMu.Lock()
	defer s.enrolPromptMu.Unlock()
	ch := s.enrolPromptCh
	if ch == nil {
		return errNoPendingPrompt
	}
	select {
	case ch <- value:
		s.enrolPromptCh = nil
		s.enrolPromptLabel = ""
		return nil
	default:
		return errPromptAnswered
	}
}

// enrolActionBase is the form-action prefix for enrolment actions driven
// from the main site (the wizard passes setupActionBase instead).
const enrolActionBase = "/ui/enrol"

// enrolActionTarget is where an enrolment action returns the browser: the
// wizard's own page when the action came from there, else the enrolment's
// detail page. Chosen from the fixed base, never from request input.
func enrolActionTarget(base string, st EnrolStateInfo) string {
	if base == setupActionBase {
		return "/setup/"
	}
	return uiEnrolPageURL(st.Engine, st.Key)
}

// enrolFragmentURL is the poll URL for one card, carrying the action base so
// the patched card keeps posting where the original did.
func enrolFragmentURL(key, base string) string {
	q := url.Values{"key": {key}}
	if base == setupActionBase {
		q.Set("base", "setup")
	}
	return "/ui/fragments/enrol-card?" + q.Encode()
}

// enrolBaseFromRequest maps the fragment poll's base parameter back onto one
// of the two fixed action bases.
func enrolBaseFromRequest(r *http.Request) string {
	if r.URL.Query().Get("base") == "setup" {
		return setupActionBase
	}
	return enrolActionBase
}

// uiEnrolPageURL is the canonical detail-page URL for an enrolment.
func uiEnrolPageURL(engine, key string) string {
	return "/ui/enrolments/" + url.PathEscape(engine) + "/" + uiEscapePath(key) + "/"
}

// buildUIEnrolCard assembles the card view from an enrolment's live state.
// base selects where this card's actions post and return to (see ActionBase);
// it also rides the fragment URL, so a running card polled from the wizard
// re-renders as a wizard card rather than silently reverting to the main
// site's actions on the first patch.
func (s *Server) buildUIEnrolCard(st EnrolStateInfo, anyRunning bool, base string) uiEnrolCard {
	title := st.EngineName
	if i := strings.IndexByte(st.Key, '/'); i >= 0 {
		// Grouped keys title on the leaf ("databricks/prod" shows "prod").
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
		FragmentURL: enrolFragmentURL(st.Key, base),
		PageURL:     uiEnrolPageURL(st.Engine, st.Key),
		ElementID:   "ui-enrol-" + hex.EncodeToString([]byte(st.Key)),
		ActionBase:  base,
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
	card := s.buildUIEnrolCard(st, anyRunning, enrolActionBase)
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
	base := enrolBaseFromRequest(r)
	card, err := uiFragment("enrol-card", s.buildUIEnrolCard(st, anyRunning, base))
	if err != nil {
		writeError(w, "failed to render fragment", http.StatusInternalServerError)
		return
	}
	if base != setupActionBase {
		uiPatchElements(w, r, card)
		return
	}
	// On the wizard, the card is not the only thing this poll invalidates:
	// finishing an enrolment can be what makes every enrolment addressed, and
	// the footer renders from that. Patching only the card is what left the
	// user on a completed wizard whose exit control still said "Skip
	// remaining" and was still disabled from when something was running.
	footer, err := uiFragment("setup-footer", s.setupFooterData())
	if err != nil {
		writeError(w, "failed to render fragment", http.StatusInternalServerError)
		return
	}
	uiPatchElements(w, r, card+footer)
}

// uiEnrolAction wraps the shared form-POST plumbing of the start/skip/reset
// handlers: gate, look up, act, redirect back to the detail page (with the
// error carried in the query when the action was refused).
func (s *Server) uiEnrolAction(w http.ResponseWriter, r *http.Request, base string, act func(runner *EnrolmentRunner, key string) error) {
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
	target := enrolActionTarget(base, st)
	if err := act(runner, key); err != nil {
		target += "?err=" + url.QueryEscape(err.Error())
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *Server) handleUIEnrolStart(w http.ResponseWriter, r *http.Request) {
	s.enrolStart(w, r, enrolActionBase)
}

func (s *Server) handleSetupEnrolStart(w http.ResponseWriter, r *http.Request) {
	s.enrolStart(w, r, setupActionBase)
}

func (s *Server) enrolStart(w http.ResponseWriter, r *http.Request, base string) {
	s.uiEnrolAction(w, r, base, func(runner *EnrolmentRunner, key string) error {
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
	s.enrolSkip(w, r, enrolActionBase)
}

func (s *Server) handleSetupEnrolSkip(w http.ResponseWriter, r *http.Request) {
	s.enrolSkip(w, r, setupActionBase)
}

func (s *Server) enrolSkip(w http.ResponseWriter, r *http.Request, base string) {
	s.uiEnrolAction(w, r, base, func(runner *EnrolmentRunner, key string) error {
		return runner.Skip(key)
	})
}

func (s *Server) handleUIEnrolReset(w http.ResponseWriter, r *http.Request) {
	s.enrolReset(w, r, enrolActionBase)
}

func (s *Server) handleSetupEnrolReset(w http.ResponseWriter, r *http.Request) {
	s.enrolReset(w, r, setupActionBase)
}

func (s *Server) enrolReset(w http.ResponseWriter, r *http.Request, base string) {
	s.uiEnrolAction(w, r, base, func(runner *EnrolmentRunner, key string) error {
		return runner.Reset(key)
	})
}

// handleUIEnrolSecret takes the passphrase an engine is blocked on: it hands the submitted passphrase to the engine
// blocked in EnrolPromptSecret, then returns to the detail page.
func (s *Server) handleUIEnrolSecret(w http.ResponseWriter, r *http.Request) {
	s.enrolSecret(w, r, enrolActionBase)
}

func (s *Server) handleSetupEnrolSecret(w http.ResponseWriter, r *http.Request) {
	s.enrolSecret(w, r, setupActionBase)
}

func (s *Server) enrolSecret(w http.ResponseWriter, r *http.Request, base string) {
	if !s.requireUIWrite(w, r) {
		return
	}
	key := uiFormValue(r, "key")
	value := r.PostFormValue("value")
	target := "/ui/enrolments/"
	if base == setupActionBase {
		target = "/setup/"
	}
	if st, _, err := s.uiEnrolState(key); err == nil {
		target = enrolActionTarget(base, st)
	}

	if err := s.deliverEnrolPrompt(value); err != nil {
		http.Redirect(w, r, target+"?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
