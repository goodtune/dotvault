// The first-run enrolment wizard: the standalone page that stands between a
// fresh login and the main site while the user has no credentials at all.
//
// It appears only when *no* enrolment has been completed. Once anything is
// enrolled — or the user dismisses the wizard — the main site takes over and
// individual enrolments are managed from /ui/enrolments/ instead. That rule
// is the whole difference from the enrolment page this replaced, which reappeared
// whenever any enrolment was outstanding and so kept interrupting users who
// had deliberately skipped one.
package web

import (
	"net/http"
)

// setupActionBase is the form-action prefix the wizard's cards post to. It
// selects the redirect target for the shared enrolment actions (back to the
// wizard rather than to an enrolment's own page) and is a fixed,
// server-chosen string — never anything a request can influence.
const setupActionBase = "/setup"

// uiSetupData is the wizard's view model.
type uiSetupData struct {
	uiStandaloneData
	Cards        []uiEnrolCard
	AnyRunning   bool
	AllAddressed bool
}

// NeedsSetupWizard reports whether the first-run wizard should be shown.
func (s *Server) NeedsSetupWizard() bool {
	runner := s.getEnrolRunner()
	return runner != nil && runner.NeedsWizard()
}

// completeEnrolments dismisses the wizard and releases any daemon startup
// blocked on it. Idempotent, and safe when no runner exists.
func (s *Server) completeEnrolments() {
	if runner := s.getEnrolRunner(); runner != nil {
		runner.Complete()
	}
}

// handleSetup renders the wizard, or steps aside when it isn't needed.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !s.uiAuthenticated() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.NeedsSetupWizard() {
		s.completeEnrolments()
		http.Redirect(w, r, "/ui/", http.StatusSeeOther)
		return
	}

	runner := s.getEnrolRunner()
	states := runner.States()
	anyRunning := runner.AnyRunning()

	data := uiSetupData{
		uiStandaloneData: uiStandaloneData{
			Title: "Setup",
			// The cards poll their own fragments while an enrolment runs.
			Datastar: true,
			Error:    r.URL.Query().Get("err"),
		},
		AnyRunning:   anyRunning,
		AllAddressed: true,
	}
	for _, st := range states {
		data.Cards = append(data.Cards, s.buildUIEnrolCard(st, anyRunning, setupActionBase))
		if st.Status != "complete" && st.Status != "skipped" {
			data.AllAddressed = false
		}
	}
	s.uiRenderStandalone(w, "setup", data)
}

// handleSetupComplete dismisses the wizard and enters the main site.
func (s *Server) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIWrite(w, r) {
		return
	}
	s.completeEnrolments()
	http.Redirect(w, r, "/ui/", http.StatusSeeOther)
}
