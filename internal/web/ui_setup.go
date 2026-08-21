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

// allAddressed reports whether every enrolment has been dealt with, either by
// completing or by the user declining it. It is the one definition of the
// wizard's "nothing left to do" state, called by both the page render and the
// fragment patch — the footer's two branches are different elements, so the
// two paths disagreeing would mean a page whose exit control changes shape on
// a patch that was not meant to change it.
//
// An empty list is vacuously addressed, which is the right answer for the
// only way to reach it: a runner that no longer exists (a config reload
// landing mid-request), where offering "continue" beats offering to skip
// enrolments that are not there.
func allAddressed(states []EnrolStateInfo) bool {
	for _, st := range states {
		if st.Status != "complete" && st.Status != "skipped" {
			return false
		}
	}
	return true
}

// setupFooterData builds the footer's view model from live runner state, for
// the fragment patch. The page render passes its own already-fetched states
// through allAddressed instead, rather than re-fetching the runner.
func (s *Server) setupFooterData() uiSetupData {
	runner := s.getEnrolRunner()
	if runner == nil {
		return uiSetupData{AllAddressed: true}
	}
	return uiSetupData{AllAddressed: allAddressed(runner.States())}
}

// handleSetupComplete abandons whatever is still outstanding and enters the
// main site. It exists only for the not-everything-addressed half of the
// footer: with nothing left to decide the control is a plain link to "/",
// but leaving early is a real decision, so it is a POST rather than a GET
// that quietly discards the rest of someone's setup.
func (s *Server) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIWrite(w, r) {
		return
	}
	s.completeEnrolments()
	http.Redirect(w, r, "/ui/", http.StatusSeeOther)
}

// handleSetup renders the wizard, or steps aside when it isn't needed.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !s.uiAuthenticated() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// Take the runner once. NeedsSetupWizard() loads it too, and a
	// concurrent InitEnrolments swapping in a runner-less config between the
	// two loads would panic on the States() call below.
	runner := s.getEnrolRunner()
	if runner == nil || !runner.NeedsWizard() {
		s.completeEnrolments()
		http.Redirect(w, r, "/ui/", http.StatusSeeOther)
		return
	}

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
		AllAddressed: allAddressed(states),
	}
	for _, st := range states {
		data.Cards = append(data.Cards, s.buildUIEnrolCard(st, anyRunning, setupActionBase))
	}
	s.uiRenderStandalone(w, "setup", data)
}
