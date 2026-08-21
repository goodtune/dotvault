package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/config"
)

// setupTestServer is an authenticated server whose runner holds the given
// enrolments. Keys must be ones the fake Vault does not serve, or
// InitEnrolments marks them complete from Vault and the wizard steps aside.
func setupTestServer(t *testing.T, enrolments map[string]config.Enrolment) *Server {
	t.Helper()
	if err := uiInitTemplates(); err != nil {
		t.Fatal(err)
	}
	s := uiTestAuthedServer(t)
	s.InitEnrolments(t.Context(), enrolments)
	return s
}

// TestNeedsWizard_ZeroCompletedIsTheTrigger pins the rule the wizard exists
// for: it interrupts a user who has nothing enrolled, and nobody else.
func TestNeedsWizard_ZeroCompletedIsTheTrigger(t *testing.T) {
	newRunner := func() *EnrolmentRunner {
		return NewEnrolmentRunner(map[string]config.Enrolment{
			"ssh": {Engine: "ssh"},
			"gh":  {Engine: "github"},
		})
	}

	if r := NewEnrolmentRunner(nil); r.NeedsWizard() {
		t.Error("no enrolments configured: wizard must not appear")
	}

	r := newRunner()
	if !r.NeedsWizard() {
		t.Error("nothing enrolled yet: wizard should appear")
	}

	// One completed enrolment means first-run setup is behind this user; an
	// outstanding second enrolment waits on the main site instead.
	r = newRunner()
	r.MarkComplete("gh")
	if r.NeedsWizard() {
		t.Error("an enrolment is complete: wizard must step aside")
	}

	// Skipping everything completes nothing, so the dismissal latch — not a
	// completion — is what stops the wizard reappearing forever.
	r = newRunner()
	for _, key := range []string{"ssh", "gh"} {
		if err := r.Skip(key); err != nil {
			t.Fatalf("Skip(%s): %v", key, err)
		}
	}
	if !r.NeedsWizard() {
		t.Error("all skipped but nothing enrolled: wizard still warranted until dismissed")
	}
	r.Complete()
	if r.NeedsWizard() {
		t.Error("dismissed wizard must stay dismissed")
	}

	// An engine that does not exist is not runnable, so it cannot on its own
	// justify a wizard the user could do nothing with.
	if NewEnrolmentRunner(map[string]config.Enrolment{"x": {Engine: "nope"}}).NeedsWizard() {
		t.Error("unrunnable enrolment must not trigger the wizard")
	}
}

// TestWait_DoesNotBlockWhenWizardIsSkipped is the daemon-side half: startup
// waits only for a wizard the user will actually be shown. Before the wizard
// was gated this way, a host with one enrolment already complete and another
// outstanding blocked the sync engine until something called Complete —
// which, with the user sent straight to the main site, nothing ever would.
func TestWait_DoesNotBlockWhenWizardIsSkipped(t *testing.T) {
	r := NewEnrolmentRunner(map[string]config.Enrolment{
		"ssh": {Engine: "ssh"},
		"gh":  {Engine: "github"},
	})
	r.MarkComplete("gh")

	done := make(chan struct{})
	go func() { r.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Wait blocked despite the wizard being skipped")
	}
}

func TestSetupWizard_RendersCardsAndStepsAside(t *testing.T) {
	s := setupTestServer(t, map[string]config.Enrolment{"ssh": {Engine: "ssh"}})

	w := httptest.NewRecorder()
	s.handleSetup(w, httptest.NewRequest("GET", "/setup/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"Complete your setup",
		`action="/setup/start"`, // cards return to the wizard, not the site
		`action="/setup/skip"`,
		`action="/setup/complete"`,
		"enrol-card",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("wizard missing %q", want)
		}
	}
	// Standalone: no site chrome.
	if strings.Contains(body, `class="status-bar"`) || strings.Contains(body, `class="sidebar"`) {
		t.Error("wizard must be chrome-less")
	}

	// Once something is enrolled the wizard hands over to the main site.
	s.getEnrolRunner().MarkComplete("ssh")
	w = httptest.NewRecorder()
	s.handleSetup(w, httptest.NewRequest("GET", "/setup/", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/" {
		t.Fatalf("status = %d, location = %q; want a redirect to /ui/", w.Code, w.Header().Get("Location"))
	}
}

func TestSetupWizard_RedirectsUnauthenticated(t *testing.T) {
	if err := uiInitTemplates(); err != nil {
		t.Fatal(err)
	}
	s := testServer(t)
	w := httptest.NewRecorder()
	s.handleSetup(w, httptest.NewRequest("GET", "/setup/", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Errorf("status = %d, location = %q; want a redirect to the login view", w.Code, w.Header().Get("Location"))
	}
}

// TestSetupComplete_DismissesAndReleases pins the Continue button: it lets
// the daemon proceed and sends the user to the main site.
func TestSetupComplete_DismissesAndReleases(t *testing.T) {
	s := setupTestServer(t, map[string]config.Enrolment{"ssh": {Engine: "ssh"}})

	waited := make(chan struct{})
	go func() { s.WaitForEnrolments(); close(waited) }()

	req := postForm(t, "/setup/complete", url.Values{})
	req.Header.Set("Origin", "http://127.0.0.1:9000") // matches this server's listener
	w := httptest.NewRecorder()
	s.handleSetupComplete(w, req)

	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/" {
		t.Fatalf("status = %d, location = %q", w.Code, w.Header().Get("Location"))
	}
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForEnrolments still blocked after the wizard was completed")
	}
	if s.NeedsSetupWizard() {
		t.Error("wizard still warranted after completion")
	}
}

// TestSetupCardFragment_KeepsWizardActions pins the poll path: a running
// card polled from the wizard must re-render as a wizard card, or the first
// patch would silently swap its forms over to the main site's endpoints.
func TestSetupCardFragment_KeepsWizardActions(t *testing.T) {
	s := setupTestServer(t, map[string]config.Enrolment{"ssh": {Engine: "ssh"}})

	// A wizard card's poll URL carries the base (only a *running* card
	// renders the attribute, so assert on the model the template reads)...
	st, _, err := s.uiEnrolState("ssh")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.buildUIEnrolCard(st, false, setupActionBase).FragmentURL; !strings.Contains(got, "base=setup") {
		t.Fatalf("wizard card poll URL = %q, want the base parameter", got)
	}

	// ...and the fragment endpoint honours it.
	req := httptest.NewRequest("GET", "/ui/fragments/enrol-card?key=ssh&base=setup", nil)
	w := httptest.NewRecorder()
	s.handleUIEnrolCardFragment(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("fragment status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `action="/setup/start"`) {
		t.Errorf("patched card lost the wizard actions: %s", w.Body.String())
	}
}

// TestEnrolCards_HaveDistinctElementIDs pins what makes many cards on one
// page patchable: a shared id would send every patch to the first card.
func TestEnrolCards_HaveDistinctElementIDs(t *testing.T) {
	s := setupTestServer(t, map[string]config.Enrolment{
		"ssh":             {Engine: "ssh"},
		"databricks/prod": {Engine: "databricks"},
	})
	seen := map[string]bool{}
	for _, st := range s.getEnrolRunner().States() {
		id := s.buildUIEnrolCard(st, false, setupActionBase).ElementID
		if id == "" {
			t.Fatalf("%s: empty element id", st.Key)
		}
		if seen[id] {
			t.Errorf("%s: duplicate element id %q", st.Key, id)
		}
		seen[id] = true
	}
}

// TestSetupWizard_GetsScriptedCSP pins the header the wizard's card poll
// depends on. The strict policy refuses datastar's expression compiler, so a
// wizard served under it renders correctly and then silently stops updating —
// exactly the failure a live run surfaced.
func TestSetupWizard_GetsScriptedCSP(t *testing.T) {
	for _, path := range []string{"/setup", "/setup/", "/ui/", "/ui/enrolments/"} {
		if !uiScriptedPath(path) {
			t.Errorf("%s should get the datastar CSP", path)
		}
	}
	// The login view loads no script and must keep the strict policy.
	for _, path := range []string{"/", "/login/ldap", "/api/v1/status"} {
		if uiScriptedPath(path) {
			t.Errorf("%s must not get the relaxed CSP", path)
		}
	}
}

// TestEnrolCard_PromptPausesThePoll pins the fix for a defect the browser
// found: a card that polls every 2s replaces itself wholesale, so while an
// engine waits on a passphrase the refresh wiped the half-typed value (and
// detached the field mid-click, losing the submit entirely).
func TestEnrolCard_PromptPausesThePoll(t *testing.T) {
	if err := uiInitTemplates(); err != nil {
		t.Fatal(err)
	}
	card := uiEnrolCard{
		Key: "ssh", Status: "running", ElementID: "ui-enrol-x",
		FragmentURL: "/ui/fragments/enrol-card?key=ssh", ActionBase: setupActionBase,
	}
	running, err := uiFragment("enrol-card", card)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(running, "data-on-interval") {
		t.Error("a running card should poll for progress")
	}

	card.PromptPending = true
	card.PromptLabel = "Enter passphrase"
	prompting, err := uiFragment("enrol-card", card)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prompting, "data-on-interval") {
		t.Error("a card awaiting input must not poll: the patch would clobber the field")
	}
	if !strings.Contains(prompting, `name="value"`) {
		t.Error("prompting card missing the passphrase field")
	}
}
