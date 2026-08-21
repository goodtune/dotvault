package web

import (
	"net/http"
	"net/http/httptest"
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

	// Skipping everything completes nothing, but it addresses everything:
	// the user was shown each enrolment and declined it, so there is nothing
	// left for the wizard to do and it must stand aside on its own.
	r = newRunner()
	for _, key := range []string{"ssh", "gh"} {
		if err := r.Skip(key); err != nil {
			t.Fatalf("Skip(%s): %v", key, err)
		}
	}
	if r.NeedsWizard() {
		t.Error("everything skipped is everything addressed: the wizard has nothing left to offer")
	}
	// The dismissal latch still covers the other route out: leaving with
	// enrolments genuinely outstanding.
	r = newRunner()
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
		`action="/setup/complete"`, // with work outstanding, leaving is a POST
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

// TestSetupExitLink_DismissesAndReleases pins the wizard's exit control now
// that it is a plain link to "/" rather than a form POST: following it must
// let the daemon proceed and land the user on the main site.
func TestSetupExitLink_DismissesAndReleases(t *testing.T) {
	s := setupTestServer(t, map[string]config.Enrolment{"ssh": {Engine: "ssh"}})

	waited := make(chan struct{})
	go func() { s.WaitForEnrolments(); close(waited) }()

	// Skipping is what a user leaving a wizard with nothing enrolled has
	// done; the link then has to take them out rather than loop them back.
	if err := s.getEnrolRunner().Skip("ssh"); err != nil {
		t.Fatalf("Skip: %v", err)
	}
	w := httptest.NewRecorder()
	s.handleRoot(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/" {
		t.Fatalf("following the exit link: status = %d, location = %q; want a redirect to /ui/", w.Code, w.Header().Get("Location"))
	}
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForEnrolments still blocked after the wizard was left")
	}
	if s.NeedsSetupWizard() {
		t.Error("wizard still warranted after the user left it")
	}
}

// TestSetupFooter_FollowsTheWorkAndNeverGoesStale pins the fix for a wizard
// the user could not leave. The footer used to render once with the page as a
// submit button carrying {{if .AnyRunning}}disabled{{end}}, while only the
// card was re-patched by the poll — so when the last enrolment finished, the
// button stayed disabled and still read "Skip remaining", stranding the user
// on a completed wizard.
//
// It also pins why the two states are different elements. With work still
// outstanding, leaving means abandoning it, so the control stays a POST: a
// link to "/" would be answered by handleRoot with a redirect straight back
// to the wizard, making a control labelled "Skip remaining" a no-op loop.
// With everything addressed there is nothing to abandon and it is a link.
func TestSetupFooter_FollowsTheWorkAndNeverGoesStale(t *testing.T) {
	s := setupTestServer(t, map[string]config.Enrolment{"ssh": {Engine: "ssh"}})

	w := httptest.NewRecorder()
	s.handleSetup(w, httptest.NewRequest("GET", "/setup/", nil))
	body := w.Body.String()
	if !strings.Contains(body, `action="/setup/complete"`) {
		t.Errorf("with an enrolment outstanding the footer must be a dismissing POST; body = %s", body)
	}
	if !strings.Contains(body, "Skip remaining") {
		t.Error("with an enrolment outstanding the footer should offer to skip the rest")
	}
	if strings.Contains(body, `class="enrol-continue-btn" disabled`) {
		t.Error("footer button is disabled again; that is exactly what went stale")
	}

	// Completing the work flips it to a plain link out.
	s.getEnrolRunner().MarkComplete("ssh")
	frag, err := uiFragment("setup-footer", s.setupFooterData())
	if err != nil {
		t.Fatalf("render footer fragment: %v", err)
	}
	if !strings.Contains(frag, `id="setup-footer"`) {
		t.Error("footer fragment lacks the id datastar patches it by")
	}
	if !strings.Contains(frag, `href="/"`) {
		t.Errorf("with nothing outstanding the footer must be a link to the root; fragment = %s", frag)
	}
	if !strings.Contains(frag, "Continue to Dashboard") || strings.Contains(frag, "Skip remaining") {
		t.Errorf("footer did not follow the enrolment to completion; fragment = %s", frag)
	}
}

// TestSetupExitPOST_DismissesWithWorkOutstanding covers the branch three
// reviewers independently identified as the one that strands a user: an
// enrolment that is pending, running, or repeatedly failing keeps the wizard
// warranted, so leaving has to be an action that dismisses rather than a link
// handleRoot would bounce back.
func TestSetupExitPOST_DismissesWithWorkOutstanding(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(r *EnrolmentRunner)
	}{
		{"pending", func(*EnrolmentRunner) {}},
		{"failed", func(r *EnrolmentRunner) {
			st := r.states["ssh"]
			st.mu.Lock()
			st.status = "failed"
			st.errMsg = "engine exploded"
			st.mu.Unlock()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := setupTestServer(t, map[string]config.Enrolment{"ssh": {Engine: "ssh"}})
			tc.setup(s.getEnrolRunner())

			// The wizard is genuinely warranted, so a bare link out would loop.
			if !s.NeedsSetupWizard() {
				t.Fatalf("precondition: wizard should still be warranted in %s state", tc.name)
			}
			w := httptest.NewRecorder()
			s.handleRoot(w, httptest.NewRequest("GET", "/", nil))
			if got := w.Header().Get("Location"); got != "/setup/" {
				t.Fatalf("precondition: GET / went to %q, want a bounce to /setup/", got)
			}

			// The footer's POST is what actually gets the user out.
			waited := make(chan struct{})
			go func() { s.WaitForEnrolments(); close(waited) }()

			req := postForm(t, "/setup/complete", nil)
			req.Header.Set("Origin", "http://127.0.0.1:9000")
			w2 := httptest.NewRecorder()
			s.handleSetupComplete(w2, req)
			if w2.Code != http.StatusSeeOther || w2.Header().Get("Location") != "/ui/" {
				t.Fatalf("status = %d, location = %q; want a redirect to /ui/", w2.Code, w2.Header().Get("Location"))
			}
			select {
			case <-waited:
			case <-time.After(2 * time.Second):
				t.Fatal("WaitForEnrolments still blocked after the wizard was left")
			}
			if s.NeedsSetupWizard() {
				t.Error("wizard still warranted after the user left it")
			}
		})
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

	// uiScriptedPath is only half the guarantee: assert the header the
	// middleware actually emits, so rewiring the predicate's call site
	// cannot pass this test while serving the wrong policy.
	_, ts := uiTestServer(t)
	resp := uiGet(t, ts, "/setup/")
	defer resp.Body.Close()
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "'unsafe-eval'") {
		t.Errorf("/setup/ response CSP = %q, want the datastar-compatible policy", csp)
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

// TestUIPage_ReleasesTheStartupGate pins the fix for a deadlock that
// requireUIPage — not handleRoot — has to close. The daemon blocks on
// WaitForEnrolments, and only a page that dismisses the wizard releases it.
// A browser reloading a bookmarked /ui/ page after a daemon restart never
// touches "/", so releasing solely there left the user browsing a working
// site while the sync engine never started.
func TestUIPage_ReleasesTheStartupGate(t *testing.T) {
	s := setupTestServer(t, map[string]config.Enrolment{"ssh": {Engine: "ssh"}})

	waited := make(chan struct{})
	go func() { s.WaitForEnrolments(); close(waited) }()

	select {
	case <-waited:
		t.Fatal("startup gate released before any page was served")
	case <-time.After(50 * time.Millisecond):
	}

	// A main-site page GET, reached directly — no visit to "/" first.
	w := httptest.NewRecorder()
	if !s.requireUIPage(w, httptest.NewRequest("GET", "/ui/secrets/", nil)) {
		t.Fatalf("requireUIPage refused an authenticated request: status = %d", w.Code)
	}

	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("serving a main-site page did not release the startup gate")
	}
}

// TestNeedsWizard_IgnoresUnattendedEnrolments pins the copy engine's
// exclusion from the wizard decision, in both directions.
//
// The bug this closes: a copy enrolment needs no human and completes on its
// own, often before the user has seen anything. Counted as prior progress it
// satisfied the "something is already enrolled" test and suppressed the
// wizard for the interactive enrolments that genuinely needed one — so a
// fresh user with a copy enrolment configured never saw setup at all.
func TestNeedsWizard_IgnoresUnattendedEnrolments(t *testing.T) {
	// A completed copy enrolment must not stand in for the user having been
	// through setup: the interactive enrolment beside it still needs one.
	r := NewEnrolmentRunner(map[string]config.Enrolment{
		"mirror": {Engine: "copy"},
		"gh":     {Engine: "github"},
	})
	r.MarkComplete("mirror")
	if !r.NeedsWizard() {
		t.Error("a completed copy enrolment suppressed the wizard; an interactive enrolment is still pending")
	}

	// Nor may a pending one: it gives the user nothing to do, so on its own
	// it cannot justify a wizard.
	if NewEnrolmentRunner(map[string]config.Enrolment{"mirror": {Engine: "copy"}}).NeedsWizard() {
		t.Error("copy enrolments alone must not trigger the wizard")
	}

	// And an interactive enrolment beside it still decides normally.
	r = NewEnrolmentRunner(map[string]config.Enrolment{
		"mirror": {Engine: "copy"},
		"gh":     {Engine: "github"},
	})
	if !r.NeedsWizard() {
		t.Error("nothing interactive enrolled yet: wizard should appear")
	}
	r.MarkComplete("gh")
	if r.NeedsWizard() {
		t.Error("the interactive enrolment is complete: wizard must step aside")
	}
}

// TestWait_CopyOnlyConfigDoesNotBlockStartup pins the more consequential half
// of the unattended exclusion. Wait() gates daemon startup — the sync engine
// included — behind the wizard being dismissed. A host configured with only
// copy enrolments used to park there until a human opened the web UI, which on
// an unattended host is never; it must now proceed on its own.
func TestWait_CopyOnlyConfigDoesNotBlockStartup(t *testing.T) {
	r := NewEnrolmentRunner(map[string]config.Enrolment{"mirror": {Engine: "copy"}})

	returned := make(chan struct{})
	go func() { r.Wait(); close(returned) }()

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("Wait() blocked on a copy-only config; the daemon would never start syncing")
	}
}

// TestNeedsWizard_UnattendedExclusionIsUnconditional records two edges a
// future reader will question. A *failed* copy enrolment is still skipped —
// it is unattended whatever became of it, and a human in the wizard could do
// nothing about it — and an unknown engine keeps its existing treatment,
// since "unattended" is a property of a registered engine and there is none.
func TestNeedsWizard_UnattendedExclusionIsUnconditional(t *testing.T) {
	r := NewEnrolmentRunner(map[string]config.Enrolment{"mirror": {Engine: "copy"}})
	// No exported way to fail an enrolment without running it; this test is
	// in-package, so set the state the engine would have left behind.
	st := r.states["mirror"]
	st.mu.Lock()
	st.status = "failed"
	st.errMsg = "source secret not found"
	st.mu.Unlock()
	if r.NeedsWizard() {
		t.Error("a failed copy enrolment raised the wizard; there is nothing a user could do in it")
	}

	// Unknown engines are not runnable and were never affected by the
	// exclusion; a copy enrolment beside one does not change that.
	r = NewEnrolmentRunner(map[string]config.Enrolment{
		"mirror": {Engine: "copy"},
		"x":      {Engine: "nope"},
	})
	if r.NeedsWizard() {
		t.Error("neither an unattended nor an unrunnable enrolment can justify a wizard")
	}
}

// TestSetupWizard_RendersUnattendedCardsWithHelpText guards the boundary of
// the unattended exclusion. It applies to whether the wizard *appears*, and
// to nothing else: once the wizard is up, a copy enrolment is an ordinary
// card and its configured help_text renders — as markdown — exactly like any
// other engine's. Narrowing the exclusion into the render loop would drop it
// silently, since a missing card looks like a card for an enrolment that
// simply is not configured.
func TestSetupWizard_RendersUnattendedCardsWithHelpText(t *testing.T) {
	s := setupTestServer(t, map[string]config.Enrolment{
		"mirror": {Engine: "copy", HelpText: "Mirrors the **team** secret."},
		"ssh":    {Engine: "ssh", HelpText: "Generates a key pair."},
	})

	w := httptest.NewRecorder()
	s.handleSetup(w, httptest.NewRequest("GET", "/setup/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want 200 (the ssh enrolment warrants a wizard)", w.Code)
	}
	body := w.Body.String()

	if !strings.Contains(body, "Mirrors the") {
		t.Error("copy enrolment's help_text is missing from the wizard")
	}
	if !strings.Contains(body, "<strong>team</strong>") {
		t.Error("copy enrolment's help_text was not rendered as markdown")
	}
	if !strings.Contains(body, "Generates a key pair") {
		t.Error("interactive enrolment's help_text is missing from the wizard")
	}
}

// TestSetupCardFragment_PatchesFooterToo pins the mechanism that keeps the
// exit control honest in a live page. The card's own poll stops once the
// enrolment reaches a terminal state, so the patch that observes completion
// is the last one the page will ever get — if the footer does not ride along
// with it, nothing else will ever correct it.
func TestSetupCardFragment_PatchesFooterToo(t *testing.T) {
	s := setupTestServer(t, map[string]config.Enrolment{"ssh": {Engine: "ssh"}})
	s.getEnrolRunner().MarkComplete("ssh")

	w := httptest.NewRecorder()
	s.handleUIEnrolCardFragment(w, httptest.NewRequest("GET", "/ui/fragments/enrol-card?key=ssh&base=setup", nil))
	body := w.Body.String()
	if !strings.Contains(body, "setup-footer") {
		t.Fatalf("wizard card patch does not carry the footer; body = %s", body)
	}
	if !strings.Contains(body, "Continue to Dashboard") || strings.Contains(body, "Skip remaining") {
		t.Errorf("patched footer did not follow the enrolment to completion; body = %s", body)
	}

	// The main site has no such footer; sending one would patch an element
	// that does not exist there.
	w2 := httptest.NewRecorder()
	s.handleUIEnrolCardFragment(w2, httptest.NewRequest("GET", "/ui/fragments/enrol-card?key=ssh", nil))
	if strings.Contains(w2.Body.String(), "setup-footer") {
		t.Error("main-site card patch carried the wizard footer")
	}
}
