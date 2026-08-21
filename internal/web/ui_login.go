// The login surface: the server-rendered pages that stand in front of the
// main site at "/". It is deliberately standalone — no navigation, no status
// bar, and (unlike every other page) no JavaScript at all: the waiting states
// advance with a meta refresh, so a browser with scripting disabled can still
// complete a login.
//
// "/" is the single entry point. It renders the login card when the daemon
// holds no token, and otherwise routes the user onward — to the first-run
// enrolment wizard when nothing has been enrolled yet, else to the main site.
//
// Each auth method gets the flow it needs: OIDC redirects through Vault to the
// callback the daemon already registers, LDAP posts credentials and then polls
// a progress page for MFA, token accepts a pasted token, and certificate auth
// (mtls, mtls+tpm, mtls+os) shows a waiting card — with one exception, the
// one-time certificate bootstrap, which borrows whichever of the OIDC or LDAP
// cards vault.mtls.bootstrap_method names.
package web

import (
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
)

// loginCookieName carries the LDAP login's server-side session id between the
// credential POST and the progress page. A cookie rather than a URL segment:
// the id is a bearer secret for that in-flight login, and a URL would put it
// in the browser's history and any Referer the operator's own login_text
// markdown might trigger. It is not an authentication cookie — the daemon's
// session is its Vault token, held server-side — so it is scoped to /login
// and cleared as soon as the login reaches a terminal state.
const loginCookieName = "dotvault_login"

// loginPollSeconds is the meta-refresh cadence of the login waiting states,
// a cadence brisk enough that an approved push feels immediate.
const loginPollSeconds = 2

// bootstrapNoticeHTML frames the reused OIDC/LDAP card during the one-time
// mTLS certificate bootstrap: the credential prompt below it is an enrolment,
// not a recurring sign-in. Prepended to the operator's login_text so the
// bootstrap path renders the ordinary cards verbatim rather than forking them.
const bootstrapNoticeHTML = `<h2>One-time certificate enrolment</h2>` +
	`<p>This host signs in to Vault with a client certificate. Authenticate ` +
	`once now so dotvault can issue that certificate — after this, sign-in is ` +
	`automatic and you will not be asked for a credential again.</p>`

// uiStandaloneData is the shell every chrome-less page embeds.
type uiStandaloneData struct {
	Title string
	// Refresh, when non-zero, emits a meta refresh after that many seconds.
	Refresh int
	// Datastar loads the browser runtime. The login pages leave it false;
	// the wizard needs it for its running cards.
	Datastar bool
	Error    string
}

// uiLoginData is the login card's view model. Method is the *card* to render,
// which under a certificate bootstrap is the bootstrap credential method
// rather than the daemon's configured one.
type uiLoginData struct {
	uiStandaloneData
	Method     string
	CustomText template.HTML
	Issuing    bool
}

// uiLoginLDAPData is the post-submit LDAP card: an MFA push awaiting approval,
// or a passcode prompt.
type uiLoginLDAPData struct {
	uiStandaloneData
	Phase string // "" (awaiting push approval) or "totp"
}

// signalAuthDone releases a WaitForAuth without blocking if nobody is waiting.
func (s *Server) signalAuthDone() {
	select {
	case s.authDone <- struct{}{}:
	default:
	}
}

// consumeLoginToken is the single token-adoption path shared by every
// browser login flow (OIDC callback and LDAP alike). It reports whether the
// token was diverted to a waiting certificate bootstrap rather than adopted.
//
// The ordering is load-bearing and predates this file: a bootstrap token
// carries pki/sign and must reach the waiting BootstrapLogin raw — no
// Downscope, no SetToken, no token file, no authDone — because it is consumed
// immediately to mint a certificate and must never become the operational
// credential. Under certificate auth a browser login is *only* ever a
// bootstrap, so a second login arriving after the bootstrap was consumed is
// dropped rather than adopted (operationalAdoptionAllowed).
func (s *Server) consumeLoginToken(ctx context.Context, raw string) (bootstrapped bool, err error) {
	if s.deliverBootstrapToken(raw) {
		return true, nil
	}
	if !s.operationalAdoptionAllowed() {
		slog.Debug("ignoring already-consumed bootstrap login")
		return true, nil
	}

	token, err := auth.Downscope(ctx, s.vault, raw, s.policyConstraint())
	if err != nil {
		return false, err
	}
	s.vault.SetToken(token)
	auth.WarnUnrestrictedPolicy(s.policyConstraint())
	if err := auth.WriteTokenFile(s.tokenFilePath, token, s.sealToken); err != nil {
		slog.Warn("failed to write token file", "error", err)
	}
	s.signalAuthDone()
	return false, nil
}

// requireSameOrigin is the CSRF control for every browser-driven POST on this
// daemon, login included. Browsers attach an Origin header to all POSTs, so a
// present header naming this daemon's own origin is the one shape a
// same-origin form submit can have; anything else — a cross-site form, or a
// request with no Origin at all — is refused.
//
// Login POSTs need this as much as the authenticated ones do: without it a
// hostile page could post its own Vault token to /login/token and have the
// daemon adopt an attacker-chosen identity, syncing that attacker's secrets
// onto this machine and lending the token back out over /api/v1/token.
func (s *Server) requireSameOrigin(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || !s.originAllowed(origin) {
		writeError(w, "cross-site requests are not allowed", http.StatusForbidden)
		return false
	}
	return true
}

// setLoginCookie / clearLoginCookie manage the in-flight LDAP session id.
func setLoginCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     loginCookieName,
		Value:    sessionID,
		Path:     "/login",
		HttpOnly: true,
		// Strict, not Lax. The LDAP progress page is a GET that adopts the
		// token once Vault authenticates, so it cannot carry an Origin check
		// of its own; under Lax the cookie would still ride a cross-site
		// top-level navigation, letting a hostile page decide the moment the
		// user's own in-flight login gets adopted. Every legitimate way to
		// reach the page is a same-site redirect or meta-refresh, so Strict
		// costs nothing.
		SameSite: http.SameSiteStrictMode,
	})
}

func clearLoginCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     loginCookieName,
		Value:    "",
		Path:     "/login",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// handleRoot is the entry point. Unauthenticated it renders the login card;
// authenticated it sends the user on to the first-run wizard or the main site.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if !s.uiAuthenticated() {
		s.renderLogin(w, r, "")
		return
	}
	if s.NeedsSetupWizard() {
		http.Redirect(w, r, "/setup/", http.StatusSeeOther)
		return
	}
	// Landing on the main site is the signal that the user is done with
	// first-run setup, whether they finished it, skipped it, or never needed
	// it. Releasing the wait here (idempotent) is what keeps a daemon from
	// blocking on a wizard nobody is going to complete.
	s.completeEnrolments()
	http.Redirect(w, r, "/ui/", http.StatusSeeOther)
}

// renderLogin draws the login card for the configured auth method, or — while
// a certificate bootstrap is waiting — for the bootstrap credential method.
func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, errMsg string) {
	data := uiLoginData{
		uiStandaloneData: uiStandaloneData{Title: "Sign in", Error: errMsg},
		Method:           s.authMethod,
		CustomText:       template.HTML(s.loginTextHTML),
	}

	if s.authMethod == "mtls" {
		if bm := s.bootstrapMethod; s.bootstrapActive() && (bm == "oidc" || bm == "ldap") {
			// Reuse the ordinary credential card, framed as an enrolment.
			data.Method = bm
			data.CustomText = template.HTML(bootstrapNoticeHTML + s.loginTextHTML)
		} else {
			// Nothing for the user to do: either the daemon is signing in
			// with its certificate, or the bootstrap credential flow is done
			// and issuance is in flight. Both resolve without interaction,
			// so poll for the transition.
			data.Refresh = loginPollSeconds
			data.Issuing = r.URL.Query().Get("issuing") == "1"
		}
	}
	s.uiRenderStandalone(w, "login", data)
}

// handleLoginLDAP starts an LDAP login and hands off to the progress page.
func (s *Server) handleLoginLDAP(w http.ResponseWriter, r *http.Request) {
	if !s.requireSameOrigin(w, r) {
		return
	}
	if s.login == nil {
		writeError(w, "login not available", http.StatusServiceUnavailable)
		return
	}
	username := uiFormValue(r, "username")
	password := r.PostFormValue("password")
	if username == "" || password == "" {
		s.renderLogin(w, r, "username and password required")
		return
	}

	sessionID, err := generateSessionID()
	if err != nil {
		slog.Error("failed to generate session ID", "error", err)
		s.renderLogin(w, r, "internal error")
		return
	}
	s.login.StartLogin(sessionID, s.loginMount("ldap"), username, password)
	setLoginCookie(w, sessionID)
	http.Redirect(w, r, "/login/ldap", http.StatusSeeOther)
}

// handleLoginLDAPProgress renders the state of the in-flight LDAP login and
// adopts its token once Vault authenticates. It is the page the meta refresh
// reloads, so it is also where a push approval is noticed.
func (s *Server) handleLoginLDAPProgress(w http.ResponseWriter, r *http.Request) {
	if s.uiAuthenticated() {
		clearLoginCookie(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	cookie, err := r.Cookie(loginCookieName)
	if err != nil || cookie.Value == "" || s.login == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	status := s.login.GetStatus(cookie.Value)
	if status == nil {
		clearLoginCookie(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	switch status.State {
	case "authenticated":
		if status.Token == "" {
			// Authenticated with the token already consumed by an earlier
			// poll: nothing left to adopt, so fall through to the entry
			// point, which reflects whatever that adoption achieved.
			s.login.Clear(cookie.Value)
			clearLoginCookie(w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		bootstrapped, err := s.consumeLoginToken(r.Context(), status.Token)
		s.login.Clear(cookie.Value)
		clearLoginCookie(w)
		if err != nil {
			slog.Error("downscoping token to least privilege failed", "error", err)
			s.renderLogin(w, r, "authentication failed during token downscoping")
			return
		}
		if bootstrapped {
			slog.Info("LDAP bootstrap login successful via web UI")
			http.Redirect(w, r, "/?issuing=1", http.StatusSeeOther)
			return
		}
		slog.Info("LDAP authentication successful via web UI")
		http.Redirect(w, r, "/", http.StatusSeeOther)

	case "failed":
		msg := status.Error
		if msg == "" {
			msg = "Login failed"
		}
		s.login.Clear(cookie.Value)
		clearLoginCookie(w)
		s.renderLogin(w, r, msg)

	case "mfa_required":
		data := uiLoginLDAPData{
			uiStandaloneData: uiStandaloneData{Title: "Sign in", Error: status.Error},
		}
		if len(status.MFAMethods) > 0 && status.MFAMethods[0].UsesPasscode {
			// A passcode prompt must not auto-refresh: it would wipe what
			// the user is typing. The form submit drives this one forward.
			data.Phase = "totp"
		} else {
			data.Refresh = loginPollSeconds
		}
		s.uiRenderStandalone(w, "login_ldap", data)

	default: // pending
		s.uiRenderStandalone(w, "login_ldap", uiLoginLDAPData{
			uiStandaloneData: uiStandaloneData{Title: "Sign in", Refresh: loginPollSeconds},
		})
	}
}

// handleLoginLDAPTOTP submits an MFA passcode and returns to the progress page.
func (s *Server) handleLoginLDAPTOTP(w http.ResponseWriter, r *http.Request) {
	if !s.requireSameOrigin(w, r) {
		return
	}
	cookie, err := r.Cookie(loginCookieName)
	if err != nil || cookie.Value == "" || s.login == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	passcode := uiFormValue(r, "passcode")
	if passcode == "" {
		http.Redirect(w, r, "/login/ldap", http.StatusSeeOther)
		return
	}
	status := s.login.GetStatus(cookie.Value)
	if status == nil {
		clearLoginCookie(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if status.State != "mfa_required" || len(status.MFAMethods) == 0 || !status.MFAMethods[0].UsesPasscode {
		// Not the phase this form belongs to (a stale resubmit); let the
		// progress page render whatever the real state is.
		http.Redirect(w, r, "/login/ldap", http.StatusSeeOther)
		return
	}
	s.login.SubmitTOTP(cookie.Value, passcode)
	http.Redirect(w, r, "/login/ldap", http.StatusSeeOther)
}

// handleLoginToken adopts a pasted Vault token after validating it.
func (s *Server) handleLoginToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireSameOrigin(w, r) {
		return
	}
	// Under certificate auth the operational token comes from the cert login
	// alone — pasting one here would install a credential the certificate
	// flow never sanctioned. The card is never rendered under mtls; this
	// closes the direct-POST path.
	if !s.operationalAdoptionAllowed() {
		writeError(w, "token login is not available under certificate authentication: this daemon obtains its Vault token from its client certificate", http.StatusForbidden)
		return
	}
	token := uiFormValue(r, "token")
	if token == "" {
		s.renderLogin(w, r, "token required")
		return
	}

	// Validate before keeping it, preserving any existing token on failure.
	prevToken := s.vault.Token()
	s.vault.SetToken(token)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, err := s.vault.LookupSelf(ctx); err != nil {
		s.vault.SetToken(prevToken)
		s.renderLogin(w, r, "invalid token")
		return
	}
	if err := auth.WriteTokenFile(s.tokenFilePath, token, s.sealToken); err != nil {
		slog.Warn("failed to write token file", "error", err)
	}
	slog.Info("token authentication successful via web UI")
	s.signalAuthDone()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
