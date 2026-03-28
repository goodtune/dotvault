package auth

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
)

// LoginStatus represents the current state of an async login attempt.
type LoginStatus struct {
	State      string             `json:"state"`
	Token      string             `json:"-"`
	Error      string             `json:"error,omitempty"`
	MFAMethods []vault.MFAMethod  `json:"mfa_methods,omitempty"`
}

// loginSession holds internal state for an in-progress login attempt.
type loginSession struct {
	status       *LoginStatus
	mfaRequestID string
	mfaMethodID  string
	totpCh       chan string
	cancel       context.CancelFunc
	completedAt  time.Time // set when session reaches a terminal state
}

// LoginTracker manages async login attempts keyed by session ID.
type LoginTracker struct {
	mu       sync.Mutex
	sessions map[string]*loginSession
	vault    *vault.Client
}

// NewLoginTracker creates a new LoginTracker.
func NewLoginTracker(vc *vault.Client) *LoginTracker {
	lt := &LoginTracker{
		sessions: make(map[string]*loginSession),
		vault:    vc,
	}
	go lt.gcLoop()
	return lt
}

// gcLoop periodically purges sessions that have been in a terminal state
// for more than 10 minutes, preventing unbounded memory growth from
// abandoned sessions.
func (lt *LoginTracker) gcLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		lt.mu.Lock()
		now := time.Now()
		for id, s := range lt.sessions {
			if !s.completedAt.IsZero() && now.Sub(s.completedAt) > 10*time.Minute {
				s.cancel()
				delete(lt.sessions, id)
			}
		}
		lt.mu.Unlock()
	}
}

// StartLogin begins an async LDAP login attempt. The login runs in a
// background goroutine with a 5-minute timeout. Poll GetStatus to
// check progress.
func (lt *LoginTracker) StartLogin(sessionID, mount, username, password string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)

	session := &loginSession{
		status: &LoginStatus{State: "pending"},
		totpCh: make(chan string, 1),
		cancel: cancel,
	}

	lt.mu.Lock()
	lt.sessions[sessionID] = session
	lt.mu.Unlock()

	go lt.runLogin(ctx, session, mount, username, password)
}

func (lt *LoginTracker) runLogin(ctx context.Context, session *loginSession, mount, username, password string) {
	defer session.cancel()

	result, err := lt.vault.LoginLDAP(ctx, mount, username, password)
	if err != nil {
		lt.mu.Lock()
		session.status.State = "failed"
		session.status.Error = err.Error()
		session.completedAt = time.Now()
		lt.mu.Unlock()
		return
	}

	// No MFA — done.
	if !result.MFARequired {
		lt.mu.Lock()
		session.status.Token = result.Token
		session.status.State = "authenticated"
		session.completedAt = time.Now()
		lt.mu.Unlock()
		return
	}

	// MFA required.
	if len(result.MFAMethods) == 0 {
		lt.mu.Lock()
		session.status.State = "failed"
		session.status.Error = "MFA required but no methods available"
		session.completedAt = time.Now()
		lt.mu.Unlock()
		return
	}

	method := result.MFAMethods[0]

	lt.mu.Lock()
	session.status.State = "mfa_required"
	session.status.MFAMethods = result.MFAMethods
	session.mfaRequestID = result.MFARequestID
	session.mfaMethodID = method.ID
	lt.mu.Unlock()

	if method.UsesPasscode {
		// TOTP — wait for passcode submission, allow retries.
		lt.waitForTOTP(ctx, session, result.MFARequestID, method.ID)
	} else {
		// Push (Duo) — call ValidateMFA which blocks until approved.
		slog.Info("waiting for MFA push approval")
		token, err := lt.vault.ValidateMFA(ctx, result.MFARequestID, method.ID, "")
		if err != nil {
			lt.mu.Lock()
			session.status.State = "failed"
			session.status.Error = err.Error()
			session.completedAt = time.Now()
			lt.mu.Unlock()
			return
		}
		lt.mu.Lock()
		session.status.Token = token
		session.status.State = "authenticated"
		session.completedAt = time.Now()
		lt.mu.Unlock()
	}
}

func (lt *LoginTracker) waitForTOTP(ctx context.Context, session *loginSession, mfaRequestID, methodID string) {
	for {
		select {
		case passcode := <-session.totpCh:
			token, err := lt.vault.ValidateMFA(ctx, mfaRequestID, methodID, passcode)
			if err != nil {
				slog.Warn("TOTP validation failed", "error", err)
				lt.mu.Lock()
				session.status.State = "mfa_required"
				session.status.Error = err.Error()
				lt.mu.Unlock()
				continue
			}
			lt.mu.Lock()
			session.status.Token = token
			session.status.State = "authenticated"
			session.status.Error = ""
			session.completedAt = time.Now()
			lt.mu.Unlock()
			return
		case <-ctx.Done():
			lt.mu.Lock()
			session.status.State = "failed"
			session.status.Error = "login timed out"
			session.completedAt = time.Now()
			lt.mu.Unlock()
			return
		}
	}
}

// SubmitTOTP submits a TOTP passcode for an in-progress MFA login.
func (lt *LoginTracker) SubmitTOTP(sessionID, passcode string) {
	lt.mu.Lock()
	session, ok := lt.sessions[sessionID]
	lt.mu.Unlock()
	if !ok {
		return
	}
	select {
	case session.totpCh <- passcode:
	default:
	}
}

// GetStatus returns the current login status for a session.
// Returns nil if the session does not exist.
func (lt *LoginTracker) GetStatus(sessionID string) *LoginStatus {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	session, ok := lt.sessions[sessionID]
	if !ok {
		return nil
	}
	// Return a copy so callers can read without holding the lock.
	s := *session.status
	return &s
}

// Clear removes a completed login session.
func (lt *LoginTracker) Clear(sessionID string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if session, ok := lt.sessions[sessionID]; ok {
		session.cancel()
		delete(lt.sessions, sessionID)
	}
}
