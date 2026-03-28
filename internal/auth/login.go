package auth

import "github.com/goodtune/dotvault/internal/vault"

// LoginTracker tracks the state of an interactive login flow.
// Stub — will be replaced by the full implementation in Task 2.
type LoginTracker struct{}

// NewLoginTracker creates a new LoginTracker.
func NewLoginTracker(vc *vault.Client) *LoginTracker {
	return &LoginTracker{}
}
