package web

import (
	"context"
	"fmt"
)

// Bootstrap mode lets the web SPA drive the one-time mTLS certificate
// bootstrap using the same LDAP/OIDC login machinery the operational login
// uses. The crucial difference is ownership of the resulting token: an
// operational login adopts its token (downscope → s.vault → token file →
// authDone), whereas a bootstrap login must hand the RAW token straight back
// to the caller and adopt nothing.
//
// The bootstrap token is transient and carries pki/sign — precisely the broad
// privilege the least-privilege posture exists to keep off disk and out of
// GET /api/v1/token. So while bootstrap mode is active the token-adoption
// sites divert: no Downscope, no vault.SetToken, no WriteTokenFile, no
// WarnUnrestrictedPolicy, and no authDone signal. It never reaches s.vault,
// the token file, or any log line at any level.
//
// Exactly one BootstrapLogin may wait at a time; a second concurrent call
// fails rather than silently racing for the token.

// BootstrapLogin blocks until a browser-driven login completes and returns the
// resulting RAW Vault token without adopting it. The token is transient and
// carries pki/sign; it must never become the operational token.
func (s *Server) BootstrapLogin(ctx context.Context) (string, error) {
	ch := make(chan string, 1)

	s.bootstrapMu.Lock()
	if s.bootstrapCh != nil {
		s.bootstrapMu.Unlock()
		return "", fmt.Errorf("bootstrap login already in progress")
	}
	s.bootstrapCh = ch
	s.bootstrapMu.Unlock()

	// Clear bootstrap mode on every exit path (delivery, cancellation, or a
	// panic upstack). The identity check keeps a late unwind from clobbering
	// a subsequent BootstrapLogin's channel.
	defer func() {
		s.bootstrapMu.Lock()
		if s.bootstrapCh == ch {
			s.bootstrapCh = nil
		}
		s.bootstrapMu.Unlock()
	}()

	select {
	case token := <-ch:
		return token, nil
	case <-ctx.Done():
		return "", fmt.Errorf("bootstrap login cancelled: %w", ctx.Err())
	}
}

// deliverBootstrapToken hands a raw login token to a waiting BootstrapLogin
// and reports whether it did. A false return means bootstrap mode is not
// active and the caller must fall through to its normal token adoption —
// which must remain byte-for-byte what it was before bootstrap mode existed.
//
// Bootstrap mode is cleared here, under the same lock that reads it, so a
// single BootstrapLogin consumes exactly one token: a second login completing
// before the caller returns takes the ordinary adoption path rather than
// blocking or being dropped.
func (s *Server) deliverBootstrapToken(token string) bool {
	s.bootstrapMu.Lock()
	ch := s.bootstrapCh
	if ch == nil {
		s.bootstrapMu.Unlock()
		return false
	}
	s.bootstrapCh = nil
	s.bootstrapMu.Unlock()

	// Buffered with capacity 1 and only ever sent to once, so this cannot
	// block even if BootstrapLogin has already given up on ctx cancellation.
	ch <- token
	return true
}

// bootstrapActive reports whether a BootstrapLogin is currently waiting for a
// token. Surfaced (without the token) on /api/v1/status so the SPA can show
// the bootstrap login flow instead of the operational one.
func (s *Server) bootstrapActive() bool {
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()
	return s.bootstrapCh != nil
}

// operationalAdoptionAllowed reports whether a browser login may become this
// daemon's operational Vault token.
//
// It may not under certificate auth. There the operational token comes from
// exactly one place — the cert login in authenticateMTLS — and a browser login
// exists solely to bootstrap the certificate. Adopting one would install a
// credential the cert flow never sanctioned.
//
// This is a security boundary, not tidiness. deliverBootstrapToken hands the
// token to a single waiter and clears bootstrap mode, but LoginTracker.GetStatus
// returns a *copy* of the session and the session is cleared only after the
// divert, so two overlapping polls of the (unauthenticated, un-CSRF'd)
// /auth/ldap/status can both observe the same authenticated session holding the
// same raw token. The first is diverted; without this guard the second falls
// through to the adoption path, where Downscope is a no-op under the default
// (inactive) constraint — putting the raw pki/sign bootstrap token on the shared
// client, in the token file, and behind GET /api/v1/token. Gating on the
// configured method rather than on bootstrap-mode-still-being-active closes that
// race, because the method does not change while the daemon runs.
func (s *Server) operationalAdoptionAllowed() bool {
	return s.bootstrapMethod == ""
}
