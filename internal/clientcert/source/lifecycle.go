package source

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/clientcert"
	"github.com/goodtune/dotvault/internal/tokengate"
)

// LifecycleWirer is implemented by every Source this package returns that
// signs: the ephemeral source and the held-with-fallback source. Both setters
// are safe to call while the source is in use, because the daemon builds the
// source before authentication and the lifecycle manager only after it. A nil
// argument is ignored. The held source alone signs nothing and does not
// implement it.
//
// The seams are tokengate's, shared with the SSH agent's backend;
// *auth.LifecycleManager satisfies both.
type LifecycleWirer interface {
	SetReauthGate(tokengate.Gate)
	SetReauthReporter(tokengate.Reporter)
}

func (e *ephemeral) SetReauthGate(g tokengate.Gate)         { e.gate.Set(g) }
func (e *ephemeral) SetReauthReporter(r tokengate.Reporter) { e.reporter.Set(r) }

// reportRejection tells the wired reporter about err when it is a token
// rejection (a 403 or an expired token), and does nothing otherwise. The
// classification is auth.IsTokenRejected, the predicate NotifyRejected itself
// applies, so the two cannot disagree; filtering here as well keeps a 5xx or
// a transport failure from ever reaching the lifecycle manager.
func (e *ephemeral) reportRejection(err error) {
	if err == nil || !auth.IsTokenRejected(err) {
		return
	}
	if e.reporter.Get() == nil {
		return
	}
	slog.Debug("client certificate: reporting a token rejection to the token lifecycle manager", "error", err)
	e.reporter.Report(err)
}

// awaitReplacement returns the token flight f should sign with. When no
// replacement is in flight that is the token Current read. When one is, it
// waits for it to clear — bounded by reauthWait, which never exceeds the
// sign's own timeout — and re-reads the client's token, since the value read
// before the wait is the one being replaced. A replacement that does not
// clear in time is ErrReauthInProgress: transient, and not a Vault verdict.
func (e *ephemeral) awaitReplacement(ctx context.Context, f *flight) (string, error) {
	g := e.gate.Get()
	if g == nil || !g.NeedsReauth() {
		return f.token, nil
	}
	ctx, cancel := context.WithTimeout(ctx, e.reauthWait)
	defer cancel()
	if err := tokengate.Wait(ctx, g); err != nil {
		return "", fmt.Errorf("%w: %w", clientcert.ErrReauthInProgress, err)
	}
	token := e.s.Token()
	if token == "" {
		return "", clientcert.ErrNoToken
	}
	if token != f.token {
		h := sha256.Sum256([]byte(token))
		e.mu.Lock()
		f.token, f.tokenHash = token, h
		e.lastToken = h
		e.mu.Unlock()
	}
	return token, nil
}

// SetReauthGate forwards to the ephemeral source: the held source makes no
// Vault call to gate.
func (f *fallback) SetReauthGate(g tokengate.Gate) {
	if w, ok := f.eph.(LifecycleWirer); ok {
		w.SetReauthGate(g)
	}
}

// SetReauthReporter forwards to the ephemeral source, as SetReauthGate does.
func (f *fallback) SetReauthReporter(r tokengate.Reporter) {
	if w, ok := f.eph.(LifecycleWirer); ok {
		w.SetReauthReporter(r)
	}
}

var (
	_ LifecycleWirer = (*ephemeral)(nil)
	_ LifecycleWirer = (*fallback)(nil)
)
