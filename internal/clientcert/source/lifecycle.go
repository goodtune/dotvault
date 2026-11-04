package source

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/clientcert"
)

// ReauthGate lets a signing source observe the daemon's token lifecycle, so a
// sign that would start while the token is being replaced waits for the
// replacement instead of presenting the token Vault just rejected.
// *auth.LifecycleManager satisfies it; NeedsReauth is its gate, true across a
// replacement whether or not the replacement succeeds. The SSH agent consumes
// the same seam (agent.ReauthGate).
type ReauthGate interface {
	NeedsReauth() bool
}

// RejectionReporter lets a signing source report a token rejection it saw
// before the lifecycle manager's own poll did, so recovery starts now rather
// than at the next check. *auth.LifecycleManager satisfies it via
// NotifyRejected, which rate-limits what it is told. The SSH agent consumes
// the same seam (agent.RejectionReporter).
type RejectionReporter interface {
	NotifyRejected(err error)
}

// LifecycleWirer is implemented by every Source this package returns that
// signs: the ephemeral source and the held-with-fallback source. Both setters
// are safe to call while the source is in use, because the daemon builds the
// source before authentication and the lifecycle manager only after it. A nil
// argument is ignored. The held source alone signs nothing and does not
// implement it.
type LifecycleWirer interface {
	SetReauthGate(ReauthGate)
	SetReauthReporter(RejectionReporter)
}

// gateHolder and reporterHolder keep the stored type of an atomic.Value
// stable whichever implementation is wired.
type (
	gateHolder     struct{ gate ReauthGate }
	reporterHolder struct{ reporter RejectionReporter }
)

// reauthPoll is how often a waiting sign re-reads the gate, matching the SSH
// agent's.
const reauthPoll = 100 * time.Millisecond

func (e *ephemeral) SetReauthGate(g ReauthGate) {
	if g != nil {
		e.gate.Store(gateHolder{gate: g})
	}
}

func (e *ephemeral) SetReauthReporter(r RejectionReporter) {
	if r != nil {
		e.reporter.Store(reporterHolder{reporter: r})
	}
}

func (e *ephemeral) reauthGate() ReauthGate {
	h, _ := e.gate.Load().(gateHolder)
	return h.gate
}

// reportRejection tells the wired reporter about err when it is a token
// rejection (a 403 or an expired token), and does nothing otherwise. The
// classification is auth.IsTokenRejected, the predicate NotifyRejected itself
// applies, so the two cannot disagree; filtering here as well keeps a 5xx or
// a transport failure from ever reaching the lifecycle manager.
func (e *ephemeral) reportRejection(err error) {
	if err == nil || !auth.IsTokenRejected(err) {
		return
	}
	h, ok := e.reporter.Load().(reporterHolder)
	if !ok || h.reporter == nil {
		return
	}
	slog.Debug("client certificate: reporting a token rejection to the token lifecycle manager", "error", err)
	h.reporter.NotifyRejected(err)
}

// awaitReplacement returns the token flight f should sign with. When no
// replacement is in flight that is the token Current read. When one is, it
// waits for it to clear — bounded by reauthWait, which never exceeds the
// sign's own timeout — and re-reads the client's token, since the value read
// before the wait is the one being replaced. A replacement that does not
// clear in time is ErrReauthInProgress: transient, and not a Vault verdict.
func (e *ephemeral) awaitReplacement(ctx context.Context, f *flight) (string, error) {
	g := e.reauthGate()
	if g == nil || !g.NeedsReauth() {
		return f.token, nil
	}
	ctx, cancel := context.WithTimeout(ctx, e.reauthWait)
	defer cancel()
	ticker := time.NewTicker(reauthPoll)
	defer ticker.Stop()
	for g.NeedsReauth() {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("%w: %w", clientcert.ErrReauthInProgress, ctx.Err())
		case <-ticker.C:
		}
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
func (f *fallback) SetReauthGate(g ReauthGate) {
	if w, ok := f.eph.(LifecycleWirer); ok {
		w.SetReauthGate(g)
	}
}

// SetReauthReporter forwards to the ephemeral source, as SetReauthGate does.
func (f *fallback) SetReauthReporter(r RejectionReporter) {
	if w, ok := f.eph.(LifecycleWirer); ok {
		w.SetReauthReporter(r)
	}
}

var (
	_ LifecycleWirer = (*ephemeral)(nil)
	_ LifecycleWirer = (*fallback)(nil)
)
