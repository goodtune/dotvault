package peer

import "context"

// Chain borrows through an ordered list of tiers, taking the first token any of
// them offers. It exists because "local-first" and "most-recently-seen first"
// are two different rules that must both hold, and a single Pool can only
// express the second.
//
// Within one tier, recency is right: among several forwarded workstations the
// one that reconnected most recently is the one actually there, so Pool orders
// its members by lastSeen. Between the local API socket and the peers, recency
// is exactly wrong: the local socket is bound once when the long-lived per-user
// daemon starts, while a forwarded peer socket is re-created on every SSH
// reconnect — so the peer is almost always the fresher of the two and a single
// pool over both would systematically prefer the source that disappears with a
// session over the one that does not. That is the inversion of the documented
// local-first borrow order, and the reason it is a tier boundary rather than a
// sort key: no ordering *within* a pool can encode "this one is more stable",
// because stability is not something a stat can see.
//
// A tier that holds no token is skipped, not treated as terminal — a local
// daemon that has not authenticated yet answers 401, and the peer behind it is
// then the correct source.
type Chain struct {
	tiers []Borrower
}

var _ Borrower = (*Chain)(nil)

// NewChain builds a chain over borrowers, in priority order. Nil borrowers are
// dropped, so a caller may pass a tier it did not configure without branching.
// A chain with no tiers borrows nothing.
func NewChain(borrowers ...Borrower) *Chain {
	c := &Chain{}
	for _, b := range borrowers {
		if b == nil {
			continue
		}
		// A caller that declares `var p *Pool` and passes it unassigned hands
		// over a non-nil interface holding a nil pointer, which the check
		// above cannot see. *Pool is nil-receiver safe so keeping it would
		// borrow nothing rather than panic, but it would still count as a
		// tier — and Status() skips it, so the tier list and the status list
		// would be different lengths. Drop it here instead, which is what
		// makes "nil borrowers are dropped" true for both spellings.
		if p, ok := b.(*Pool); ok && p == nil {
			continue
		}
		c.tiers = append(c.tiers, b)
	}
	return c
}

// NewLocalFirstChain builds the standard two-tier borrow chain: this host's own
// local API socket first, then the peer socket patterns, most-recently-seen
// first within them. An empty local contributes no tier, so a caller with no
// local socket configured needs no branch and gets a one-tier chain rather than
// an empty leading one.
//
// Why a tier and not just an ordering hint: config.TokenBorrowSockets() already
// returns the local socket ahead of the peers, so a single pool over that list
// looks like it would do. It would not. A pool sorts its members by recency,
// and in steady state the local socket is the *older* of the two — bound once
// when the long-lived per-user daemon started, against a forwarded peer socket
// re-created on every SSH reconnect. Flattening the tiers therefore inverts the
// documented local-first order rather than preserving it, systematically
// preferring the source that disappears with an SSH session over the one that
// does not. No sort key inside a pool can fix that, because stability is not
// something a stat can see — which is what makes this a tier boundary.
//
// Callers that want peers only (the daemon, which serves the local socket
// itself, and `dotvault login`, which must not borrow back the token it is
// replacing) build a single NewPool instead: their list is peers-only and there
// is no second tier to order.
func NewLocalFirstChain(local string, peerPatterns []string, opts ...Option) *Chain {
	var tiers []Borrower
	if local != "" {
		tiers = append(tiers, NewPool([]string{local}, opts...))
	}
	if len(peerPatterns) > 0 {
		tiers = append(tiers, NewPool(peerPatterns, opts...))
	}
	return NewChain(tiers...)
}

// Borrow implements Borrower: walk the tiers in order and return the first
// token offered, along with the socket path it came from. Best-effort, like
// Pool.Borrow — it never returns an error.
func (c *Chain) Borrow(ctx context.Context) (string, string) {
	if c == nil {
		return "", ""
	}
	for _, b := range c.tiers {
		if token, source := b.Borrow(ctx); token != "" {
			return token, source
		}
	}
	return "", ""
}

// Status reports each pool tier's status, in tier order, for diagnostics
// (`dotvault status`). A tier that is not a *Pool is skipped rather than
// reported as an empty tier, since "no sockets present" and "this tier does
// not exist" are different answers and only the first is useful. A nil *Pool
// never reaches here — NewChain drops it — so the tiers Status reports are
// positionally aligned with the ones NewChain kept, which is what lets a
// caller label them (see cmd/dotvault newBorrowChain).
func (c *Chain) Status() []Status {
	if c == nil {
		return nil
	}
	var out []Status
	for _, b := range c.tiers {
		if p, ok := b.(*Pool); ok && p != nil {
			out = append(out, p.Status())
		}
	}
	return out
}
