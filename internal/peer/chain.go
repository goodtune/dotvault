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
		c.tiers = append(c.tiers, b)
	}
	return c
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
// (`dotvault status`). A tier that is not a *Pool — or is a nil one, which is
// what a caller building a tier it has no config for ends up with — is skipped
// rather than reported as an empty tier, since "no sockets present" and "this
// tier does not exist" are different answers and only the first is useful.
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
