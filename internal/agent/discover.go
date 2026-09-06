package agent

import (
	"context"
	"log/slog"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

// discoveryProbeTimeout bounds the "who are you" round-trip against a single
// discovery candidate. Discovery runs on the List path, so a candidate whose
// socket exists but whose owning process is wedged must not hold the whole
// listing hostage — an unresponsive agent is simply dropped from this scan and
// reconsidered on the next one.
const discoveryProbeTimeout = 2 * time.Second

// discoverUpstreamEndpoints returns the SSH-agent endpoints owned by the
// current user that dotvault can reasonably shadow, most-preferred first. It
// is what makes "point every ssh client at the dotvault socket, permanently"
// workable: the user's real agents are found rather than configured, and an
// agent started or stopped after the daemon changes the answer on the next
// scan (discovery is re-run per identity refresh, not cached for the process).
//
// exclude carries the endpoints this daemon serves the agent on. They are
// removed by path first — the cheap, always-correct case — and then by the
// IDExtension probe below, which catches the same daemon reached under a
// different path (a symlink, a bind mount, a forwarded socket). Both matter:
// once a user sets SSH_AUTH_SOCK to dotvault, the highest-priority discovery
// candidate is dotvault itself, and delegating to it would recurse until the
// listener ran out of connections.
//
// Candidates that do not exist, are not sockets, or are not owned by this uid
// are dropped by the platform layer (candidateEndpoints), so a world-writable
// /tmp cannot inject an agent into the fan-out. That ownership check is the
// security boundary here, and it matters more than it would for a read-only
// proxy: mutations are forwarded too, so an attacker-controlled endpoint that
// slipped in would receive private keys from a client's `ssh-add`.
func discoverUpstreamEndpoints(ctx context.Context, exclude []string, dial dialFunc) []string {
	excluded := make(map[string]bool, len(exclude))
	for _, e := range exclude {
		excluded[normalizeEndpoint(e)] = true
		// Resolve too: dotvault's own socket is routinely reached through a
		// symlinked runtime dir, and the raw and resolved forms must both be
		// recognised as ours.
		if r := resolveEndpointPath(e); r != "" {
			excluded[normalizeEndpoint(r)] = true
		}
	}

	var out []string
	seen := make(map[string]bool)
	for _, cand := range candidateEndpoints() {
		key := normalizeEndpoint(cand)
		if r := resolveEndpointPath(cand); r != "" {
			key = normalizeEndpoint(r)
		}
		if excluded[key] || seen[key] {
			continue
		}
		seen[key] = true
		switch probeCandidate(ctx, cand, dial) {
		case candidateSelf:
			slog.Debug("ssh agent: skipping discovered endpoint served by this daemon", "endpoint", cand)
			// Remember it as ours so a second path to the same daemon is
			// dropped without another probe.
			excluded[key] = true
			continue
		case candidateForeign:
			slog.Debug("ssh agent: skipping discovered endpoint owned by another user", "endpoint", cand)
			continue
		}
		out = append(out, cand)
	}
	return out
}

// candidateVerdict is what a single discovery probe concluded about an
// endpoint.
type candidateVerdict int

const (
	// candidateUsable: not this daemon, and not owned by another user as far
	// as this platform can tell. Note "as far as it can tell" is the honest
	// reading — a probe that could not run at all lands here too, which is the
	// deliberate fail-open documented on peerUID.
	candidateUsable candidateVerdict = iota
	// candidateSelf: this very daemon, reached under another name.
	candidateSelf
	// candidateForeign: served by a different uid.
	candidateForeign
)

// probeCandidate dials an endpoint once and answers both questions the dial
// can settle: is this us, and is it ours. One connection serves both because
// the answers come from the same place — the peer we are already attached to.
//
// A dead endpoint (dial fails) is reported usable rather than dropped: it may
// simply be starting, and the ordinary per-request error handling deals with
// it far better than removing it from the candidate list would.
func probeCandidate(ctx context.Context, endpoint string, dial dialFunc) candidateVerdict {
	ctx, cancel := context.WithTimeout(ctx, discoveryProbeTimeout)
	defer cancel()

	conn, err := dial(ctx, endpoint)
	if err != nil {
		return candidateUsable
	}
	defer conn.Close()
	// The probe must not outlive its context even if the peer never replies.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	// Ownership first: it is a local syscall with no round trip, and an
	// endpoint that is not ours should not be sent even an identity probe.
	if uid, ok := peerUID(conn); ok && uid != selfUID() {
		return candidateForeign
	}

	// Then identity. A non-dotvault agent answers SSH_AGENT_FAILURE
	// (agent.ErrExtensionUnsupported), which is the "not us" answer; only a
	// reply matching this process's ID excludes an endpoint, so a probe that
	// cannot run never silently blanks discovery.
	if len(processAgentID) == 0 {
		return candidateUsable
	}
	reply, err := agent.NewClient(conn).Extension(IDExtension, nil)
	if err == nil && string(reply) == string(processAgentID) {
		return candidateSelf
	}
	return candidateUsable
}

// selfUID is the uid peer credentials are compared against. On Windows
// os.Getuid returns -1, which no peerUID implementation there can match — but
// peerUID also always reports "unknown" on that platform, so the comparison is
// never reached.
func selfUID() uint32 { return uint32(os.Getuid()) }

// dialFunc opens a connection to an agent endpoint. Injected so tests can
// drive discovery without real sockets; production wires it to dialEndpoint.
type dialFunc func(ctx context.Context, endpoint string) (net.Conn, error)
