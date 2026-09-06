package agent

import (
	"context"
	"log/slog"
	"net"
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
		if isSelfAgent(ctx, cand, dial) {
			slog.Debug("ssh agent: skipping discovered endpoint served by this daemon", "endpoint", cand)
			// Remember it as ours so a second path to the same daemon is
			// dropped without another probe.
			excluded[key] = true
			continue
		}
		out = append(out, cand)
	}
	return out
}

// isSelfAgent reports whether endpoint is served by this dotvault process,
// asked over the wire rather than inferred from the path. A non-dotvault agent
// answers SSH_AGENT_FAILURE (agent.ErrExtensionUnsupported) and a dead one
// fails to dial; either way the answer is "not us" and the endpoint stays in
// the candidate list, where the ordinary per-request error handling deals with
// it. Only a reply that matches this process's ID excludes an endpoint, so a
// probe that cannot run never silently blanks discovery.
func isSelfAgent(ctx context.Context, endpoint string, dial dialFunc) bool {
	if len(processAgentID) == 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, discoveryProbeTimeout)
	defer cancel()

	conn, err := dial(ctx, endpoint)
	if err != nil {
		return false
	}
	defer conn.Close()
	// The probe must not outlive its context even if the peer never replies.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	reply, err := agent.NewClient(conn).Extension(IDExtension, nil)
	if err != nil {
		return false
	}
	return string(reply) == string(processAgentID)
}

// dialFunc opens a connection to an agent endpoint. Injected so tests can
// drive discovery without real sockets; production wires it to dialEndpoint.
type dialFunc func(ctx context.Context, endpoint string) (net.Conn, error)
