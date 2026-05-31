package agent

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// dialTimeout bounds the connect to a local agent endpoint. A loopback socket
// or named pipe answers (or refuses) effectively instantly; the timeout only
// guards the pathological case of an endpoint that exists but never accepts.
const dialTimeout = 3 * time.Second

// QueryListening connects to a running daemon's agent endpoint and returns the
// identities it is currently serving, obtained over the SSH agent protocol —
// the equivalent of `ssh-add -l`. This reports what the live daemon actually
// offers (the cached minted certificate with its true remaining validity, the
// keys presently discoverable in Vault) rather than a static description of
// config, and it never creates the endpoint.
//
// A dial failure is returned to the caller: when the agent is configured as
// enabled, an unreachable endpoint is an unexpected condition (the daemon isn't
// running, or hasn't authenticated far enough to start the listener) and the
// caller should surface it as such rather than silently substituting config.
func QueryListening(ctx context.Context, addr string) ([]IdentityStatus, error) {
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	conn, err := dialEndpoint(dialCtx, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	keys, err := agent.NewClient(conn).List()
	if err != nil {
		return nil, fmt.Errorf("list identities: %w", err)
	}
	return keysToStatuses(keys), nil
}

// keysToStatuses converts the agent-protocol key list into the IdentityStatus
// shape, parsing each advertised blob so a certificate's true remaining
// validity is recovered from the wire rather than re-derived from config. A
// blob that fails to parse is surfaced as a placeholder rather than dropped, so
// a discrepancy between what the daemon advertises and what the client can read
// is visible rather than silent. Kept separate from QueryListening so the parse
// behaviour is unit-testable without a live endpoint.
func keysToStatuses(keys []*agent.Key) []IdentityStatus {
	out := make([]IdentityStatus, 0, len(keys))
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			out = append(out, IdentityStatus{
				Comment:     k.Comment,
				Fingerprint: fmt.Sprintf("(unparseable: %v)", err),
			})
			continue
		}
		id := Identity{PubKey: pub, Comment: k.Comment}
		if cert, ok := pub.(*ssh.Certificate); ok {
			id.Expiry = certExpiry(cert)
		}
		out = append(out, identityStatus(id))
	}
	return out
}
