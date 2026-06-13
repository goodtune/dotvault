package agent

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// upstreamSource delegates List and Sign to a second SSH agent reached over its
// own endpoint — a Unix domain socket (OpenSSH ssh-agent) or a Windows named
// pipe (OpenSSH agent service / Pageant). It lets a user keep signing with
// legacy on-disk keys their personal agent already holds while dotvault serves
// its Vault-backed keys from the same surface.
//
// dotvault never stores or reads the upstream's private keys: the source is a
// pure proxy. A fresh connection is dialled per operation (List/Sign) and
// closed immediately, so the upstream agent appearing or disappearing changes
// the advertised identities on the next request without a restart, and no
// long-lived connection is held against an agent that may come and go.
type upstreamSource struct {
	name     string
	endpoint string
	// dial opens a client connection to the upstream agent. Injected so tests
	// can drive an in-memory agent without a real socket; production wires it
	// to the platform dialEndpoint.
	dial func(ctx context.Context) (net.Conn, error)
}

func newUpstreamSource(name, endpoint string) *upstreamSource {
	return &upstreamSource{
		name:     name,
		endpoint: endpoint,
		dial: func(ctx context.Context) (net.Conn, error) {
			return dialEndpoint(ctx, endpoint)
		},
	}
}

func (s *upstreamSource) Name() string { return s.name }
func (s *upstreamSource) Type() string { return "agent" }

// connect dials the upstream and returns an agent client plus the underlying
// connection for the caller to close.
func (s *upstreamSource) connect(ctx context.Context) (agent.ExtendedAgent, net.Conn, error) {
	conn, err := s.dial(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("dial upstream agent %s: %w", s.endpoint, err)
	}
	return agent.NewClient(conn), conn, nil
}

func (s *upstreamSource) Identities(ctx context.Context) ([]Identity, error) {
	client, conn, err := s.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	keys, err := client.List()
	if err != nil {
		return nil, fmt.Errorf("list upstream agent %s: %w", s.endpoint, err)
	}
	ids := make([]Identity, 0, len(keys))
	for _, k := range keys {
		// *agent.Key satisfies ssh.PublicKey (Type/Marshal), which is all the
		// backend needs for advertising and Sign matching.
		ids = append(ids, Identity{PubKey: k, Comment: k.Comment})
	}
	return ids, nil
}

func (s *upstreamSource) Sign(ctx context.Context, key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, bool, error) {
	client, conn, err := s.connect(ctx)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()

	// Confirm the upstream still advertises this key before forwarding, so a
	// key that belongs to another source falls through (matched == false)
	// rather than surfacing the upstream's "not found" as a hard error.
	keys, err := client.List()
	if err != nil {
		return nil, false, fmt.Errorf("list upstream agent %s: %w", s.endpoint, err)
	}
	owned := false
	for _, k := range keys {
		if keyEqual(k, key) {
			owned = true
			break
		}
	}
	if !owned {
		return nil, false, nil
	}

	sig, err := client.SignWithFlags(key, data, flags)
	if err != nil {
		return nil, false, fmt.Errorf("upstream agent %s sign: %w", s.endpoint, err)
	}
	return sig, true, nil
}
