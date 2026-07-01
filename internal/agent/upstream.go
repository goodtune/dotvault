package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

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

	// advertised is the set of Marshal()'d public-key blobs from the last
	// successful List; listed reports whether a List has ever succeeded (so an
	// empty advertised set means "no keys" rather than "not yet known"). Sign
	// consults these to answer ownership without dialing — see mightOwn.
	mu         sync.Mutex
	advertised map[string]bool
	listed     bool
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

// remember records the keys a successful List advertised so a later Sign can
// answer ownership without a round-trip.
func (s *upstreamSource) remember(keys []*agent.Key) {
	set := make(map[string]bool, len(keys))
	for _, k := range keys {
		set[string(k.Marshal())] = true
	}
	s.mu.Lock()
	s.advertised = set
	s.listed = true
	s.mu.Unlock()
}

// mightOwn reports whether key could belong to this upstream. Before the first
// successful List (listed == false) ownership is unknown, so it returns true
// and lets Sign dial to find out; afterwards it answers from the advertised
// set, so a Sign for a key this upstream has never offered short-circuits
// without touching the socket.
func (s *upstreamSource) mightOwn(key ssh.PublicKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.listed {
		return true
	}
	return s.advertised[string(key.Marshal())]
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
	s.remember(keys)
	ids := make([]Identity, 0, len(keys))
	for _, k := range keys {
		// *agent.Key satisfies ssh.PublicKey (Type/Marshal), which is all the
		// backend needs for advertising and Sign matching.
		ids = append(ids, Identity{PubKey: k, Comment: k.Comment})
	}
	return ids, nil
}

func (s *upstreamSource) Sign(ctx context.Context, key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, bool, error) {
	// Ownership fast-path: a key this upstream has never advertised cannot be
	// ours, so fall through (matched == false) WITHOUT dialing. This is what
	// keeps a down or slow upstream — even one ordered before kv/vault-ca in
	// agent.keys — from blocking a Sign for a key another source owns:
	// Backend.SignWithFlags treats a source error as fatal to the whole
	// request, so this source must never return an error for a key it doesn't
	// own.
	if !s.mightOwn(key) {
		return nil, false, nil
	}

	client, conn, err := s.connect(ctx)
	if err != nil {
		// An unreachable upstream owns no usable key right now. Treat it as
		// "not mine" rather than a hard error so later sources are still tried;
		// the aggregate result becomes ErrKeyNotFound only when no source
		// matches. The connectivity failure is still surfaced via Identities
		// (agent status), so it isn't lost.
		slog.Debug("ssh agent: upstream unreachable during sign, falling through", "endpoint", s.endpoint, "error", err)
		return nil, false, nil
	}
	defer conn.Close()

	// Confirm the upstream still advertises this key before forwarding, so a
	// key that belongs to another source falls through rather than surfacing
	// the upstream's "not found" as a hard error.
	keys, err := client.List()
	if err != nil {
		slog.Debug("ssh agent: upstream list failed during sign, falling through", "endpoint", s.endpoint, "error", err)
		return nil, false, nil
	}
	s.remember(keys)

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
