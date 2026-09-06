package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// upstreamSource delegates the agent protocol to one or more *other* SSH
// agents reached over their own endpoints — Unix domain sockets (OpenSSH
// ssh-agent, gpg-agent, a keyring daemon, a password manager) or Windows named
// pipes (the OpenSSH agent service, Pageant). It is what lets a user point
// every ssh client at dotvault's endpoint permanently: the legacy on-disk keys
// their own agent already holds keep working, served from the same socket as
// dotvault's Vault-backed ones.
//
// dotvault never stores or reads the upstream's private keys: the source is a
// pure proxy. A fresh connection is dialled per operation and closed
// immediately, so an upstream agent appearing or disappearing changes the
// advertised identities on the next request without a restart, and no
// long-lived connection is held against an agent that may come and go.
//
// Mutations are proxied too (see MutatingSource), which is the other half of
// "in front of" rather than "beside": `ssh-add` against dotvault lands the key
// in the upstream agent, and `ssh-add -D`/`-x` reach it as well. dotvault
// stores nothing on that path either — the key goes straight out over the
// upstream connection.
type upstreamSource struct {
	name string

	// resolve returns the endpoints to proxy, most-preferred first. An
	// explicitly configured socket/pipe yields exactly that one endpoint; in
	// auto-detect mode it re-scans the platform's well-known agent locations
	// on every call, so an agent started (or stopped) long after the daemon
	// changes what is served on the next request rather than at the next
	// restart. Re-scanning per call rather than caching is deliberate: the
	// backend's own List cache already bounds how often this runs, and the
	// whole point of auto-detection is that the answer is allowed to change.
	resolve func(ctx context.Context) []string

	// dial opens a client connection to a given upstream endpoint. Injected so
	// tests can drive an in-memory agent without a real socket; production
	// wires it to the platform dialEndpoint.
	dial dialFunc

	// verifyPeer requires every connection to be answered by a process running
	// as this same user, checked with peerUID on the connection itself. It is
	// set for auto-detected endpoints — dotvault chose those from a shared
	// namespace, so it owes the check — and deliberately NOT for an explicitly
	// configured one, where the operator named the endpoint and may well have
	// meant a system agent running as another account. Where peerUID cannot
	// answer (no platform support) the check passes; see peerUID.
	verifyPeer bool

	mu sync.Mutex
	// owner maps a Marshal()'d public-key blob to the endpoint that last
	// advertised it, so Sign and Remove route straight to the agent that holds
	// the key instead of re-listing every one of them. listed reports whether
	// a full, error-free scan has ever completed — only then is an absence
	// from owner conclusive evidence that a key is not ours.
	owner  map[string]string
	listed bool
	// endpoints is the most recent resolve() result, kept for status output
	// so `dotvault status` can show which agents are actually being shadowed.
	endpoints []string
}

// newUpstreamSource builds a source that proxies to a fixed endpoint.
func newUpstreamSource(name, endpoint string) *upstreamSource {
	return newUpstreamSourceFunc(name, func(context.Context) []string { return []string{endpoint} })
}

// newAutoUpstreamSource builds a source that re-discovers the user's agents on
// every listing, excluding the endpoints this daemon serves itself.
func newAutoUpstreamSource(name string, self []string) *upstreamSource {
	s := newUpstreamSourceFunc(name, nil)
	s.verifyPeer = true
	scan := func(ctx context.Context) []string {
		return discoverUpstreamEndpoints(ctx, self, s.dial)
	}
	s.resolve = memoiseScan(scan, discoveryMemoTTL)
	return s
}

// discoveryMemoTTL collapses the repeated scans a single logical operation
// triggers. A scan dials every candidate, so it is the expensive part of the
// source, and several call sites resolve endpoints independently: an identity
// refresh, a Sign whose owner is unknown, an Add, a broadcast, and every
// /api/v1/status poll (Status calls Identities directly, bypassing the
// backend's own List cache). The window is deliberately shorter than that
// cache so "re-scan on every refresh" stays true at the cadence that matters —
// it suppresses duplicate scans within one burst, not between refreshes.
const discoveryMemoTTL = 3 * time.Second

// memoiseScan wraps an endpoint scan in a short single-flight TTL cache.
// Concurrent callers share one scan rather than each dialling every candidate.
func memoiseScan(scan func(context.Context) []string, ttl time.Duration) func(context.Context) []string {
	var (
		mu   sync.Mutex
		at   time.Time
		last []string
	)
	return func(ctx context.Context) []string {
		mu.Lock()
		defer mu.Unlock()
		if !at.IsZero() && time.Since(at) < ttl {
			return last
		}
		last = scan(ctx)
		at = time.Now()
		return last
	}
}

func newUpstreamSourceFunc(name string, resolve func(ctx context.Context) []string) *upstreamSource {
	return &upstreamSource{
		name:    name,
		resolve: resolve,
		dial:    dialEndpoint,
	}
}

func (s *upstreamSource) Name() string { return s.name }
func (s *upstreamSource) Type() string { return "agent" }

// NeedsVaultToken is false: this source proxies to agents that hold their own
// keys, so it works on a daemon that has never authenticated. See
// VaultIndependent.
func (s *upstreamSource) NeedsVaultToken() bool { return false }

// Endpoints reports the upstream endpoints from the most recent resolve, for
// status output. It does not itself trigger a scan: Status calls Identities
// first, which refreshes this.
func (s *upstreamSource) Endpoints() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.endpoints...)
}

// currentEndpoints resolves the endpoints to proxy and records them for status.
func (s *upstreamSource) currentEndpoints(ctx context.Context) []string {
	eps := s.resolve(ctx)
	s.mu.Lock()
	s.endpoints = append([]string(nil), eps...)
	s.mu.Unlock()
	return eps
}

// connect dials one upstream and returns an agent client plus the underlying
// connection for the caller to close.
//
// The agent client's own calls (List/Sign/Add/...) are blocking reads with no
// context of their own, so the caller's deadline is applied to the connection
// itself. That is what bounds a wedged upstream — and, in the worst case, a
// delegation loop that slipped both layers of the self-reference guard, which
// would otherwise sit blocked on its own reply forever rather than unwinding
// with an error the caller can report.
func (s *upstreamSource) connect(ctx context.Context, endpoint string) (agent.ExtendedAgent, net.Conn, error) {
	conn, err := s.dial(ctx, endpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("dial upstream agent %s: %w", endpoint, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if s.verifyPeer {
		if uid, known := peerUID(conn); known && uid != selfUID() {
			conn.Close()
			return nil, nil, fmt.Errorf("upstream agent %s is served by uid %d, not this user", endpoint, uid)
		}
	}
	return agent.NewClient(conn), conn, nil
}

// remember records which endpoint advertised which key so a later Sign or
// Remove can route without re-listing. complete says whether every endpoint
// answered: ownership is only conclusive when the picture is whole, so a scan
// with a failing endpoint updates the routing table but does not license the
// short-circuit in mightOwn.
func (s *upstreamSource) remember(owner map[string]string, complete bool) {
	s.mu.Lock()
	s.owner = owner
	// Assigned, never latched. owner is replaced wholesale, so a later scan in
	// which an endpoint was down installs a map missing that endpoint's keys —
	// and leaving listed true from an earlier complete scan would then let
	// mightOwn answer a confident "not ours" for a key the source really does
	// own, refusing to sign it. listed must describe the map it sits beside.
	s.listed = complete
	s.mu.Unlock()
}

// mightOwn reports whether key could belong to one of the upstreams, and names
// the endpoint that advertised it when known. Before a complete listing
// ownership is unknown, so it returns true with an empty endpoint and lets the
// caller dial to find out; afterwards it answers from the routing table, so an
// operation on a key no upstream has ever offered short-circuits without
// touching a socket.
func (s *upstreamSource) mightOwn(key ssh.PublicKey) (endpoint string, might bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ep, ok := s.owner[string(key.Marshal())]; ok {
		return ep, true
	}
	if !s.listed {
		return "", true
	}
	return "", false
}

// forget drops the routing table after a mutation, so the next operation
// rebuilds it rather than routing on a picture the mutation invalidated.
func (s *upstreamSource) forget() {
	s.mu.Lock()
	s.owner = nil
	s.listed = false
	s.mu.Unlock()
}

// Identities lists every upstream's keys, in endpoint order, and records who
// owns what.
//
// A key advertised by more than one upstream is listed once, attributed to the
// first endpoint that offered it — duplicates are common (SSH_AUTH_SOCK
// usually points at an agent this scan also finds by its well-known path) and
// an ssh client offering the same key twice wastes an authentication attempt
// against a server's MaxAuthTries budget.
//
// An endpoint that fails is skipped rather than failing the source: with
// auto-detection the endpoint list is a best guess about what is running, and
// one dead socket in it must not blank the agents that answered. The error
// only surfaces when nothing answered at all — and an empty endpoint list is
// not an error, it is the honest "nothing to shadow right now", which keeps
// the backend's List cache usable on a host where no other agent is running.
func (s *upstreamSource) Identities(ctx context.Context) ([]Identity, error) {
	eps := s.currentEndpoints(ctx)
	if len(eps) == 0 {
		s.remember(nil, true)
		return nil, nil
	}

	var (
		ids   []Identity
		errs  []error
		owner = make(map[string]string)
	)
	for _, ep := range eps {
		keys, err := s.list(ctx, ep)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, k := range keys {
			blob := string(k.Marshal())
			if _, dup := owner[blob]; dup {
				continue
			}
			owner[blob] = ep
			// *agent.Key satisfies ssh.PublicKey (Type/Marshal/Verify), which
			// is all the backend needs for advertising and Sign matching.
			ids = append(ids, Identity{PubKey: k, Comment: k.Comment})
		}
	}
	s.remember(owner, len(errs) == 0)
	if len(ids) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return ids, nil
}

// list dials one endpoint and returns the keys it advertises.
func (s *upstreamSource) list(ctx context.Context, endpoint string) ([]*agent.Key, error) {
	client, conn, err := s.connect(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	keys, err := client.List()
	if err != nil {
		return nil, fmt.Errorf("list upstream agent %s: %w", endpoint, err)
	}
	return keys, nil
}

// Sign routes the request to the upstream that holds the key.
//
// Ownership fast-path first: a key no upstream has ever advertised cannot be
// ours, so it falls through (matched == false) WITHOUT dialing. Besides saving
// a round-trip, that keeps a foreign key — one owned by a kv or vault-ca
// source — from dialing an upstream at all, so a dead upstream contributes no
// spurious "unreachable" error to the backend's joined error for keys it does
// not own.
//
// When the routing table names the owning endpoint, only that one is tried.
// Otherwise (no complete listing yet) every endpoint is tried in order, which
// is the same work the first List would have done.
func (s *upstreamSource) Sign(ctx context.Context, key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, bool, error) {
	endpoint, might := s.mightOwn(key)
	if !might {
		return nil, false, nil
	}

	var errs []error
	for _, ep := range s.targets(ctx, endpoint) {
		sig, matched, err := s.signAt(ctx, ep, key, data, flags)
		if err != nil {
			// Report the failure rather than swallowing it: the backend skips
			// a source that errors and tries the rest, surfacing the
			// accumulated errors only when no source matches — so an error
			// here cannot block a key owned by a healthy source, and an
			// upstream-owned key that cannot be signed reports why
			// (unreachable) instead of a generic key-not-found.
			errs = append(errs, err)
			continue
		}
		if matched {
			return sig, true, nil
		}
	}
	if len(errs) > 0 {
		return nil, false, errors.Join(errs...)
	}
	return nil, false, nil
}

// signAt confirms the given upstream still advertises the key before
// forwarding, so a key removed from the agent since the last listing is
// reported as not-ours rather than as an upstream error.
func (s *upstreamSource) signAt(ctx context.Context, endpoint string, key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, bool, error) {
	client, conn, err := s.connect(ctx, endpoint)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()

	keys, err := client.List()
	if err != nil {
		return nil, false, fmt.Errorf("list upstream agent %s: %w", endpoint, err)
	}
	if !advertises(keys, key) {
		return nil, false, nil
	}
	sig, err := client.SignWithFlags(key, data, flags)
	if err != nil {
		return nil, false, fmt.Errorf("upstream agent %s sign: %w", endpoint, err)
	}
	return sig, true, nil
}

// targets returns the endpoints an operation on a single key should try: just
// the known owner when the routing table has one, else everything currently
// resolvable.
func (s *upstreamSource) targets(ctx context.Context, known string) []string {
	if known != "" {
		return []string{known}
	}
	return s.currentEndpoints(ctx)
}

func advertises(keys []*agent.Key, key ssh.PublicKey) bool {
	for _, k := range keys {
		if keyEqual(k, key) {
			return true
		}
	}
	return false
}

// --- MutatingSource: operations forwarded to the shadowed agent(s). ---

// Add forwards a client-supplied key to the *first* resolvable upstream.
//
// One target, not a fan-out: `ssh-add` means "put this key in my agent", and
// copying a private key into every agent on the machine — a keyring daemon, a
// password manager's vault, a gpg-agent — is not what the user asked for and
// not something they could easily undo. First is the most-preferred endpoint,
// which on Unix is $SSH_AUTH_SOCK when set: the agent the user's own tooling
// already treats as theirs (see candidateEndpoints).
//
// dotvault keeps nothing: the key is written straight to the upstream
// connection and this process retains no copy.
func (s *upstreamSource) Add(ctx context.Context, key agent.AddedKey) error {
	eps := s.currentEndpoints(ctx)
	if len(eps) == 0 {
		return fmt.Errorf("no upstream SSH agent available to add the key to")
	}
	// Deliberately no fallthrough to eps[1:] on failure: retrying elsewhere
	// would put the private key in an agent the user did not name, which is
	// precisely what targeting one endpoint exists to prevent. A failed add is
	// reported, not rerouted.
	client, conn, err := s.connect(ctx, eps[0])
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := client.Add(key); err != nil {
		return fmt.Errorf("upstream agent %s add: %w", eps[0], err)
	}
	// The new key changes what List should report and who owns it.
	s.forget()
	return nil
}

// Remove deletes the key from the upstream that holds it, reporting
// matched == false when no upstream does — which lets the backend answer
// ErrReadOnly for a Vault-backed key rather than pretending to remove it.
func (s *upstreamSource) Remove(ctx context.Context, key ssh.PublicKey) (bool, error) {
	endpoint, might := s.mightOwn(key)
	if !might {
		return false, nil
	}

	var errs []error
	for _, ep := range s.targets(ctx, endpoint) {
		matched, err := s.removeAt(ctx, ep, key)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if matched {
			s.forget()
			return true, nil
		}
	}
	if len(errs) > 0 {
		return false, errors.Join(errs...)
	}
	return false, nil
}

func (s *upstreamSource) removeAt(ctx context.Context, endpoint string, key ssh.PublicKey) (bool, error) {
	client, conn, err := s.connect(ctx, endpoint)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	keys, err := client.List()
	if err != nil {
		return false, fmt.Errorf("list upstream agent %s: %w", endpoint, err)
	}
	if !advertises(keys, key) {
		return false, nil
	}
	if err := client.Remove(key); err != nil {
		return false, fmt.Errorf("upstream agent %s remove: %w", endpoint, err)
	}
	return true, nil
}

// RemoveAll clears every upstream agent. It does not touch dotvault's own
// Vault-backed identities — those are not the agent's to delete, and they
// reappear from Vault regardless — so `ssh-add -D` through dotvault means
// exactly what it means against the agent underneath.
func (s *upstreamSource) RemoveAll(ctx context.Context) error {
	err := s.broadcast(ctx, "remove-all", func(c agent.ExtendedAgent) error { return c.RemoveAll() })
	s.forget()
	return err
}

// Lock locks every upstream agent. dotvault's own identities are unaffected:
// their availability is governed by the Vault token, not by a passphrase this
// process would have to hold in memory to honour.
func (s *upstreamSource) Lock(ctx context.Context, passphrase []byte) error {
	return s.broadcast(ctx, "lock", func(c agent.ExtendedAgent) error { return c.Lock(passphrase) })
}

// Unlock unlocks every upstream agent.
func (s *upstreamSource) Unlock(ctx context.Context, passphrase []byte) error {
	return s.broadcast(ctx, "unlock", func(c agent.ExtendedAgent) error { return c.Unlock(passphrase) })
}

// broadcast applies op to every resolvable upstream, joining the failures.
//
// These three operations are agent-wide rather than key-scoped, so unlike Add
// they genuinely do address every agent being shadowed: a client that locks
// "the agent" it is talking to means all of what that agent serves. An error
// from one upstream does not stop the others — a partial lock is still worth
// having, and the caller is told which endpoints failed.
func (s *upstreamSource) broadcast(ctx context.Context, what string, op func(agent.ExtendedAgent) error) error {
	eps := s.currentEndpoints(ctx)
	if len(eps) == 0 {
		return fmt.Errorf("no upstream SSH agent available to %s", what)
	}
	var errs []error
	for _, ep := range eps {
		// The closure is what makes the close deferred per iteration rather
		// than per function, so a panicking op cannot leak the connection.
		err := func() error {
			client, conn, err := s.connect(ctx, ep)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := op(client); err != nil {
				return fmt.Errorf("upstream agent %s %s: %w", ep, what, err)
			}
			return nil
		}()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
