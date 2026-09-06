// Package agent implements dotvault's SSH agent surface: an
// agent.ExtendedAgent backend served over a Unix domain socket (Linux/macOS)
// or a named pipe (Windows). Signing capability is exposed over dotvault's
// live, renewing Vault token without ever writing private keys to disk.
//
// The backend is platform-neutral and concurrency-safe; both platform
// listeners (listener_unix.go, listener_windows.go) serve the same instance.
// Identities come from one or more Source implementations — raw keys read from
// KV, short-lived certificates minted by a Vault SSH CA, or an upstream SSH
// agent the daemon shadows and delegates to. dotvault is one-way for its own keys,
// so those are read-only: Add/Remove/Lock against a Vault-backed identity
// returns a read-only error. An upstream agent is not dotvault's to be one-way
// about, though — those operations are proxied to it verbatim, so a client
// pointed permanently at the dotvault endpoint can still `ssh-add` a legacy
// on-disk key into the agent underneath.
package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// IDExtension is a dotvault-private agent-protocol extension whose reply is
// this process's agent instance ID. It exists purely as a loop guard for
// upstream-agent discovery: an endpoint that answers with our own ID is this
// daemon reached by another name, and delegating to it would recurse forever.
//
// Comparing paths alone cannot catch that. Once a user points SSH_AUTH_SOCK at
// dotvault — which is the whole point of the shadowing arrangement — the most
// likely discovery candidate IS dotvault, reachable through a symlink, a bind
// mount, a container path, or an SSH RemoteForward that no amount of
// path-cleaning resolves to the endpoint we bound. Asking the agent who it is
// settles it regardless of how it was reached.
//
// Any other agent answers SSH_AGENT_FAILURE (x/crypto surfaces
// agent.ErrExtensionUnsupported), which is the "not us" answer — so the probe
// costs one round-trip against a cold discovery scan and nothing thereafter.
const IDExtension = "dotvault-agent-id@goodtune.github.io"

// processAgentID identifies this daemon process's agent across every endpoint
// it serves. Generated once at package init: a single process is a single
// agent no matter how many listeners (the primary socket, the Pageant pipe)
// front it, and every one of them must answer the same value for the loop
// guard to recognise them all. A random ID rather than the PID because the
// probe crosses namespaces (containers, forwarded sockets) where PIDs collide.
var processAgentID = newProcessAgentID()

func newProcessAgentID() []byte {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Cannot happen on any supported platform. Falling back to a fixed
		// value would make two dotvaults mistake each other for themselves,
		// so degrade the other way: an empty ID matches nothing, the probe
		// stops rejecting endpoints, and the path-based guard still stands.
		return nil
	}
	out := make([]byte, hex.EncodedLen(len(b)))
	hex.Encode(out, b[:])
	return out
}

// ErrReadOnly is returned by a mutating agent operation that has nowhere to go
// — no upstream-agent source is configured, or the key named belongs to a
// Vault-backed source. dotvault syncs one way (Vault → local) and its own
// identities mirror that: they are never added, removed, or locked by a
// client. With an upstream source configured, mutations are forwarded there
// instead of refused; see MutatingSource.
var ErrReadOnly = errors.New("dotvault agent is read-only")

// Identity is a public key or certificate the agent can present.
type Identity struct {
	// PubKey is the key advertised over List and matched on Sign. For
	// certificate sources this is the *ssh.Certificate (its Marshal returns
	// the cert blob, which is what a client requests on Sign).
	PubKey ssh.PublicKey

	// Comment is the human-facing label shown by `ssh-add -l`.
	Comment string

	// Expiry is the certificate validity end for cert identities; the zero
	// value means "no expiry" (a raw key).
	Expiry time.Time
}

// Source is one configured origin of signing identities — a KV path prefix or
// a Vault SSH-CA role. The backend aggregates identities from every source for
// List and offers each source the chance to satisfy a Sign.
type Source interface {
	// Name is a stable label for status and logging.
	Name() string

	// Type reports the source kind ("kv", "vault-ca", or "agent") for status
	// output.
	Type() string

	// Identities returns the public keys/certs currently available. Sources
	// that have disappeared from Vault simply return fewer identities on the
	// next call — no restart required.
	Identities(ctx context.Context) ([]Identity, error)

	// Sign signs data with the private key matching key, if this source owns
	// it. matched is false (with a nil error) when the key belongs to another
	// source, so the backend can try the next one. The signature is obtained
	// at request time: KV sources read+parse+discard the private key; CA
	// sources ensure a fresh certificate and sign with the in-memory key.
	Sign(ctx context.Context, key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (sig *ssh.Signature, matched bool, err error)
}

// MutatingSource is the optional extension a Source implements when it can
// accept the agent protocol's mutating operations — today only the
// upstream-agent source, which forwards them to the agent it shadows.
//
// This is what makes dotvault safe to put *in front of* a user's existing
// agent rather than beside it: `ssh-add` against the dotvault endpoint lands
// the key in the upstream agent, so a client can be pointed at dotvault
// permanently and still do everything it did with the agent underneath. A
// Vault-backed source implements none of this — its keys come from Vault and
// there is nothing sensible for a client-supplied key to mean — so the backend
// keeps answering ErrReadOnly whenever no mutating source is configured.
//
// Remove reports matched == false (with a nil error) when the source does not
// hold the key, mirroring Sign, so the backend can distinguish "removed" from
// "not ours" and answer read-only for a key nobody can remove.
type MutatingSource interface {
	Source

	Add(ctx context.Context, key agent.AddedKey) error
	Remove(ctx context.Context, key ssh.PublicKey) (matched bool, err error)
	RemoveAll(ctx context.Context) error
	Lock(ctx context.Context, passphrase []byte) error
	Unlock(ctx context.Context, passphrase []byte) error
}

// signData signs data, honouring the rsa-sha2-256 / rsa-sha2-512 flags modern
// servers require so SHA-1 signatures are not produced for RSA keys. Non-RSA
// signers (Ed25519) ignore the flags and sign normally.
func signData(signer ssh.Signer, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	var algo string
	switch {
	case flags&agent.SignatureFlagRsaSha512 != 0:
		algo = ssh.KeyAlgoRSASHA512
	case flags&agent.SignatureFlagRsaSha256 != 0:
		algo = ssh.KeyAlgoRSASHA256
	}
	if algo != "" {
		if as, ok := signer.(ssh.AlgorithmSigner); ok {
			return as.SignWithAlgorithm(rand.Reader, data, algo)
		}
	}
	return signer.Sign(rand.Reader, data)
}

// keyEqual reports whether two public keys are byte-identical. Marshal is the
// canonical wire encoding, so this matches raw keys and certificates alike.
func keyEqual(a, b ssh.PublicKey) bool {
	am, bm := a.Marshal(), b.Marshal()
	if len(am) != len(bm) {
		return false
	}
	for i := range am {
		if am[i] != bm[i] {
			return false
		}
	}
	return true
}
