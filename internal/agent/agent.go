// Package agent implements dotvault's SSH agent surface: a read-only
// agent.ExtendedAgent backend served over a Unix domain socket (Linux/macOS)
// or a named pipe (Windows). Signing capability is exposed over dotvault's
// live, renewing Vault token without ever writing private keys to disk.
//
// The backend is platform-neutral and concurrency-safe; both platform
// listeners (listener_unix.go, listener_windows.go) serve the same instance.
// Identities come from one or more Source implementations — raw keys read from
// KV, or short-lived certificates minted by a Vault SSH CA. dotvault is
// one-way, so the agent is too: Add/Remove/Lock and friends return a
// read-only error.
package agent

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ErrReadOnly is returned by every mutating agent operation. dotvault syncs
// one way (Vault → local); the agent mirrors that and never accepts keys,
// locks, or removals from clients.
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

	// Type reports the source kind ("kv" or "vault-ca") for status output.
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
