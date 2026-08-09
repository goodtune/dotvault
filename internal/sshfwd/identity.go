package sshfwd

import (
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	dvagent "github.com/goodtune/dotvault/internal/agent"
)

// SignerSource is the slice of agent.ExtendedAgent the forwarder needs.
// *agent.Backend satisfies it structurally; the narrowed interface keeps this
// package's tests free of Vault and keeps the dependency one-directional.
type SignerSource interface {
	List() ([]*sshagent.Key, error)
	SignWithFlags(key ssh.PublicKey, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error)
}

// Signers adapts a SignerSource into ssh.Signers usable by
// ssh.PublicKeysCallback.
//
// The agent Backend cannot be used directly: its Signers() returns ErrReadOnly
// by design, because dotvault syncs one way and the agent never hands out key
// material. This wraps each advertised identity in a signer that delegates
// back to the backend, so the private key stays wherever the source keeps it
// (Vault, or an in-memory ephemeral key behind a Vault-CA certificate).
//
// Callers should invoke this per dial rather than caching the result: a
// Vault-CA certificate rotated since the last connection is picked up on the
// next reconnect with no cache of its own.
func Signers(src SignerSource) ([]ssh.Signer, error) {
	keys, err := src.List()
	if err != nil {
		return nil, fmt.Errorf("list agent identities: %w", err)
	}
	signers := make([]ssh.Signer, 0, len(keys))
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			return nil, fmt.Errorf("parse agent identity %q: %w", k.Comment, err)
		}
		signers = append(signers, &backendSigner{src: src, pub: pub})
	}
	return signers, nil
}

// backendSigner is one advertised identity, signing via the backend.
type backendSigner struct {
	src SignerSource
	pub ssh.PublicKey
}

func (s *backendSigner) PublicKey() ssh.PublicKey { return s.pub }

func (s *backendSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	return s.src.SignWithFlags(s.pub, data, 0)
}

// SignWithAlgorithm satisfies ssh.AlgorithmSigner so an RSA identity can be
// used with rsa-sha2-256/512 rather than the deprecated ssh-rsa. The backend
// already honours these flags.
//
// For certificates, the algorithm argument is always the underlying (non-cert)
// algorithm name — x/crypto/ssh strips the -cert-v01@openssh.com suffix before
// calling SignWithAlgorithm. The comparison must account for this.
func (s *backendSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	var flags sshagent.SignatureFlags
	switch algorithm {
	case ssh.KeyAlgoRSASHA256:
		flags = sshagent.SignatureFlagRsaSha256
	case ssh.KeyAlgoRSASHA512:
		flags = sshagent.SignatureFlagRsaSha512
	case "":
		// Caller has no preference.
	default:
		// For a certificate, compare against the underlying key type, not the
		// full certificate type. The library calls SignWithAlgorithm with the
		// stripped algorithm name (e.g. ssh-ed25519, not ssh-ed25519-cert-v01@openssh.com).
		expectedType := s.pub.Type()
		if cert, ok := s.pub.(*ssh.Certificate); ok {
			expectedType = cert.Key.Type()
		}
		if algorithm != expectedType {
			return nil, &ErrUnsupportedAlgorithm{algorithm, expectedType}
		}
	}
	return s.src.SignWithFlags(s.pub, data, flags)
}

// ErrUnsupportedAlgorithm distinguishes an unsupported algorithm rejection
// from a backend signing failure.
type ErrUnsupportedAlgorithm struct {
	algorithm string
	keyType   string
}

func (e *ErrUnsupportedAlgorithm) Error() string {
	return fmt.Sprintf("unsupported signature algorithm %q for key type %q", e.algorithm, e.keyType)
}

// Compile-time proof the daemon's real backend satisfies SignerSource, so a
// change to either side breaks the build rather than the daemon at runtime.
var _ SignerSource = (*dvagent.Backend)(nil)
