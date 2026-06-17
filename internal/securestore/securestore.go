// Package securestore provides a platform-agnostic seam for holding the
// private key behind a TLS client certificate. The calling code (the
// cert-auth flow in internal/auth) never branches on platform: it asks
// Open for a backend, then Generate/Import/Load a crypto.Signer plus an
// opaque handle it can persist alongside the certificate.
//
// Two backends ship today:
//
//   - "file"  — a software key stored as a PKCS#8 PEM handle. Used for the
//     plain "mtls" auth method and on any platform without hardware support.
//     The key bytes live in the handle, so the caller writes them at 0600.
//   - "tpm"   — (Linux/Windows only) the key is sealed under the TPM's
//     Storage Root Key. The handle is the marshalled go-tpm-tools SealedBytes
//     proto and carries no usable key material off the originating chip.
//
// macOS Secure Enclave support is a future backend: Open("tpm") returns
// ErrUnsupported there until the binary is code-signed with the required
// entitlements. The interface is designed so that lands without changing
// any caller.
//
// The whole package is CGO-free; the TPM backend talks to /dev/tpmrm0
// (Linux) or TBS (Windows) through pure-Go go-tpm/go-tpm-tools.
package securestore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ErrUnsupported is returned by Open when the requested backend is not
// available on the current platform/build (e.g. "tpm" on unsigned macOS,
// or a host with no TPM device). Callers surface this as a clear error and
// must never silently fall back to a weaker backend.
var ErrUnsupported = errors.New("securestore: backend not supported on this platform")

// KeyType selects the algorithm for a generated key.
type KeyType string

const (
	// KeyEC is an ECDSA P-256 key. Default; the only type the macOS Secure
	// Enclave supports, so cross-platform configs should prefer it.
	KeyEC KeyType = "ec"
	// KeyRSA is an RSA 2048 key.
	KeyRSA KeyType = "rsa"
)

// Capabilities describes a backend.
type Capabilities struct {
	// Name is the backend identifier ("file", "tpm", "secure-enclave").
	Name string
	// HardwareBound is true when the private key is bound to hardware and
	// cannot be loaded on another machine (TPM/Enclave), false when it is a
	// portable software key (file).
	HardwareBound bool
}

// Storage holds the private key behind a client certificate. Implementations
// are not required to be safe for concurrent use; the cert-auth flow loads a
// signer once and assembles a tls.Certificate from it.
type Storage interface {
	// Capabilities reports backend identity and whether it hardware-binds.
	Capabilities() Capabilities
	// Generate creates a new private key of the given type and returns a
	// crypto.Signer plus an opaque handle that Load can later use to
	// reconstruct the signer. sealToPCRs binds the key to the current PCR
	// (boot) state where the backend supports it; it is ignored by backends
	// that do not.
	Generate(kt KeyType, sealToPCRs bool) (crypto.Signer, []byte, error)
	// Import takes an existing software private key (the BYO path) and
	// returns a crypto.Signer plus a handle, sealing it into hardware where
	// supported.
	Import(key crypto.PrivateKey, sealToPCRs bool) (crypto.Signer, []byte, error)
	// Load reconstructs a crypto.Signer from a handle previously returned by
	// Generate or Import.
	Load(handle []byte) (crypto.Signer, error)
	// Close releases any resources (e.g. the TPM device handle).
	Close() error
}

// Open returns a backend for the given mode: "file" or "tpm". "tpm" maps to
// the platform hardware backend (TPM on Linux/Windows) and returns
// ErrUnsupported where no hardware backend is built.
func Open(mode string) (Storage, error) {
	switch mode {
	case "file", "":
		return fileStorage{}, nil
	case "tpm":
		return openHardware()
	default:
		return nil, fmt.Errorf("securestore: unknown backend %q", mode)
	}
}

// ModeForMethod maps a dotvault auth method to a securestore backend mode.
// "mtls+tpm" wants hardware; everything else (including plain "mtls") uses
// the file backend.
func ModeForMethod(authMethod string) string {
	if authMethod == "mtls+tpm" {
		return "tpm"
	}
	return "file"
}

// newSoftwareKey generates a private key of the requested type.
func newSoftwareKey(kt KeyType) (crypto.Signer, error) {
	switch kt {
	case KeyEC, "":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyRSA:
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("securestore: unknown key type %q", kt)
	}
}

// marshalKey encodes a private key as PKCS#8 PEM.
func marshalKey(key crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal pkcs8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// parseKey decodes a PKCS#8 PEM private key into a crypto.Signer.
func parseKey(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("securestore: no PEM block in key handle")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fall back to the legacy EC/PKCS1 encodings a BYO key might use.
		if ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes); ecErr == nil {
			return ecKey, nil
		}
		if rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes); rsaErr == nil {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("parse pkcs8: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("securestore: key of type %T is not a crypto.Signer", key)
	}
	return signer, nil
}

// fileStorage is the software backend: the handle is the PKCS#8 PEM key.
type fileStorage struct{}

func (fileStorage) Capabilities() Capabilities {
	return Capabilities{Name: "file", HardwareBound: false}
}

func (fileStorage) Generate(kt KeyType, _ bool) (crypto.Signer, []byte, error) {
	signer, err := newSoftwareKey(kt)
	if err != nil {
		return nil, nil, err
	}
	handle, err := marshalKey(signer)
	if err != nil {
		return nil, nil, err
	}
	return signer, handle, nil
}

func (fileStorage) Import(key crypto.PrivateKey, _ bool) (crypto.Signer, []byte, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("securestore: imported key of type %T is not a crypto.Signer", key)
	}
	handle, err := marshalKey(key)
	if err != nil {
		return nil, nil, err
	}
	return signer, handle, nil
}

func (fileStorage) Load(handle []byte) (crypto.Signer, error) {
	return parseKey(handle)
}

func (fileStorage) Close() error { return nil }
