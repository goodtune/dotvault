// Package securestore provides a platform-agnostic seam for holding the
// private key behind a TLS client certificate. The calling code (the
// cert-auth flow in internal/auth) never branches on platform: it asks
// Open for a backend, then Generate/Import/Load a crypto.Signer plus an
// opaque handle it can persist alongside the certificate.
//
// Three backends ship today:
//
//   - "file"  — a software key stored as a PKCS#8 PEM handle. Used for the
//     plain "mtls" auth method and on any platform without hardware support.
//     The key bytes live in the handle, so the caller writes them at 0600.
//   - "tpm"   — (Linux/Windows only) the key is sealed under the TPM's
//     Storage Root Key. The handle is the marshalled go-tpm-tools SealedBytes
//     proto and carries no usable key material off the originating chip.
//   - "os"    — (Windows only) the key and certificate live in the OS-native
//     certificate store (CurrentUser, CNG software provider) via
//     github.com/google/certtostore, so other software — most importantly the
//     system browsers — can discover and present the certificate for mTLS. The
//     handle records the CNG provider + key container; the cert is pushed into
//     the store through the optional CertStorer capability. On non-Windows
//     platforms Open("os") returns ErrUnsupported (Linux PKCS#11 and macOS
//     Keychain backends are future work).
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

// DataSealer is an optional capability for hardware backends that can seal an
// arbitrary small blob (e.g. a Vault token) under the same hardware root of
// trust that protects a key. The "file" backend deliberately does NOT
// implement it: sealing data under a software key kept on the same disk gives
// no at-rest protection, so data sealing is a hardware-only (TPM) feature.
type DataSealer interface {
	// SealData seals data and returns an opaque handle. The handle is
	// machine-bound: it can only be unsealed by UnsealData on the originating
	// chip.
	SealData(data []byte) ([]byte, error)
	// UnsealData reverses SealData.
	UnsealData(handle []byte) ([]byte, error)
}

// CertStorer is an optional capability for backends that keep the certificate
// alongside the private key in a shared, externally-visible store (the "os"
// backend's OS-native certificate store). The "file" and "tpm" backends do NOT
// implement it — they hold only the key, and the certificate lives in
// dotvault's own credential envelope. The cert-auth flow type-asserts this
// capability after a certificate is issued and, when present, pushes the cert
// into the store so other software (browsers, etc.) can present it.
type CertStorer interface {
	// StoreCert installs certPEM (leaf followed by its issuing CA chain) into
	// the store, associating it with the key behind handle. It returns the
	// handle to persist going forward (unchanged for the "os" backend, but the
	// signature leaves room for a backend that re-keys on store).
	StoreCert(handle []byte, certPEM string) ([]byte, error)
}

// SealData seals data under the platform hardware backend (TPM on
// Linux/Windows), opening and closing the device around the operation. It
// returns ErrUnsupported on a host with no hardware backend — callers MUST
// treat that as a hard error and never fall back to storing data in plaintext.
// The sealed blob is machine-bound: only UnsealData on the originating chip
// can recover it.
func SealData(data []byte) ([]byte, error) {
	store, err := Open("tpm")
	if err != nil {
		return nil, err
	}
	defer store.Close()
	sealer, ok := store.(DataSealer)
	if !ok {
		return nil, ErrUnsupported
	}
	return sealer.SealData(data)
}

// UnsealData reverses SealData, opening and closing the hardware backend
// around the operation. ErrUnsupported (no hardware) or an unseal error
// (wrong machine, cleared TPM) are both surfaced to the caller.
func UnsealData(handle []byte) ([]byte, error) {
	store, err := Open("tpm")
	if err != nil {
		return nil, err
	}
	defer store.Close()
	sealer, ok := store.(DataSealer)
	if !ok {
		return nil, ErrUnsupported
	}
	return sealer.UnsealData(handle)
}

// HardwareAvailable reports whether the platform hardware backend can be
// opened on this host (nil) or why it cannot (ErrUnsupported, wrapped). It is
// a cheap preflight used to fail a "+tpm" auth method fast and clearly when no
// TPM is present, rather than authenticating and then silently failing to
// persist the sealed token.
func HardwareAvailable() error {
	store, err := Open("tpm")
	if err != nil {
		return err
	}
	return store.Close()
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
	case "os":
		return openOSStore()
	default:
		return nil, fmt.Errorf("securestore: unknown backend %q", mode)
	}
}

// ModeForMethod maps a dotvault auth method to a securestore backend mode.
// "mtls+tpm" wants hardware, "mtls+os" the OS-native cert store; everything
// else (including plain "mtls") uses the file backend.
func ModeForMethod(authMethod string) string {
	switch authMethod {
	case "mtls+tpm":
		return "tpm"
	case "mtls+os":
		return "os"
	default:
		return "file"
	}
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
