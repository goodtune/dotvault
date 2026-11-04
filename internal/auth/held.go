package auth

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/goodtune/dotvault/internal/securestore"
)

// HeldCertificate is the certificate dotvault already holds for Vault cert
// auth, exported for use by other tools. It exists only for a host running
// plain `mtls`, whose key sits in the file backend and so is already readable
// by this user; nothing here widens what the user could read from disk.
type HeldCertificate struct {
	// CertPEM is the leaf and chain exactly as recorded in the envelope.
	CertPEM []byte
	// KeyPEM is the private key as a PKCS#8 "PRIVATE KEY" block.
	KeyPEM []byte
	// NotAfter is the leaf's expiry.
	NotAfter time.Time
	// Serial is the leaf's serial as recorded in the envelope.
	Serial string
	// Version identifies the credential.json this was read from, taken
	// before the content was read, so a caller comparing it with a later
	// StatCredential notices a rotation that replaced the credential.
	Version CredentialVersion
}

// CredentialVersion identifies one write of credential.json: its
// full-resolution mtime and its size, so a rewrite within the same second is
// still told apart unless it also keeps the size and lands on the identical
// mtime. Comparable with ==.
type CredentialVersion struct {
	ModTime time.Time
	Size    int64
}

// StatCredential reports the version of the credential envelope under
// storageDir without reading it, for a caller that keeps an exported
// HeldCertificate and wants to know cheaply whether it is still current. It
// stats the same file ExportHeldCertificate reads; an empty storageDir is
// refused for the same reason it is there.
func StatCredential(storageDir string) (CredentialVersion, error) {
	if storageDir == "" {
		return CredentialVersion{}, fmt.Errorf("%w: no credential storage directory", ErrNoCertCredential)
	}
	fi, err := os.Stat(credentialPath(storageDir))
	if err != nil {
		return CredentialVersion{}, err
	}
	return versionOf(fi), nil
}

func versionOf(fi os.FileInfo) CredentialVersion {
	// Normalise to wall-clock UTC so == compares the instant, not the
	// location or a monotonic reading.
	return CredentialVersion{ModTime: fi.ModTime().UTC().Round(0), Size: fi.Size()}
}

// ErrHeldNotExportable is returned when the held certificate's key is
// hardware-sealed or lives in the OS certificate store, or the configured
// method is not plain mtls. The decision rests on the configured method and
// the envelope's recorded backend, never on the in-memory key type: the TPM
// backend unseals its scalar into software, so the type of the loaded key
// says nothing about where it is meant to stay.
var ErrHeldNotExportable = errors.New("held certificate key is not exportable")

// heldAfterStat is a test seam run between the stat and the read, so a test
// can land a rotation in that window. Nil in production.
var heldAfterStat func()

// ExportHeldCertificate returns the certificate and key stored for cert auth.
// It is refused with ErrHeldNotExportable unless method is exactly "mtls" and
// the envelope's backend is "file". It wraps ErrNoCertCredential when no usable
// credential exists: the envelope is absent, expired, or issued to another
// user than username. No error or log line carries key material.
func ExportHeldCertificate(storageDir, method, username string) (*HeldCertificate, error) {
	if method != "mtls" {
		return nil, fmt.Errorf("%w: auth method %q keeps its key in hardware or the OS store, or holds none", ErrHeldNotExportable, method)
	}
	if storageDir == "" {
		// An empty directory would make loadCredential probe a cwd-relative
		// credential.json and serve whatever certificate sits in the working
		// directory; see CertLoginFromStore.
		return nil, fmt.Errorf("%w: no credential storage directory", ErrNoCertCredential)
	}
	// Stat before reading. A rotation landing between the two then pairs the
	// old version with the new content, which only makes the caller reload
	// once more; the other order would pair a new version with old content and
	// hide the rotation from it until the next one.
	fi, err := os.Stat(credentialPath(storageDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: a bootstrap is required", ErrNoCertCredential)
		}
		return nil, fmt.Errorf("%w: stat credential: %w", ErrNoCertCredential, err)
	}
	if heldAfterStat != nil {
		heldAfterStat()
	}
	cred, err := loadCredential(storageDir)
	if err != nil {
		return nil, fmt.Errorf("%w: load certificate credential: %w", ErrNoCertCredential, err)
	}
	if cred == nil {
		return nil, fmt.Errorf("%w: a bootstrap is required", ErrNoCertCredential)
	}
	if cred.Backend != "file" {
		return nil, fmt.Errorf("%w: key is held by the %q backend", ErrHeldNotExportable, cred.Backend)
	}
	if cred.Identity != "" && username != "" && cred.Identity != username {
		return nil, fmt.Errorf("%w: credential belongs to %q, not the current user %q", ErrNoCertCredential, cred.Identity, username)
	}
	if !cred.NotAfter.IsZero() && time.Now().After(cred.NotAfter) {
		return nil, fmt.Errorf("%w: certificate expired at %s", ErrNoCertCredential, cred.NotAfter.Format(time.RFC3339))
	}

	store, err := securestore.Open("file")
	if err != nil {
		return nil, fmt.Errorf("%w: open secure store: %w", ErrNoCertCredential, err)
	}
	defer store.Close()
	signer, err := store.Load(cred.Handle)
	if err != nil {
		return nil, fmt.Errorf("%w: load key from secure store: %w", ErrNoCertCredential, err)
	}
	leaf, err := leafCert(cred.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: parse certificate: %w", ErrNoCertCredential, err)
	}
	if eq, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); !ok || !eq.Equal(signer.Public()) {
		return nil, fmt.Errorf("%w: stored key does not match the certificate", ErrNoCertCredential)
	}
	// Re-marshal rather than pass the handle through: it may be a legacy
	// encoding (SEC1 or PKCS#1) that a consumer expecting PKCS#8 would reject.
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal key as PKCS#8", ErrHeldNotExportable)
	}

	return &HeldCertificate{
		CertPEM:  []byte(cred.CertPEM),
		KeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		NotAfter: cred.NotAfter,
		Serial:   cred.Serial,
		Version:  versionOf(fi),
	}, nil
}
