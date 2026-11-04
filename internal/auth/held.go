package auth

import (
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
	// ModTime is the mtime of credential.json, so a caller can notice that a
	// rotation replaced the credential.
	ModTime time.Time
}

// ErrHeldNotExportable is returned when the held certificate's key is
// hardware-sealed or lives in the OS certificate store, or the configured
// method is not plain mtls. The decision rests on the configured method and
// the envelope's recorded backend, never on the in-memory key type: the TPM
// backend unseals its scalar into software, so the type of the loaded key
// says nothing about where it is meant to stay.
var ErrHeldNotExportable = errors.New("held certificate key is not exportable")

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
	// Re-marshal rather than pass the handle through: it may be a legacy
	// encoding (SEC1 or PKCS#1) that a consumer expecting PKCS#8 would reject.
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal key as PKCS#8", ErrHeldNotExportable)
	}

	fi, err := os.Stat(credentialPath(storageDir))
	if err != nil {
		return nil, fmt.Errorf("%w: stat credential: %w", ErrNoCertCredential, err)
	}
	return &HeldCertificate{
		CertPEM:  []byte(cred.CertPEM),
		KeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		NotAfter: cred.NotAfter,
		Serial:   cred.Serial,
		ModTime:  fi.ModTime(),
	}, nil
}
