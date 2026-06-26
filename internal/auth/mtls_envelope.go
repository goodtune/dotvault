package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// envelopeSchema is the on-disk credential format version.
const envelopeSchema = 1

// sealedCredential is the on-disk envelope for a cert-auth credential. The
// private key is never in this file: for mtls+tpm the Handle is the TPM-sealed
// blob; for mtls+os the Handle records the OS-store key container (the key lives
// in the OS certificate store); for mtls the Handle is the PEM key (the file
// backend is the only mode where key bytes touch disk, by definition). The
// CertPEM is retained for every backend as the metadata/assembly source of
// truth — including mtls+os, where the cert is *also* installed in the OS store.
// Written 0600 via temp+rename.
type sealedCredential struct {
	Schema   int       `json:"schema"`
	Method   string    `json:"method"`   // "mtls" | "mtls+tpm" | "mtls+os"
	Backend  string    `json:"backend"`  // "tpm" | "file" | "os"
	CertPEM  string    `json:"cert_pem"` // leaf + chain
	Handle   []byte    `json:"handle"`   // opaque securestore handle
	Serial   string    `json:"serial"`
	NotAfter time.Time `json:"not_after"`
	Identity string    `json:"identity"` // OS username at issue time
	IssuedAt time.Time `json:"issued_at"`
}

func credentialPath(storageDir string) string {
	return filepath.Join(storageDir, "credential.json")
}

// loadCredential reads the envelope. A missing file returns (nil, nil).
func loadCredential(storageDir string) (*sealedCredential, error) {
	data, err := os.ReadFile(credentialPath(storageDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read credential: %w", err)
	}
	var c sealedCredential
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse credential: %w", err)
	}
	if c.Schema != envelopeSchema {
		return nil, fmt.Errorf("credential schema %d unsupported (want %d)", c.Schema, envelopeSchema)
	}
	return &c, nil
}

// saveCredential writes the envelope atomically at 0600.
func saveCredential(storageDir string, c *sealedCredential) error {
	if err := os.MkdirAll(storageDir, 0o700); err != nil {
		return fmt.Errorf("create storage dir: %w", err)
	}
	c.Schema = envelopeSchema
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credential: %w", err)
	}
	final := credentialPath(storageDir)
	tmp, err := os.CreateTemp(storageDir, ".credential-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp credential: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp credential: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp credential: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp credential: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("rename credential: %w", err)
	}
	return nil
}
