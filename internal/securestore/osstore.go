package securestore

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// CNG NCRYPT_EXPORT_POLICY_PROPERTY flags. A key with none of these bits set is
// non-exportable (NCRYPT_ALLOW_EXPORT_NONE) — the default for a key created with
// NCryptCreatePersistedKey, which is how the "os" backend generates its key. We
// verify this rather than assume it (see assertNonExportable in
// osstore_windows.go).
//
// All four flags count as exportable, archiving included. The archiving flags
// are not a backup-only concession: Microsoft defines them as permitting the
// private key to be exported *once* (0x8 in plaintext), and a one-time export is
// still an extraction. Whoever performs it walks away with the key and can reuse
// the Vault-issued identity on another machine, which is precisely the invariant
// assertNonExportable exists to enforce. Do not narrow this mask.
//
// https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers#ncrypt_export_policy_property
const (
	cngAllowExport             = 0x1 // NCRYPT_ALLOW_EXPORT_FLAG
	cngAllowPlaintextExport    = 0x2 // NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
	cngAllowArchiving          = 0x4 // NCRYPT_ALLOW_ARCHIVING_FLAG — one-time export
	cngAllowPlaintextArchiving = 0x8 // NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG — one-time plaintext export
)

// exportPolicyIsExportable reports whether a CNG export-policy value permits the
// private key to be extracted from the store. It is the security-critical
// interpretation of the raw policy DWORD, kept in a platform-neutral file so it
// is unit-testable on every platform (the read that produces the DWORD is a
// Windows syscall).
func exportPolicyIsExportable(policy uint32) bool {
	return policy&(cngAllowExport|cngAllowPlaintextExport|cngAllowArchiving|cngAllowPlaintextArchiving) != 0
}

// parseLeafAndIssuer splits a PEM chain (leaf followed by its CA chain) into the
// leaf and its immediate issuer. The OS-native backend's StoreCert needs both:
// certtostore.Store dereferences the intermediate unconditionally, so an issuing
// CA is required — Vault PKI returns it via ca_chain / issuing_ca, which the edge
// case of a root signing leaves directly does not satisfy.
//
// It lives in a platform-neutral file (rather than osstore_windows.go) so it is
// unit-testable on every platform — it depends only on the standard library.
func parseLeafAndIssuer(certPEM string) (leaf, issuer *x509.Certificate, err error) {
	var certs []*x509.Certificate
	rest := []byte(certPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, perr := x509.ParseCertificate(block.Bytes)
		if perr != nil {
			return nil, nil, fmt.Errorf("parse certificate in chain: %w", perr)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, nil, errors.New("no CERTIFICATE block in issued credential")
	}
	if len(certs) < 2 {
		return nil, nil, errors.New("the OS-native certificate store requires the PKI to return its issuing CA chain (ca_chain / issuing_ca); none was present")
	}
	return certs[0], certs[1], nil
}

// Key-container naming for the OS backend.
//
// The backend originally generated into one fixed container. That made rotation
// destructive: certtostore's Generate passes NCRYPT_OVERWRITE_KEY_FLAG, so
// minting a replacement key obliterated the key matching the still-current
// certificate and envelope — any failure between Generate and the replacement
// cert login (PKI sign, cert install, envelope write, login) left the host with
// a credential it could no longer use and no way back.
//
// Rotation is therefore two-phase. Generate mints into a *fresh* container
// (osContainerPrefix + random suffix) and the caller keeps using the old
// credential until the replacement is fully committed — envelope persisted and
// cert login done — at which point CommitCert removes the superseded container
// and leaf. A failure before that point is undone by RollbackCert, which
// removes only the uncommitted replacement.
const (
	// osContainerPrefix prefixes every container this backend generates.
	osContainerPrefix = "dotvault-mtls-"
	// osLegacyContainer is the single fixed container name used before
	// rotation became two-phase. Envelopes written by that version still name
	// it, so it stays loadable (and is deleted like any other superseded
	// container the first time a rotation commits).
	osLegacyContainer = "dotvault-mtls"
)

// newOSContainer returns a fresh, unique CNG key-container name. Uniqueness is
// what makes rotation non-destructive: the replacement key cannot overwrite the
// one the current certificate depends on.
func newOSContainer() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate key container name: %w", err)
	}
	return osContainerPrefix + hex.EncodeToString(b[:]), nil
}

// validOSContainer reports whether name is a container this backend owns: one
// it generated (prefix + hex suffix) or the legacy fixed name. Anything else
// comes from a corrupted envelope or a different deployment, and operating on
// it would mean deleting or signing with a key that is not ours.
func validOSContainer(name string) bool {
	if name == osLegacyContainer {
		return true
	}
	suffix, ok := strings.CutPrefix(name, osContainerPrefix)
	if !ok || suffix == "" {
		return false
	}
	if _, err := hex.DecodeString(suffix); err != nil {
		return false
	}
	return strings.ToLower(suffix) == suffix
}

// osHandle is the opaque securestore handle for the OS backend. It records only
// where the credential lives — the CNG provider and key container, plus the
// SHA-1 thumbprint of the leaf certificate installed in CurrentUser\My. The key
// material itself never leaves the OS store. Load reopens the key by container
// name (CNG's NCryptOpenKey), so the container is the stable association across
// restarts; the thumbprint is what lets a superseded leaf be found and deleted
// once its replacement commits.
type osHandle struct {
	Provider   string `json:"provider"`
	Container  string `json:"container"`
	Thumbprint string `json:"thumbprint,omitempty"`
}

// encodeOSHandle marshals a handle for persistence in the credential envelope.
func encodeOSHandle(h osHandle) ([]byte, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("marshal os handle: %w", err)
	}
	return b, nil
}

// decodeOSHandle parses and sanity-checks a handle. It rejects a handle whose
// container is not one this backend owns: the key lookup keys off that name, so
// a foreign value could only come from a corrupted envelope or a different
// deployment, and failing loudly beats silently operating on the wrong key —
// or, worse, deleting one.
func decodeOSHandle(handle []byte) (osHandle, error) {
	var h osHandle
	if err := json.Unmarshal(handle, &h); err != nil {
		return osHandle{}, fmt.Errorf("decode os handle: %w", err)
	}
	if h.Container == "" {
		return osHandle{}, errors.New("securestore: os handle has no container")
	}
	if !validOSContainer(h.Container) {
		return osHandle{}, fmt.Errorf("securestore: os handle container %q is not a dotvault key container", h.Container)
	}
	return h, nil
}

// certSHA1Thumbprint returns the uppercase hex SHA-1 of a DER certificate — the
// "thumbprint" Windows itself displays and indexes certificates by. SHA-1 is
// used as an identifier here, not as a security primitive: the value only ever
// selects which certificate in CurrentUser\My to delete, and the certificate we
// are looking for is one we installed moments earlier.
func certSHA1Thumbprint(der []byte) string {
	sum := sha1.Sum(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// supersededOSArtifacts reports the key container and leaf-certificate
// thumbprint that become garbage once newHandle supersedes oldHandle. Either
// may be empty, meaning "nothing to remove":
//
//   - a first seed has no old handle at all;
//   - a re-issue that somehow reused the container (or the leaf) must not
//     delete the artefact the new credential is using — hence the inequality
//     tests rather than an unconditional delete of the old values.
//
// It is a pure function so the destructive decision is unit-testable on every
// platform; the Windows file only executes what it returns.
func supersededOSArtifacts(newHandle, oldHandle osHandle) (container, thumbprint string) {
	if oldHandle.Container != "" && oldHandle.Container != newHandle.Container {
		container = oldHandle.Container
	}
	if oldHandle.Thumbprint != "" && oldHandle.Thumbprint != newHandle.Thumbprint {
		thumbprint = oldHandle.Thumbprint
	}
	return container, thumbprint
}
