package securestore

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// CNG NCRYPT_EXPORT_POLICY_PROPERTY flags. A key with neither bit set is
// non-exportable (NCRYPT_ALLOW_EXPORT_NONE) — the default for a key created with
// NCryptCreatePersistedKey, which is how the "os" backend generates its key. We
// verify this rather than assume it (see assertNonExportable in
// osstore_windows.go). The archiving flags (0x4/0x8) are deliberately not in the
// mask: they govern backup/escrow, not the plaintext-key extraction the user is
// protecting against.
const (
	cngAllowExport          = 0x1 // NCRYPT_ALLOW_EXPORT_FLAG
	cngAllowPlaintextExport = 0x2 // NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
)

// exportPolicyIsExportable reports whether a CNG export-policy value permits the
// private key to be extracted from the store. It is the security-critical
// interpretation of the raw policy DWORD, kept in a platform-neutral file so it
// is unit-testable on every platform (the read that produces the DWORD is a
// Windows syscall).
func exportPolicyIsExportable(policy uint32) bool {
	return policy&(cngAllowExport|cngAllowPlaintextExport) != 0
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
