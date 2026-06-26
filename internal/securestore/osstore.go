package securestore

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

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
