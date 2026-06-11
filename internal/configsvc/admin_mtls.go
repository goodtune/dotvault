package configsvc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// MTLSServerConfig builds the TLS configuration for the service-account
// listener. The security properties, in order of enforcement:
//
//  1. ClientCAs is exactly the pinned CA bundle from admin.mtls.ca_cert —
//     intended to be a dedicated Vault PKI intermediate minted for this
//     purpose. Because the service trusts nothing else, the Vault PKI
//     role's issuance policy (allowed names, clientAuth EKU, short
//     max_ttl) IS the access policy.
//  2. RequireAndVerifyClientCert makes the handshake fail without a valid
//     client certificate; Go's verifier additionally enforces the
//     validity window and the clientAuth extended key usage.
//  3. The certificate's CN must then match a registered, enabled service
//     account (checked per request in identify) — so deleting or
//     disabling the account revokes access immediately, and revocation
//     lists are unnecessary when certificates are short-lived.
func MTLSServerConfig(cfg AdminMTLSConfig) (*tls.Config, error) {
	pem, err := os.ReadFile(cfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("read admin.mtls.ca_cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("admin.mtls.ca_cert %s: no certificates found", cfg.CACert)
	}
	return &tls.Config{
		ClientCAs:  pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// NewAdminAuthenticator builds the password authenticator for the admin
// config, or nil when LDAP login is not configured (mTLS-only deployments).
func NewAdminAuthenticator(cfg AdminConfig) (PasswordAuthenticator, error) {
	if cfg.LDAP.URL == "" {
		return nil, nil
	}
	return newLDAPAuthenticator(cfg.LDAP)
}
