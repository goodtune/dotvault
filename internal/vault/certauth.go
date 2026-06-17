package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/goodtune/dotvault/internal/observability"
)

// LoginCert authenticates via the TLS cert auth method. The client must have
// been built with a ClientCert so the certificate is presented during the
// handshake; Vault matches it against the registered CA and the named role's
// policies. On success the returned token is adopted onto the client.
func (c *Client) LoginCert(ctx context.Context, mount, role string) error {
	if mount == "" {
		mount = "cert"
	}
	data := map[string]interface{}{}
	if role != "" {
		// The cert auth method calls the role parameter "name".
		data["name"] = role
	}
	secret, err := c.raw.Logical().WriteWithContext(ctx, fmt.Sprintf("auth/%s/login", mount), data)
	if err != nil {
		observability.RecordVaultCall(ctx, "login_cert", classifyVaultErr(err))
		return fmt.Errorf("cert auth login: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		observability.RecordVaultCall(ctx, "login_cert", "client_error")
		return fmt.Errorf("cert auth login: no token in response")
	}
	observability.RecordVaultCall(ctx, "login_cert", "ok")
	c.raw.SetToken(secret.Auth.ClientToken)
	return nil
}

// IssuedCert is the result of a PKI issue or sign operation.
type IssuedCert struct {
	// CertPEM is the leaf certificate followed by any CA chain, PEM-encoded.
	CertPEM string
	// PrivateKeyPEM is populated only by IssueCertificate (Vault generates the
	// key). SignCSR leaves it empty because the key never left the host.
	PrivateKeyPEM string
	// Serial is the certificate serial number, for audit/revocation.
	Serial string
}

// SignCSR submits a CSR to the PKI engine's sign endpoint and returns the
// signed certificate. The private key behind the CSR never leaves the host —
// this is the preferred issuance path for both mtls and mtls+tpm.
func (c *Client) SignCSR(ctx context.Context, mount, role, csrPEM, commonName, ttl string) (*IssuedCert, error) {
	data := map[string]interface{}{
		"csr":    csrPEM,
		"format": "pem",
	}
	if commonName != "" {
		data["common_name"] = commonName
	}
	if ttl != "" {
		data["ttl"] = ttl
	}
	path := fmt.Sprintf("%s/sign/%s", strings.Trim(mount, "/"), role)
	return c.pkiWrite(ctx, "pki_sign", path, data)
}

// IssueCertificate asks the PKI engine to generate a keypair and certificate.
// Used only when the PKI role forbids the sign endpoint; the returned
// PrivateKeyPEM must be handed to the secure store immediately.
func (c *Client) IssueCertificate(ctx context.Context, mount, role, commonName, ttl string) (*IssuedCert, error) {
	data := map[string]interface{}{
		"format": "pem",
	}
	if commonName != "" {
		data["common_name"] = commonName
	}
	if ttl != "" {
		data["ttl"] = ttl
	}
	path := fmt.Sprintf("%s/issue/%s", strings.Trim(mount, "/"), role)
	return c.pkiWrite(ctx, "pki_issue", path, data)
}

func (c *Client) pkiWrite(ctx context.Context, op, path string, data map[string]interface{}) (*IssuedCert, error) {
	secret, err := c.raw.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		observability.RecordVaultCall(ctx, op, classifyVaultErr(err))
		return nil, fmt.Errorf("%s %s: %w", op, path, err)
	}
	if secret == nil || secret.Data == nil {
		observability.RecordVaultCall(ctx, op, "client_error")
		return nil, fmt.Errorf("%s %s: empty response", op, path)
	}
	observability.RecordVaultCall(ctx, op, "ok")

	leaf, _ := secret.Data["certificate"].(string)
	if leaf == "" {
		return nil, fmt.Errorf("%s %s: no certificate in response", op, path)
	}

	out := &IssuedCert{Serial: stringField(secret.Data, "serial_number")}
	out.PrivateKeyPEM = stringField(secret.Data, "private_key")

	// Append the CA chain so the assembled tls.Certificate presents the full
	// path Vault's cert auth method needs to verify. ca_chain is a list;
	// issuing_ca is the single-CA fallback on older PKI mounts.
	chain := []string{strings.TrimRight(leaf, "\n")}
	switch v := secret.Data["ca_chain"].(type) {
	case []interface{}:
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				chain = append(chain, strings.TrimRight(s, "\n"))
			}
		}
	default:
		if ca := stringField(secret.Data, "issuing_ca"); ca != "" {
			chain = append(chain, strings.TrimRight(ca, "\n"))
		}
	}
	out.CertPEM = strings.Join(chain, "\n") + "\n"
	return out, nil
}

func stringField(data map[string]any, key string) string {
	s, _ := data[key].(string)
	return s
}
