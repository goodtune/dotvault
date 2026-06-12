package groups

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"

	"github.com/go-ldap/ldap/v3"
)

// Dialer establishes LDAP connections with the package's TLS conventions
// (ldaps:// or StartTLS, optional CA pinning, ServerName derived from the
// URL host). It is shared by the group resolver and the admin API's
// password authenticator so the two cannot drift on connection semantics.
type Dialer struct {
	url      string
	startTLS bool
	tls      *tls.Config
}

// NewDialer validates the endpoint and prepares the TLS configuration.
func NewDialer(rawURL string, startTLS bool, caCert string) (*Dialer, error) {
	if rawURL == "" {
		return nil, fmt.Errorf("ldap: url is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("ldap: parse url: %w", err)
	}
	if u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return nil, fmt.Errorf("ldap: url scheme must be ldap or ldaps, got %q", u.Scheme)
	}
	if u.Scheme == "ldaps" && startTLS {
		// StartTLS upgrades a plaintext connection; ldaps is already TLS.
		// Attempting the upgrade on an encrypted session fails confusingly
		// at runtime, so refuse the combination at config time.
		return nil, fmt.Errorf("ldap: start_tls cannot be combined with an ldaps:// url (the connection is already TLS)")
	}

	var tlsCfg *tls.Config
	if u.Scheme == "ldaps" || startTLS {
		tlsCfg = &tls.Config{ServerName: u.Hostname()}
		if caCert != "" {
			pem, err := os.ReadFile(caCert)
			if err != nil {
				return nil, fmt.Errorf("ldap: read ca_cert: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("ldap: ca_cert %s: no certificates found", caCert)
			}
			tlsCfg.RootCAs = pool
		}
	}
	return &Dialer{url: rawURL, startTLS: startTLS, tls: tlsCfg}, nil
}

// Dial opens a connection, upgrading via StartTLS when configured. The
// caller closes the connection.
func (d *Dialer) Dial() (*ldap.Conn, error) {
	var opts []ldap.DialOpt
	if d.tls != nil && !d.startTLS {
		opts = append(opts, ldap.DialWithTLSConfig(d.tls))
	}
	conn, err := ldap.DialURL(d.url, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", d.url, err)
	}
	if d.startTLS {
		if err := conn.StartTLS(d.tls); err != nil {
			conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}
	return conn, nil
}
