package groups

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig configures the directory-backed resolver. The YAML tags are the
// `groups.ldap` block of the service config.
type LDAPConfig struct {
	// URL is the directory endpoint (ldap:// or ldaps://). Required.
	URL string `yaml:"url"`
	// StartTLS upgrades a plain ldap:// connection before binding.
	StartTLS bool `yaml:"start_tls"`
	// CACert optionally pins the CA bundle for ldaps:// / StartTLS.
	CACert string `yaml:"ca_cert"`
	// BindDN and the bind password authenticate the service to the
	// directory. Empty BindDN means an anonymous bind.
	BindDN string `yaml:"bind_dn"`
	// BindPassword is the literal password. Prefer BindPasswordFile in
	// deployed configs so the secret stays out of the config file.
	BindPassword string `yaml:"bind_password"`
	// BindPasswordFile is read on every lookup, so a rotated secret needs
	// no restart.
	BindPasswordFile string `yaml:"bind_password_file"`
	// BaseDN is the subtree searched for group entries. Required.
	BaseDN string `yaml:"base_dn"`
	// Filter is the group search filter with a single %s placeholder for
	// the (escaped) username, e.g.
	// "(&(objectClass=groupOfNames)(member=uid=%s,ou=people,dc=example,dc=com))".
	// Required.
	Filter string `yaml:"filter"`
	// Attribute is the entry attribute carrying the group name. Default
	// "cn".
	Attribute string `yaml:"attribute"`
}

type ldapResolver struct {
	cfg LDAPConfig
	tls *tls.Config
}

// NewLDAP validates cfg and returns the directory-backed Resolver. Each
// lookup dials a fresh connection — the TTL cache in front keeps the
// directory load proportional to distinct users per TTL window, and a
// connection pool is not worth its failure modes at this request rate.
func NewLDAP(cfg LDAPConfig) (Resolver, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("ldap resolver: url is required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("ldap resolver: parse url: %w", err)
	}
	if u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return nil, fmt.Errorf("ldap resolver: url scheme must be ldap or ldaps, got %q", u.Scheme)
	}
	if cfg.BaseDN == "" {
		return nil, fmt.Errorf("ldap resolver: base_dn is required")
	}
	if !strings.Contains(cfg.Filter, "%s") {
		return nil, fmt.Errorf("ldap resolver: filter must contain a %%s placeholder for the username")
	}
	if cfg.BindPassword != "" && cfg.BindPasswordFile != "" {
		return nil, fmt.Errorf("ldap resolver: bind_password and bind_password_file are mutually exclusive")
	}
	if cfg.Attribute == "" {
		cfg.Attribute = "cn"
	}

	var tlsCfg *tls.Config
	if u.Scheme == "ldaps" || cfg.StartTLS {
		tlsCfg = &tls.Config{ServerName: u.Hostname()}
		if cfg.CACert != "" {
			pem, err := os.ReadFile(cfg.CACert)
			if err != nil {
				return nil, fmt.Errorf("ldap resolver: read ca_cert: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("ldap resolver: ca_cert %s: no certificates found", cfg.CACert)
			}
			tlsCfg.RootCAs = pool
		}
	}
	return &ldapResolver{cfg: cfg, tls: tlsCfg}, nil
}

func (r *ldapResolver) Groups(ctx context.Context, user string) ([]string, error) {
	conn, err := r.dial()
	if err != nil {
		return nil, fmt.Errorf("ldap: %w", err)
	}
	defer conn.Close()

	// go-ldap's synchronous Search has no context plumbing; approximate the
	// caller's deadline with the connection-level timeout.
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetTimeout(time.Until(deadline))
	}

	if r.cfg.BindDN != "" {
		password, err := r.bindPassword()
		if err != nil {
			return nil, fmt.Errorf("ldap: %w", err)
		}
		if err := conn.Bind(r.cfg.BindDN, password); err != nil {
			return nil, fmt.Errorf("ldap bind as %s: %w", r.cfg.BindDN, err)
		}
	}

	req := ldap.NewSearchRequest(
		r.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter(r.cfg.Filter, user),
		[]string{r.cfg.Attribute}, nil)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap search for %q: %w", user, err)
	}

	var groups []string
	for _, entry := range res.Entries {
		if name := entry.GetAttributeValue(r.cfg.Attribute); name != "" {
			groups = append(groups, name)
		}
	}
	return groups, nil
}

func (r *ldapResolver) dial() (*ldap.Conn, error) {
	var opts []ldap.DialOpt
	if r.tls != nil && !r.cfg.StartTLS {
		opts = append(opts, ldap.DialWithTLSConfig(r.tls))
	}
	conn, err := ldap.DialURL(r.cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", r.cfg.URL, err)
	}
	if r.cfg.StartTLS {
		if err := conn.StartTLS(r.tls); err != nil {
			conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}
	return conn, nil
}

func (r *ldapResolver) bindPassword() (string, error) {
	if r.cfg.BindPasswordFile == "" {
		return r.cfg.BindPassword, nil
	}
	raw, err := os.ReadFile(r.cfg.BindPasswordFile)
	if err != nil {
		return "", fmt.Errorf("read bind_password_file: %w", err)
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}

// searchFilter substitutes the escaped username into the configured filter.
// Escaping is non-negotiable: the username arrives from a client-asserted
// header, and an unescaped value could rewrite the filter.
func searchFilter(filter, user string) string {
	return strings.ReplaceAll(filter, "%s", ldap.EscapeFilter(user))
}
