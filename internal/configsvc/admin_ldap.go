package configsvc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/goodtune/dotvault/internal/configsvc/groups"
)

// ErrBadCredentials is returned for any authentication failure the caller
// should present as "invalid username or password" — deliberately one
// sentinel so the login handler cannot leak whether the user exists.
var ErrBadCredentials = errors.New("invalid username or password")

// PasswordAuthenticator verifies a username/password pair. The production
// implementation binds against LDAP; tests inject fakes.
type PasswordAuthenticator interface {
	Authenticate(ctx context.Context, username, password string) error
}

// AdminLDAPConfig configures human-admin authentication: a credential bind
// against the directory. The user's DN is derived either from a template
// (flat trees) or a search (directories where the DN is not derivable from
// the username). Group membership for the admin check is NOT resolved here —
// that goes through the service's configured groups resolver, so admins are
// defined in the same membership source that drives layer composition.
type AdminLDAPConfig struct {
	// URL, StartTLS, CACert have the same semantics as groups.ldap. This
	// is its own block (rather than reusing groups.ldap) because a
	// deployment may use static composition groups while authenticating
	// admins against a directory.
	URL      string `yaml:"url"`
	StartTLS bool   `yaml:"start_tls"`
	CACert   string `yaml:"ca_cert"`

	// UserDNTemplate derives the bind DN from the username, e.g.
	// "uid=%s,ou=people,dc=example,dc=com". The username is DN-escaped
	// before substitution. Mutually exclusive with the search fields.
	UserDNTemplate string `yaml:"user_dn_template"`

	// Search-based DN resolution: bind with the service credential, search
	// UserSearchBaseDN with UserSearchFilter (%s → escaped username,
	// exactly one entry required), then bind as the found DN.
	BindDN           string `yaml:"bind_dn"`
	BindPassword     string `yaml:"bind_password"`
	BindPasswordFile string `yaml:"bind_password_file"`
	UserSearchBaseDN string `yaml:"user_search_base_dn"`
	UserSearchFilter string `yaml:"user_search_filter"`
}

func (c AdminLDAPConfig) validate() error {
	if c.URL == "" {
		return fmt.Errorf("admin.ldap.url is required")
	}
	templated := c.UserDNTemplate != ""
	searched := c.UserSearchBaseDN != "" || c.UserSearchFilter != ""
	switch {
	case templated && searched:
		return fmt.Errorf("admin.ldap: user_dn_template and user_search_* are mutually exclusive")
	case !templated && !searched:
		return fmt.Errorf("admin.ldap: one of user_dn_template or user_search_base_dn + user_search_filter is required")
	case templated && !strings.Contains(c.UserDNTemplate, "%s"):
		return fmt.Errorf("admin.ldap.user_dn_template must contain a %%s username placeholder")
	case searched && (c.UserSearchBaseDN == "" || c.UserSearchFilter == ""):
		return fmt.Errorf("admin.ldap: user_search_base_dn and user_search_filter are both required for search-based login")
	case searched && !strings.Contains(c.UserSearchFilter, "%s"):
		return fmt.Errorf("admin.ldap.user_search_filter must contain a %%s username placeholder")
	}
	if c.BindPassword != "" && c.BindPasswordFile != "" {
		return fmt.Errorf("admin.ldap: bind_password and bind_password_file are mutually exclusive")
	}
	return nil
}

// ldapConn is the slice of *ldap.Conn the authenticator uses — an interface
// so the search-then-bind DN resolution is unit-testable without a live
// directory.
type ldapConn interface {
	Bind(username, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
}

type ldapAuthenticator struct {
	cfg    AdminLDAPConfig
	dialer *groups.Dialer
}

func newLDAPAuthenticator(cfg AdminLDAPConfig) (*ldapAuthenticator, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	dialer, err := groups.NewDialer(cfg.URL, cfg.StartTLS, cfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("admin.ldap: %w", err)
	}
	return &ldapAuthenticator{cfg: cfg, dialer: dialer}, nil
}

func (a *ldapAuthenticator) Authenticate(ctx context.Context, username, password string) error {
	// An empty password must be rejected before it reaches the directory:
	// LDAP treats a bind with a DN and no password as an *anonymous* bind,
	// which many servers accept — turning "no password" into a successful
	// login. Same for the username, which would make the DN nonsensical.
	if strings.TrimSpace(username) == "" || password == "" {
		return ErrBadCredentials
	}

	conn, err := a.dialer.Dial()
	if err != nil {
		return fmt.Errorf("ldap: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetTimeout(time.Until(deadline))
	}

	userDN, err := a.resolveUserDN(conn, username)
	if err != nil {
		return err
	}
	if err := conn.Bind(userDN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return ErrBadCredentials
		}
		return fmt.Errorf("ldap bind: %w", err)
	}
	return nil
}

func (a *ldapAuthenticator) resolveUserDN(conn ldapConn, username string) (string, error) {
	if a.cfg.UserDNTemplate != "" {
		return strings.ReplaceAll(a.cfg.UserDNTemplate, "%s", ldap.EscapeDN(username)), nil
	}

	if a.cfg.BindDN != "" {
		password, err := groups.ReadBindPassword(a.cfg.BindPassword, a.cfg.BindPasswordFile)
		if err != nil {
			return "", fmt.Errorf("admin.ldap: %w", err)
		}
		if err := conn.Bind(a.cfg.BindDN, password); err != nil {
			return "", fmt.Errorf("ldap service bind as %s: %w", a.cfg.BindDN, err)
		}
	}
	filter := strings.ReplaceAll(a.cfg.UserSearchFilter, "%s", ldap.EscapeFilter(username))
	res, err := conn.Search(ldap.NewSearchRequest(
		a.cfg.UserSearchBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		filter, []string{"dn"}, nil))
	if err != nil {
		return "", fmt.Errorf("ldap user search: %w", err)
	}
	if len(res.Entries) != 1 {
		// Zero entries is an unknown user; more than one means the filter
		// is ambiguous and binding as "the first" would be a coin toss.
		// Both collapse into the credential sentinel for the client.
		return "", ErrBadCredentials
	}
	return res.Entries[0].DN, nil
}
