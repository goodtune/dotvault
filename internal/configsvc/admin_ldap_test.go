package configsvc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestLDAPAuthenticatorRejectsEmptyCredentialsLocally(t *testing.T) {
	// An empty password must short-circuit to ErrBadCredentials without
	// touching the network: a DN bind with no password is an *anonymous*
	// bind, which many directories accept — the classic LDAP login bypass.
	// The URL points at a black-hole address; if the authenticator dialled,
	// the context deadline would fail the test with a different error.
	a, err := newLDAPAuthenticator(AdminLDAPConfig{
		URL:            "ldap://192.0.2.1", // TEST-NET, unroutable
		UserDNTemplate: "uid=%s,dc=example,dc=com",
	})
	if err != nil {
		t.Fatalf("newLDAPAuthenticator: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	for _, tc := range []struct{ user, pass string }{
		{"alice", ""},
		{"", "password"},
		{"  ", "password"},
	} {
		if err := a.Authenticate(ctx, tc.user, tc.pass); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("Authenticate(%q, %q) = %v, want ErrBadCredentials", tc.user, tc.pass, err)
		}
	}
}

func TestLDAPAuthenticatorDNTemplateEscapes(t *testing.T) {
	a := &ldapAuthenticator{cfg: AdminLDAPConfig{UserDNTemplate: "uid=%s,ou=people,dc=example,dc=com"}}
	dn, err := a.resolveUserDN(nil, "ali,ce=admin")
	if err != nil {
		t.Fatalf("resolveUserDN: %v", err)
	}
	// RFC 4514: ',' must be escaped in a value; '=' is legal unescaped.
	if want := `uid=ali\,ce=admin,ou=people,dc=example,dc=com`; dn != want {
		t.Fatalf("resolveUserDN = %q, want %q (DN metacharacters escaped)", dn, want)
	}
}

// fakeLDAPConn drives the search-then-bind branch without a directory.
type fakeLDAPConn struct {
	bindErr    error
	boundAs    []string
	entries    []*ldap.Entry
	searchErr  error
	lastFilter string
}

func (f *fakeLDAPConn) Bind(username, password string) error {
	f.boundAs = append(f.boundAs, username)
	return f.bindErr
}

func (f *fakeLDAPConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.lastFilter = req.Filter
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	return &ldap.SearchResult{Entries: f.entries}, nil
}

func TestLDAPAuthenticatorSearchThenBind(t *testing.T) {
	a := &ldapAuthenticator{cfg: AdminLDAPConfig{
		BindDN:           "cn=svc,dc=example,dc=com",
		BindPassword:     "svc-secret",
		UserSearchBaseDN: "ou=people,dc=example,dc=com",
		UserSearchFilter: "(uid=%s)",
	}}

	t.Run("single match returns its DN, filter escaped", func(t *testing.T) {
		conn := &fakeLDAPConn{entries: []*ldap.Entry{{DN: "uid=alice,ou=people,dc=example,dc=com"}}}
		dn, err := a.resolveUserDN(conn, "ali*ce")
		if err != nil {
			t.Fatalf("resolveUserDN: %v", err)
		}
		if dn != "uid=alice,ou=people,dc=example,dc=com" {
			t.Fatalf("dn = %q", dn)
		}
		if conn.lastFilter != `(uid=ali\2ace)` {
			t.Fatalf("filter = %q, want metacharacters escaped", conn.lastFilter)
		}
		if len(conn.boundAs) != 1 || conn.boundAs[0] != "cn=svc,dc=example,dc=com" {
			t.Fatalf("service bind = %v", conn.boundAs)
		}
	})

	t.Run("zero matches collapse to bad credentials", func(t *testing.T) {
		conn := &fakeLDAPConn{}
		if _, err := a.resolveUserDN(conn, "ghost"); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("err = %v, want ErrBadCredentials", err)
		}
	})

	t.Run("ambiguous matches collapse to bad credentials", func(t *testing.T) {
		conn := &fakeLDAPConn{entries: []*ldap.Entry{{DN: "uid=a,dc=x"}, {DN: "uid=b,dc=x"}}}
		if _, err := a.resolveUserDN(conn, "dup"); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("err = %v, want ErrBadCredentials (binding as 'the first' would be a coin toss)", err)
		}
	})

	t.Run("service bind failure surfaces as backend error", func(t *testing.T) {
		conn := &fakeLDAPConn{bindErr: errors.New("invalid service credentials")}
		_, err := a.resolveUserDN(conn, "alice")
		if err == nil || errors.Is(err, ErrBadCredentials) {
			t.Fatalf("err = %v, want a non-credential backend error", err)
		}
	})
}
