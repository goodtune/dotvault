package configsvc

import (
	"context"
	"errors"
	"testing"
	"time"
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
