package integration

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/clientcert"
	"github.com/goodtune/dotvault/internal/clientcert/source"
	"github.com/goodtune/dotvault/internal/vault"
)

// Short-lived client certificates against a real Vault.
//
// The unit tests for the ephemeral source use a fake Signer, so they never
// prove that the pieces fit a real PKI engine: the CSR Vault accepts, the
// chain it returns, the lifetime it grants after applying the role's own
// limits, and above all that the common-name variable {{.token_username}}
// resolves from a real token's metadata, including after the token has been
// downscoped. These tests close that gap.
//
// Requires the docker-compose stack (`docker compose up -d`): vault-init
// provisions the pki mount, the dotvault-tools role and the dotvault policy
// (which grants pki/sign/dotvault-tools, auth/token/create and
// auth/token/lookup-self) that these tests depend on.

const (
	clientCertTestRole = "dotvault-tools"
	clientCertTestUser = "testuser"
	clientCertTestTTL  = 5 * time.Minute
)

// newClientCertTestToken mints a token carrying the dotvault policy and the
// metadata an LDAP or userpass login would record. The dev stack has neither
// auth method, so the root token creates it directly with the same
// meta.username field the real methods set.
func newClientCertTestToken(t *testing.T, root *vault.Client) string {
	t.Helper()
	secret, err := root.Raw().Auth().Token().CreateWithContext(context.Background(), &vaultapi.TokenCreateRequest{
		Policies:    []string{"dotvault"},
		Metadata:    map[string]string{"username": clientCertTestUser},
		TTL:         "10m",
		DisplayName: "clientcert-integration",
	})
	if err != nil {
		t.Fatalf("create test token: %v", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		t.Fatal("create test token: no client token in the response")
	}
	return secret.Auth.ClientToken
}

// pkiRootCA reads the PKI mount's root certificate, the trust anchor the
// issued certificate must chain to.
func pkiRootCA(t *testing.T, root *vault.Client) *x509.Certificate {
	t.Helper()
	secret, err := root.Raw().Logical().ReadWithContext(context.Background(), testPKIMount+"/cert/ca")
	if err != nil || secret == nil {
		t.Fatalf("read %s/cert/ca: %v", testPKIMount, err)
	}
	s, _ := secret.Data["certificate"].(string)
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		t.Fatal("pki/cert/ca returned no certificate")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse pki root: %v", err)
	}
	return ca
}

// signClientCert runs the ephemeral source over a real vault.Client holding
// token and returns the pair it signs.
func signClientCert(t *testing.T, token string) *clientcert.Pair {
	t.Helper()
	vc, err := vault.NewClient(vault.Config{Address: "http://127.0.0.1:8200", Token: token})
	if err != nil {
		t.Fatalf("vault client: %v", err)
	}
	src, err := source.NewEphemeral(vc, source.EphemeralOptions{
		PKIMount:   testPKIMount,
		PKIRole:    clientCertTestRole,
		CommonName: "{{.token_username}}",
		TTL:        clientCertTestTTL,
		OSUser:     "somebody-else", // must NOT end up in the subject
	})
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pair, err := src.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	return pair
}

// assertClientCert checks what a service on the far end would: the subject,
// the chain to the PKI root, the client-auth usage, and a lifetime close to
// the one asked for.
func assertClientCert(t *testing.T, pair *clientcert.Pair, root *x509.Certificate) {
	t.Helper()

	if pair.Source != clientcert.SourceEphemeral {
		t.Errorf("Source = %q, want %q", pair.Source, clientcert.SourceEphemeral)
	}
	if pair.CommonName != clientCertTestUser {
		t.Errorf("Pair.CommonName = %q, want %q", pair.CommonName, clientCertTestUser)
	}

	block, _ := pem.Decode(pair.CertPEM)
	if block == nil {
		t.Fatal("client.crt holds no PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.Subject.CommonName != clientCertTestUser {
		t.Errorf("certificate CN = %q, want %q", leaf.Subject.CommonName, clientCertTestUser)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("certificate does not chain to the PKI root for client auth: %v", err)
	}

	// Vault backdates NotBefore by 30s (not_before_duration) to tolerate
	// clock skew, so the lifetime is the TTL plus that; allow a minute.
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	if life < clientCertTestTTL || life > clientCertTestTTL+time.Minute {
		t.Errorf("lifetime = %s, want about %s", life, clientCertTestTTL)
	}

	// The key must be the one the certificate was issued for.
	if _, err := pair.TLSCertificate(); err != nil {
		t.Errorf("certificate and key do not form a usable pair: %v", err)
	}
}

func TestClientCertEphemeralAgainstVault(t *testing.T) {
	skipIfNoVault(t)

	root, err := vault.NewClient(vault.Config{Address: "http://127.0.0.1:8200", Token: rootToken(t)})
	if err != nil {
		t.Fatalf("root client: %v", err)
	}
	ca := pkiRootCA(t, root)
	token := newClientCertTestToken(t, root)

	t.Run("signs with the token's username", func(t *testing.T) {
		assertClientCert(t, signClientCert(t, token), ca)
	})

	// A downscoped child normally has no metadata of its own; Downscope
	// carries the parent's across, which is what keeps {{.token_username}}
	// working on a least-privilege token (and on one borrowed from a peer).
	t.Run("still signs after the token is downscoped", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		child, err := auth.Downscope(ctx, root, token, auth.PolicyConstraint{Policies: []string{"dotvault"}})
		if err != nil {
			t.Fatalf("Downscope: %v", err)
		}
		if child == token {
			t.Fatal("Downscope returned the parent token unchanged; the test would prove nothing")
		}
		assertClientCert(t, signClientCert(t, child), ca)
	})
}
