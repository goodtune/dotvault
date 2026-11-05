package source

import (
	"context"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/goodtune/dotvault/internal/vault"
)

// Signer is the slice of the Vault client the ephemeral source needs. Token
// reads the client's current token; the two calls take a token explicitly, so
// one sign is made entirely under the token it started with even if another
// goroutine (a re-login, a borrow, the client facade replacing a rejected
// token) installs a different one on the shared client meanwhile.
type Signer interface {
	Token() string
	LookupSelfWithToken(ctx context.Context, token string) (*vaultapi.Secret, error)
	SignCSRWithToken(ctx context.Context, token, mount, role, csrPEM, commonName, ttl string) (*vault.IssuedCert, error)
}

var _ Signer = (*vault.Client)(nil)
