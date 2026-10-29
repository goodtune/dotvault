package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/vault"
)

// errCachedAuth marks a cachedVaultClient failure whose message is already
// the whole user-facing explanation, so callers print it as is rather than
// wrapping it in a second layer of context.
var errCachedAuth = errors.New("dotvault")

// cachedVaultClient builds a Vault client authenticated with a token this
// host already holds, for the one-shot commands that must never start an
// interactive login (`dotvault enrol`, `dotvault kv`). The order is the one
// `dotvault status` and the client/ facade's AuthenticateCached use: env and
// token file, then a borrow (this host's own daemon first, then the peers —
// see newBorrowChain), then, under mtls+os alone, a login with this host's
// certificate, which needs no human and so stays inside the no-prompt rule.
//
// The token is validated with LookupSelf before it is returned, and the two
// failure shapes are kept apart: a token Vault rejected is fixed by
// `dotvault login`, an unreachable Vault is not, and pointing the user at a
// login for the second would mask the real operational problem.
func cachedVaultClient(ctx context.Context, cfg *config.Config, username string) (*vault.Client, error) {
	vc, err := vault.NewClient(vault.Config{
		Address:       cfg.Vault.Address,
		CACert:        cfg.Vault.CACert,
		TLSSkipVerify: cfg.Vault.TLSSkipVerify,
	})
	if err != nil {
		return nil, fmt.Errorf("create vault client: %w", err)
	}

	// Same exclusion as Manager.Authenticate: a file present under mtls+os is
	// stale, and using it here would route around certLogin's removal. Under
	// borrow_only that exclusion does not apply (see
	// effectivePersistTokenAtRest) — auth_method is ignored entirely, so a
	// leftover token file is an ordinary manual-override candidate.
	token := resolveTokenForMethod(paths.VaultTokenPath(), effectivePersistTokenAtRest(cfg))
	if token == "" {
		// A borrowed token is held in memory only, exactly as everywhere else
		// a borrow happens: the lender stays its single owner.
		token, _ = authBorrowChain(cfg).Borrow(ctx)
	}
	// Under borrow_only, auth_method (mtls+os included) is ignored — see
	// config.VaultConfig.BorrowOnly and mtlsParams — so this host must never
	// derive a token from its own certificate store; falling through to the
	// plain "not authenticated" branch below is the correct outcome.
	if token == "" && !cfg.Vault.BorrowOnly && !auth.PersistTokenAtRest(cfg.Vault.AuthMethod) {
		// mtls+os keeps no token at rest, so an absent file is the normal state
		// rather than "not authenticated". Deriving one from the certificate is
		// the right answer here: it needs no human, so it does not violate the
		// rule against initiating a fresh *interactive* login, and refusing
		// instead would tell the user to run `dotvault login` for a method
		// where that is neither necessary nor meaningful.
		mgr := &auth.Manager{
			VaultClient: vc,
			// Wired so certLogin can REMOVE a stale file, not so it can write
			// one: this branch runs only when PersistTokenAtRest is false, so
			// the write arm is unreachable here. Leaving it empty made
			// RemoveTokenFile a no-op (an empty path means "do not persist"),
			// so a successful mtls+os cert login left a leftover plaintext
			// token sitting on disk — declining to *use* it, but not removing
			// it.
			TokenFilePath: paths.VaultTokenPath(),
			AuthMethod:    cfg.Vault.AuthMethod,
			AuthMount:     cfg.Vault.AuthMount,
			AuthRole:      cfg.Vault.AuthRole,
			Policy:        vaultPolicyConstraint(cfg),
			Username:      username,
			MTLS:          mtlsParams(cfg, username),
		}
		if err := mgr.CertLoginFromStore(ctx); err != nil {
			return nil, fmt.Errorf("%w: certificate login failed (%v); this host may need enrolling", errCachedAuth, err)
		}
		token = vc.Token()
	}
	if token == "" {
		if cfg.Vault.BorrowOnly {
			return nil, fmt.Errorf("%w: not authenticated; this host is borrow-only and no peer socket holds a token (run the daemon so it can borrow one)", errCachedAuth)
		}
		return nil, fmt.Errorf("%w: not authenticated; run `dotvault login` first", errCachedAuth)
	}
	vc.SetToken(token)
	if _, err := vc.LookupSelf(ctx); err != nil {
		if vault.IsForbidden(err) {
			return nil, fmt.Errorf("%w: cached vault token is invalid (%v); run `dotvault login` first", errCachedAuth, err)
		}
		return nil, fmt.Errorf("%w: vault unreachable (%v)", errCachedAuth, err)
	}
	return vc, nil
}
