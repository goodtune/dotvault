package auth

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/goodtune/dotvault/internal/vault"
)

// PolicyConstraint describes the least-privilege downscoping applied to a
// freshly-minted login token. Its two fields come straight from the vault
// config (vault.policies / vault.no_default_policy).
//
// The zero value applies no narrowing — the working token carries every policy
// the auth role granted, which is dotvault's historical behaviour. Operators
// opt in to least privilege by populating Policies (and, increasingly,
// NoDefaultPolicy); see docs/configuration/config-reference.md for the staged
// rollout that ends with no_default_policy forced on at 1.0.
type PolicyConstraint struct {
	// Policies is the explicit set of Vault policies the working token should
	// carry. When non-empty the login token is exchanged for a child token
	// restricted to exactly these policies (a subset of the login token's own
	// policies — Vault enforces the subset rule). Empty means "carry whatever
	// the auth role granted".
	Policies []string
	// NoDefaultPolicy, when true, strips the implicit `default` policy from the
	// downscoped token.
	NoDefaultPolicy bool
}

// Active reports whether any narrowing is requested. With neither an explicit
// policy set nor no_default_policy, the login token is adopted verbatim.
func (c PolicyConstraint) Active() bool {
	return len(c.Policies) > 0 || c.NoDefaultPolicy
}

// Downscope exchanges a freshly-minted broad login token for a least-privilege
// child token carrying only the configured policies, when the constraint is
// active. The child is minted on an isolated sibling of vc (CreateChildTokenFor)
// so vc itself is never set to the broad token — Vault still enforces that the
// requested policies are a subset of the parent's, so this can only drop
// privilege. Returns the token the caller should adopt and persist: the
// downscoped child when a constraint is active, otherwise the original token
// unchanged.
//
// Crucially, Downscope never mutates vc. On both the active-success and the
// failure paths the caller's shared client is left exactly as it was, so a
// downscope failure cannot leave the broad token installed on (or retrievable
// from) the web server's shared client, and there is no window in which a
// concurrent reader observes the broad token. The caller is therefore
// responsible for adopting the returned token — it must call vc.SetToken on the
// result itself; Downscope deliberately does not.
//
// A downscoping failure is returned as an error rather than silently falling
// back to the broad token: least privilege must fail closed. The caller treats
// it like any other login failure.
//
// When no constraint is configured, Downscope logs a one-line transition
// warning (fresh logins are infrequent, so this is not noisy) nudging the
// operator toward vault.policies before a future release makes restriction the
// default. The warning is suppressed once the operator has opted in.
func Downscope(ctx context.Context, vc *vault.Client, token string, c PolicyConstraint) (string, error) {
	if !c.Active() {
		slog.Warn("vault token carries every policy the auth role granted; set vault.policies (and vault.no_default_policy: true) to restrict it to least privilege — a future dotvault release will make no_default_policy default true and 1.0 will remove the ability to disable it")
		return token, nil
	}
	child, err := vc.CreateChildTokenFor(ctx, token, c.Policies, c.NoDefaultPolicy)
	if err != nil {
		return "", fmt.Errorf("downscope token to least privilege: %w", err)
	}
	slog.Info("downscoped vault token to least-privilege policy set",
		"policies", c.Policies, "no_default_policy", c.NoDefaultPolicy)
	return child, nil
}
