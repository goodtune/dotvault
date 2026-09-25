package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/dotvault/internal/vault"
)

// mockVaultAccepting starts an httptest server standing in for Vault that
// accepts only the given token on lookup-self (any other token gets 403). It
// returns the server URL.
func mockVaultAccepting(t *testing.T, accepted string) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if accepted != "" && r.Header.Get("X-Vault-Token") == accepted {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"ttl": json.Number("3600")},
			})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string][]string{"errors": {"permission denied"}})
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

// TestManagerLogin_BorrowsFromSocket covers the headline production path: a
// Login with no usable local credential borrows a peer's token through the
// configured Borrower, validates it via LookupSelf, and returns without
// running the configured auth flow (here "token", which would otherwise
// error).
func TestManagerLogin_BorrowsFromSocket(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "") // hermetic: the borrower is the only source

	vaultURL := mockVaultAccepting(t, "peer-token")

	vc, err := vault.NewClient(vault.Config{Address: vaultURL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	m := &Manager{
		VaultClient: vc,
		AuthMethod:  "token", // a bare token method would error without a token
		Borrower:    &fakeBorrower{token: "peer-token", source: "/tmp/peer.sock"},
		Username:    "testuser",
	}
	if err := m.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got := vc.Token(); got != "peer-token" {
		t.Errorf("client token = %q after borrow, want %q", got, "peer-token")
	}
}

// TestManagerLogin_SocketTokenRejectedFallsThrough verifies that when the
// borrowed token fails LookupSelf, Login clears the in-memory token and falls
// through to the configured auth method (which here, "token", reports the
// usual no-token error).
func TestManagerLogin_SocketTokenRejectedFallsThrough(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")

	// The mock Vault accepts no token, so the borrowed one is rejected.
	vaultURL := mockVaultAccepting(t, "")

	vc, err := vault.NewClient(vault.Config{Address: vaultURL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	m := &Manager{
		VaultClient: vc,
		AuthMethod:  "token",
		Borrower:    &fakeBorrower{token: "rejected-token", source: "/tmp/peer.sock"},
		Username:    "testuser",
	}
	if err := m.Login(context.Background()); err == nil {
		t.Fatal("expected Login to fall through and error after the borrowed token was rejected")
	}
	if got := vc.Token(); got != "" {
		t.Errorf("in-memory token = %q after rejected borrow, want cleared", got)
	}
}

// TestManagerLogin_BorrowOnlySucceedsOnBorrow confirms BorrowOnly does not
// interfere with a successful borrow: the borrower answers, LookupSelf accepts
// it, and Login returns before ever consulting AuthMethod (set here to
// something that would fail loudly if dispatched).
func TestManagerLogin_BorrowOnlySucceedsOnBorrow(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")

	vaultURL := mockVaultAccepting(t, "peer-token")

	vc, err := vault.NewClient(vault.Config{Address: vaultURL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	m := &Manager{
		VaultClient: vc,
		AuthMethod:  "unsupported-method-should-never-be-reached",
		Borrower:    &fakeBorrower{token: "peer-token", source: "/tmp/peer.sock"},
		BorrowOnly:  true,
		Username:    "testuser",
	}
	if err := m.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got := vc.Token(); got != "peer-token" {
		t.Errorf("client token = %q after borrow, want %q", got, "peer-token")
	}
}

// TestManagerLogin_BorrowOnlyRefusesFreshAuth is the headline borrow-only
// contract: when no token can be borrowed, Login returns ErrBorrowOnly
// instead of dispatching to AuthMethod's fresh-auth flow.
func TestManagerLogin_BorrowOnlyRefusesFreshAuth(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")

	// No borrower wired at all — the borrow can't even be attempted.
	vc, err := vault.NewClient(vault.Config{Address: "https://vault.example.com:8200"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	m := &Manager{
		VaultClient: vc,
		// A real method dispatch would need no config at all to fail loudly
		// with "token" — proving BorrowOnly short-circuits before reaching it
		// means asserting the error is ErrBorrowOnly specifically, not just
		// any error.
		AuthMethod: "token",
		BorrowOnly: true,
		Username:   "testuser",
	}
	err = m.Login(context.Background())
	if !errors.Is(err, ErrBorrowOnly) {
		t.Fatalf("Login() error = %v, want errors.Is(err, ErrBorrowOnly)", err)
	}
}
