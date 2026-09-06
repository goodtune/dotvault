package auth

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/vault"
)

// TestRunBootstrapLoginSeam covers the BootstrapLogin hook: when set it
// replaces the CLI oidc/ldap dispatch, its token lands on the sibling client
// only, and its failures are surfaced rather than swallowed. When nil the
// existing method switch still runs.
func TestRunBootstrapLoginSeam(t *testing.T) {
	const sharedToken = "s.shared-operational"

	tests := []struct {
		name string
		// bootstrapLogin is attached to the Manager; nil exercises the CLI path.
		bootstrapLogin func(calls *int) func(context.Context) (string, error)
		bootstrapMeth  string
		wantErr        string // substring; empty means success expected
		wantBootToken  string
		wantCalls      int
	}{
		{
			name: "hook supplies the bootstrap token",
			bootstrapLogin: func(calls *int) func(context.Context) (string, error) {
				return func(context.Context) (string, error) {
					*calls++
					return "s.boot-token", nil
				}
			},
			// A method the CLI switch would reject, proving the hook short-circuits
			// the switch entirely rather than running alongside it.
			bootstrapMeth: "not-a-method",
			wantBootToken: "s.boot-token",
			wantCalls:     1,
		},
		{
			name:          "nil hook falls through to the CLI method switch",
			bootstrapMeth: "not-a-method",
			wantErr:       `unsupported mtls bootstrap_method "not-a-method"`,
		},
		{
			name: "hook error propagates",
			bootstrapLogin: func(calls *int) func(context.Context) (string, error) {
				return func(context.Context) (string, error) {
					*calls++
					return "", errors.New("browser login declined")
				}
			},
			bootstrapMeth: "oidc",
			wantErr:       "browser login declined",
			wantCalls:     1,
		},
		{
			name: "empty token is rejected",
			bootstrapLogin: func(calls *int) func(context.Context) (string, error) {
				return func(context.Context) (string, error) {
					*calls++
					return "", nil
				}
			},
			bootstrapMeth: "oidc",
			wantErr:       "empty token",
			wantCalls:     1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vc, err := vault.NewClient(vault.Config{Address: "https://vault.invalid"})
			if err != nil {
				t.Fatal(err)
			}
			vc.SetToken(sharedToken)

			calls := 0
			m := &Manager{
				VaultClient: vc,
				AuthMethod:  "mtls",
				Username:    "alice",
				MTLS:        &MTLSParams{Method: "mtls", BootstrapMethod: tt.bootstrapMeth},
			}
			if tt.bootstrapLogin != nil {
				m.BootstrapLogin = tt.bootstrapLogin(&calls)
			}

			bootClient, err := m.runBootstrap(t.Context())
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("runBootstrap: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("runBootstrap succeeded, want error containing %q", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
			}
			if calls != tt.wantCalls {
				t.Errorf("BootstrapLogin called %d times, want %d", calls, tt.wantCalls)
			}
			if tt.wantBootToken != "" {
				if bootClient == nil {
					t.Fatal("no bootstrap client returned")
				}
				if got := bootClient.Token(); got != tt.wantBootToken {
					t.Errorf("sibling token = %q, want %q", got, tt.wantBootToken)
				}
			}
			// The shared client must never see the bootstrap token, on any path.
			if got := vc.Token(); got != sharedToken {
				t.Errorf("shared client token = %q, want it unchanged (%q)", got, sharedToken)
			}
		})
	}
}

// TestMTLSBootstrapLoginEndToEnd runs the full seed path with a BootstrapLogin
// hook in place: the hook's token signs the CSR on the sibling client, the
// shared client ends up holding only the operational cert-auth token, and the
// bootstrap token never reaches the token file.
func TestMTLSBootstrapLoginEndToEnd(t *testing.T) {
	ca := newTestCA(t)
	f := &fakeVault{ca: ca}
	srv := newFakeVaultServer(t, f)
	dir := t.TempDir()

	m := mtlsManager(t, srv, dir)
	m.MTLS.BootstrapMethod = "oidc"
	calls := 0
	m.BootstrapLogin = func(context.Context) (string, error) {
		calls++
		return "s.boot-token", nil
	}

	if err := m.authenticateMTLS(t.Context()); err != nil {
		t.Fatalf("authenticateMTLS: %v", err)
	}
	if calls != 1 {
		t.Errorf("BootstrapLogin called %d times, want 1", calls)
	}
	if f.signCount != 1 {
		t.Errorf("PKI sign count = %d, want 1", f.signCount)
	}
	if len(f.signTokens) != 1 || f.signTokens[0] != "s.boot-token" {
		t.Errorf("PKI sign tokens = %v, want [s.boot-token]", f.signTokens)
	}
	if got := m.VaultClient.Token(); got != "s.operational-token" {
		t.Errorf("shared client token = %q, want the operational cert-auth token", got)
	}
	// The bootstrap token must not be persisted; only the operational one is.
	got, err := ReadTokenFile(filepath.Join(dir, "token"))
	if err != nil {
		t.Fatalf("ReadTokenFile: %v", err)
	}
	if got != "s.operational-token" {
		t.Errorf("token file = %q, want the operational cert-auth token", got)
	}
}
