package client

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/config"
)

// The client facade is CONSUMPTION-ONLY for certificate auth: it can present a
// certificate this host already holds, but it can never mint, rotate, or
// bootstrap one. These tests pin both halves of that contract.

// TestLogin_RefusedUnderCertificateAuth: a fresh Login under a cert method
// would, on a host with no usable credential, run the bootstrap — an OIDC
// browser flow or an LDAP terminal prompt, then mint a certificate and write it
// to this host. A library embedded in someone else's process must not do any of
// that, so Login refuses outright rather than surprising the caller.
func TestLogin_RefusedUnderCertificateAuth(t *testing.T) {
	for _, method := range []string{"mtls", "mtls+tpm", "mtls+os"} {
		t.Run(method, func(t *testing.T) {
			c, err := New(&Config{
				Vault:     VaultConfig{Address: "http://127.0.0.1:1", AuthMethod: method},
				TokenFile: filepath.Join(t.TempDir(), ".vault-token"),
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			err = c.Login(context.Background())
			if err == nil {
				t.Fatal("Login() = nil, want a refusal — the facade must never bootstrap a certificate")
			}
			if !errors.Is(err, ErrLoginRequired) {
				t.Errorf("Login() error = %v, want ErrLoginRequired", err)
			}
			if !strings.Contains(err.Error(), "consumption-only") {
				t.Errorf("Login() error = %q, want it to explain the consumption-only contract", err)
			}
			// The message must point the caller somewhere useful.
			if !strings.Contains(err.Error(), "AuthenticateCached") {
				t.Errorf("Login() error = %q, want it to name the non-interactive alternative", err)
			}
		})
	}
}

// TestLogin_AllowedForNonCertificateMethods is the counterpart: the refusal
// must not leak into the ordinary login methods.
func TestLogin_AllowedForNonCertificateMethods(t *testing.T) {
	for _, method := range []string{"token", "oidc", "ldap"} {
		t.Run(method, func(t *testing.T) {
			if config.IsMTLSMethod(method) {
				t.Fatalf("test premise wrong: %q is a cert method", method)
			}
			c, err := New(&Config{
				// Unreachable on purpose: we only care that the cert refusal
				// did NOT fire, i.e. the error is not ErrLoginRequired with
				// the consumption-only message.
				Vault:     VaultConfig{Address: "http://127.0.0.1:1", AuthMethod: method},
				TokenFile: filepath.Join(t.TempDir(), ".vault-token"),
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			err = c.Login(context.Background())
			if err != nil && strings.Contains(err.Error(), "consumption-only") {
				t.Errorf("Login() was refused as a cert method: %v", err)
			}
		})
	}
}

// TestNew_MTLSDefaultsMatchDaemon: the facade must look for the credential
// envelope exactly where the daemon wrote it. A drifting default would make
// certificate login silently unavailable rather than fail loudly.
func TestNew_MTLSDefaultsMatchDaemon(t *testing.T) {
	c, err := New(&Config{
		Vault: VaultConfig{Address: "http://127.0.0.1:8200", AuthMethod: "mtls"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := c.cfg.Vault.MTLS.CertMount; got != config.DefaultCertMount {
		t.Errorf("CertMount = %q, want %q (the daemon's default)", got, config.DefaultCertMount)
	}
	if c.cfg.Vault.MTLS.StorageDir == "" {
		t.Error("StorageDir is empty; it must default to the daemon's {cache_dir}/mtls")
	}
	if !strings.HasSuffix(filepath.ToSlash(c.cfg.Vault.MTLS.StorageDir), "/mtls") {
		t.Errorf("StorageDir = %q, want it to end in /mtls", c.cfg.Vault.MTLS.StorageDir)
	}
}

// TestAuthenticateCached_CertLoginDoesNotWriteTokenFile: the token file belongs
// to the daemon. A library inside somebody else's process must not race it, so
// a certificate login mints in memory only — the same ownership rule the
// peer-socket borrow follows.
//
// The cert login itself cannot succeed here (no enrolled credential), which is
// the point: even on the failure path nothing may be written.
func TestAuthenticateCached_CertLoginDoesNotWriteTokenFile(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), ".vault-token")
	c, err := New(&Config{
		Vault: VaultConfig{
			Address:    "http://127.0.0.1:1",
			AuthMethod: "mtls",
			MTLS:       MTLSConfig{CertRole: "dotvault", StorageDir: t.TempDir()},
		},
		TokenFile: tokenFile,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = c.AuthenticateCached(context.Background())
	if err == nil {
		t.Fatal("AuthenticateCached() = nil, want failure with no enrolled certificate")
	}
	if !errors.Is(err, ErrLoginRequired) {
		t.Errorf("error = %v, want ErrLoginRequired", err)
	}
	if _, statErr := readFileExists(tokenFile); statErr {
		t.Error("certificate login wrote the token file; it must stay in memory and leave the daemon's file alone")
	}
	if got := c.Token(); got != "" {
		t.Errorf("Token() = %q, want empty after a failed certificate login", got)
	}
}

// readFileExists reports whether path exists.
func readFileExists(path string) (struct{}, bool) {
	_, err := os.Stat(path)
	return struct{}{}, err == nil
}

// TestAuthenticateCached_CertErrorTaxonomy pins PR-review finding P2.
//
// A certificate login fails two very different ways and they call for opposite
// responses: an unreachable / rate-limited / 5xx-ing Vault is a retry
// condition, whereas a missing or unusable credential means the host must be
// enrolled. Reporting both as ErrLoginRequired told consumers to enrol when
// they should back off, contradicting AuthenticateCached's ErrUnreachable
// contract.
//
// The split cannot be inferred from the error's shape — neither a transport
// failure nor "no credential on this host" carries an HTTP response — so
// internal/auth marks the local causes with ErrNoCertCredential. These cases
// exercise both sides of that boundary through the real code path.
func TestAuthenticateCached_CertErrorTaxonomy(t *testing.T) {
	t.Run("noCredentialIsLoginRequired", func(t *testing.T) {
		// Empty storage dir: loadCredential finds nothing, so the failure is
		// local and must never be reported as a transport problem.
		c, err := New(&Config{
			Vault: VaultConfig{
				Address:    "http://127.0.0.1:1",
				AuthMethod: "mtls",
				MTLS:       MTLSConfig{CertRole: "dotvault", StorageDir: t.TempDir()},
			},
			TokenFile: filepath.Join(t.TempDir(), ".vault-token"),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		err = c.AuthenticateCached(context.Background())
		if !errors.Is(err, ErrLoginRequired) {
			t.Errorf("error = %v, want ErrLoginRequired for a host with no certificate", err)
		}
		if errors.Is(err, ErrUnreachable) {
			t.Error("a missing local credential was reported as ErrUnreachable; consumers would retry forever instead of enrolling")
		}
	})

	t.Run("localCauseIsNotMistakenForTransport", func(t *testing.T) {
		// The sentinel is what makes the classification reliable: without it,
		// classify() maps any error lacking an HTTP response to ErrUnreachable,
		// which is precisely what a local credential failure looks like.
		if !errors.Is(fmt.Errorf("%w: a bootstrap is required", auth.ErrNoCertCredential), auth.ErrNoCertCredential) {
			t.Fatal("ErrNoCertCredential does not survive wrapping")
		}
	})
}
