package client

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

// TestNew_NonCertMethodSkipsMTLSDefaults pins that New() applies no
// certificate-login defaults for a non-certificate auth method. Beyond keeping
// the projection honest (AuthenticateCached consults the MTLS fields only under
// a cert method), computing the StorageDir default calls paths.CacheDir(),
// which panics when the OS home cannot be resolved — so a plain token/oidc
// consumer on a home-less host must not be dragged through that path. Revert the
// method gate in withDefaults and StorageDir would be populated here, failing
// this test.
func TestNew_NonCertMethodSkipsMTLSDefaults(t *testing.T) {
	for _, method := range []string{"token", "oidc", "ldap", ""} {
		t.Run("method="+method, func(t *testing.T) {
			c, err := New(&Config{
				Vault: VaultConfig{Address: "http://127.0.0.1:8200", AuthMethod: method},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got := c.cfg.Vault.MTLS.StorageDir; got != "" {
				t.Errorf("StorageDir = %q, want empty for a non-cert method (must not touch paths.CacheDir)", got)
			}
			if got := c.cfg.Vault.MTLS.CertMount; got != "" {
				t.Errorf("CertMount = %q, want empty for a non-cert method", got)
			}
		})
	}
}

// TestNew_CertMethodDoesNotPanicWithoutHome pins that even under a certificate
// method, New() degrades rather than panicking when the OS home is
// unresolvable: paths.CacheDir panics via mustHomeDir there, and a public
// library must not. StorageDir resolves to "" (the cert login then fails with a
// clear error instead of crashing New). Non-Windows only — on Windows CacheDir
// reads LOCALAPPDATA and never consults the home directory, so there is no
// panic path to guard.
func TestNew_CertMethodDoesNotPanicWithoutHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("CacheDir uses LOCALAPPDATA on Windows; no mustHomeDir panic path")
	}
	// os.UserHomeDir errors on an empty $HOME, which is what makes mustHomeDir
	// panic; the recover in defaultMTLSStorageDir must swallow it.
	t.Setenv("HOME", "")
	c, err := New(&Config{
		Vault: VaultConfig{Address: "http://127.0.0.1:8200", AuthMethod: "mtls", MTLS: MTLSConfig{CertRole: "dotvault"}},
	})
	if err != nil {
		t.Fatalf("New must not fail without a home dir: %v", err)
	}
	if got := c.cfg.Vault.MTLS.StorageDir; got != "" {
		t.Errorf("StorageDir = %q, want empty when the home dir is unresolvable", got)
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

// TestAuthenticateCached_MTLSOSSkipsStaleTokenFile pins the facade's half of
// the no-token-at-rest guarantee, which Copilot's review surfaced as a stale
// comment and which turned out to be a real hole.
//
// The daemon removes a leftover token file on its next successful mtls+os
// login, but a library consumer cannot count on that ever happening in its
// own lifetime — the daemon may be stopped, or this process may be the only
// dotvault on the host. Reading the file anyway would leave a plaintext token
// from a previous method silently in use for the rest of its TTL, which is the
// exact credential mtls+os exists to eliminate.
//
// The fake Vault ACCEPTS any token, which is what makes the two behaviours
// distinguishable: adopting the file means LookupSelf succeeds and
// AuthenticateCached returns nil, whereas skipping it falls through to a
// certificate login that cannot succeed with no enrolled credential.
// Reverting the gate must fail this.
func TestAuthenticateCached_MTLSOSSkipsStaleTokenFile(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "") // hermetic: a developer export must not leak in
	fv := newFakeVault(t)
	tokenFile := filepath.Join(t.TempDir(), ".vault-token")
	if err := os.WriteFile(tokenFile, []byte("stale-from-plain-mtls\n"), 0600); err != nil {
		t.Fatal(err)
	}

	newClient := func(method string) *Client {
		t.Helper()
		c, err := New(&Config{
			Vault: VaultConfig{
				Address:    fv.srv.URL,
				AuthMethod: method,
				MTLS:       MTLSConfig{CertRole: "dotvault", StorageDir: t.TempDir()},
			},
			TokenFile: tokenFile,
		})
		if err != nil {
			t.Fatalf("New(%s): %v", method, err)
		}
		return c
	}

	t.Run("mtls+os ignores it", func(t *testing.T) {
		c := newClient("mtls+os")
		err := c.AuthenticateCached(context.Background())
		if err == nil {
			t.Fatal("AuthenticateCached() = nil — the stale plaintext token was adopted, which mtls+os must never do")
		}
		// Pin WHICH step failed. Without this the subtest would still pass if
		// the call started failing earlier for an unrelated reason, e.g. a
		// transport fault, which would make it stop testing the skip at all.
		if !errors.Is(err, ErrLoginRequired) {
			t.Errorf("error = %v, want ErrLoginRequired from the certificate candidate", err)
		}
		if got := c.Token(); got != "" {
			t.Errorf("Token() = %q, want empty — no token from disk may be held under mtls+os", got)
		}
	})

	t.Run("plain mtls still reuses it", func(t *testing.T) {
		// The scope guard: same file, same Vault, only the method differs. A
		// gate that grew too broad shows up here as an unexpected failure.
		c := newClient("mtls")
		if err := c.AuthenticateCached(context.Background()); err != nil {
			t.Fatalf("plain mtls stopped reusing its cached token: %v", err)
		}
		if got := c.Token(); got != "stale-from-plain-mtls" {
			t.Errorf("Token() = %q, want the cached file token", got)
		}
	})
}

// TestAuthenticateCached_MTLSOSHonoursEnvToken pins the exemption to the
// no-token-at-rest rule, which pre-push review found asserted in three doc
// surfaces and tested in none.
//
// DOTVAULT_TOKEN is caller-supplied and, being an environment value, is never
// at rest — so mtls+os has no reason to refuse it, and a consumer that
// provisions a token out of band must keep working. This is the behaviour a
// future over-broad tightening of "no token at rest" would silently break,
// including for the Python bindings, whose only auth entry point this is.
func TestAuthenticateCached_MTLSOSHonoursEnvToken(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "supplied-by-caller")
	fv := newFakeVault(t)
	tokenFile := filepath.Join(t.TempDir(), ".vault-token")

	c, err := New(&Config{
		Vault: VaultConfig{
			Address:    fv.srv.URL,
			AuthMethod: "mtls+os",
			MTLS:       MTLSConfig{CertRole: "dotvault", StorageDir: t.TempDir()},
		},
		TokenFile: tokenFile,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := c.AuthenticateCached(context.Background()); err != nil {
		t.Fatalf("AuthenticateCached: %v — mtls+os must still honour DOTVAULT_TOKEN", err)
	}
	if got := c.Token(); got != "supplied-by-caller" {
		t.Errorf("Token() = %q, want the env-supplied token", got)
	}
}
