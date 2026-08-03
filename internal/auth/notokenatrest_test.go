package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
)

// TestPersistTokenAtRest pins which methods may cache a token on disk.
//
// Only "+os" opts out. "+tpm" keeps a file and seals it — a different mechanism
// for a comparable property — and plain "mtls" keeps a plaintext file
// consistent with its own weaker guarantee about the key. Both are deliberately
// unchanged; this test is as much a guard against altering them as it is a
// check on "+os".
func TestPersistTokenAtRest(t *testing.T) {
	tests := []struct {
		method string
		want   bool
	}{
		{method: "mtls+os", want: false},
		// The suffix parses on any base (BaseMethod strips it), but no-persist
		// is implemented only off mtls: oidc+os routes to authenticateOIDC,
		// which writes the token file unconditionally. Claiming no-persist for
		// it would state a guarantee nothing enforces.
		{method: "oidc+os", want: true},
		{method: "ldap+os", want: true},
		{method: "mtls", want: true},
		{method: "mtls+tpm", want: true},
		{method: "oidc", want: true},
		{method: "ldap", want: true},
		{method: "token", want: true},
		{method: "oidc+tpm", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			if got := PersistTokenAtRest(tt.method); got != tt.want {
				t.Errorf("PersistTokenAtRest(%q) = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}

// TestPersistAndSealAreIndependent guards the distinction the two predicates
// draw. Conflating them would be an easy refactor to make and would silently
// either start writing files for "+os" or stop sealing them for "+tpm".
func TestPersistAndSealAreIndependent(t *testing.T) {
	if SealTokenAtRest("mtls+os") {
		t.Error("mtls+os must not claim to seal a token — it writes none to seal")
	}
	if !PersistTokenAtRest("mtls+tpm") {
		t.Error("mtls+tpm must still persist a token; it protects it by sealing, not by omission")
	}
	if !SealTokenAtRest("mtls+tpm") {
		t.Error("mtls+tpm must still seal")
	}
}

// TestRemoveTokenFile covers the half of the guarantee that is easy to forget:
// declining to write a new token does nothing about one already on disk.
func TestRemoveTokenFile(t *testing.T) {
	t.Run("removesExisting", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".dotvault-token")
		if err := os.WriteFile(path, []byte("s.stale-plaintext-token"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := RemoveTokenFile(path); err != nil {
			t.Fatalf("RemoveTokenFile: %v", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("token file still present (stat err %v) — a stale plaintext credential would survive the upgrade", err)
		}
	})

	t.Run("absentIsSuccess", func(t *testing.T) {
		// The common case on a host that never had one; must not be an error,
		// or every mtls+os login on a clean host would fail.
		if err := RemoveTokenFile(filepath.Join(t.TempDir(), "never-existed")); err != nil {
			t.Errorf("RemoveTokenFile on an absent file = %v, want nil", err)
		}
	})

	t.Run("emptyPathIsNoop", func(t *testing.T) {
		if err := RemoveTokenFile(""); err != nil {
			t.Errorf("RemoveTokenFile(\"\") = %v, want nil", err)
		}
	})
}

// TestMTLSOSLeavesNoTokenAtRest is the end-to-end assertion behind this method's
// central claim, expressed the way a reviewer would check it: run a real
// mtls+os login against the fake Vault, then look at the filesystem.
//
// The securestore "os" backend is Windows-only, so the login here uses the file
// backend under an "mtls+os" auth_method. That is the right scope for this test
// regardless: the property under test belongs to the TOKEN path, which is
// entirely platform-neutral, and coupling it to CNG would make it unrunnable on
// the machines where it is most likely to regress.
func TestMTLSOSLeavesNoTokenAtRest(t *testing.T) {
	t.Run("noTokenWritten", func(t *testing.T) {
		ca := newTestCA(t)
		srv := newFakeVaultServer(t, &fakeVault{ca: ca})
		dir := t.TempDir()

		m := mtlsManager(t, srv, dir)
		m.AuthMethod = "mtls+os" // token policy only; the store stays "file" here
		m.BootstrapLogin = func(context.Context) (string, error) { return "s.boot-token", nil }

		if err := m.authenticateMTLS(t.Context()); err != nil {
			t.Fatalf("authenticateMTLS: %v", err)
		}
		if got := m.VaultClient.Token(); got == "" {
			t.Fatal("login produced no in-memory token")
		}

		// The property: nothing usable on disk.
		if _, err := os.Stat(m.TokenFilePath); !os.IsNotExist(err) {
			t.Errorf("token file exists at %s (stat err %v) — mtls+os must leave no token at rest", m.TokenFilePath, err)
		}
	})

	t.Run("staleTokenRemoved", func(t *testing.T) {
		// The upgrade path, and the one that actually decides whether the
		// guarantee is worth stating: a host that previously ran plain mtls
		// already has a readable plaintext token, still valid until its TTL
		// expires. Declining to write a new one would leave it sitting there.
		ca := newTestCA(t)
		srv := newFakeVaultServer(t, &fakeVault{ca: ca})
		dir := t.TempDir()

		m := mtlsManager(t, srv, dir)
		m.AuthMethod = "mtls+os"
		m.BootstrapLogin = func(context.Context) (string, error) { return "s.boot-token", nil }

		if err := os.WriteFile(m.TokenFilePath, []byte("s.left-over-from-plain-mtls"), 0600); err != nil {
			t.Fatal(err)
		}

		if err := m.authenticateMTLS(t.Context()); err != nil {
			t.Fatalf("authenticateMTLS: %v", err)
		}
		if _, err := os.Stat(m.TokenFilePath); !os.IsNotExist(err) {
			t.Errorf("stale plaintext token survived an mtls+os login at %s (stat err %v)", m.TokenFilePath, err)
		}
	})

	t.Run("plainMTLSStillPersists", func(t *testing.T) {
		// The scope guard. This change must not alter plain mtls or mtls+tpm,
		// and the cheapest way for it to do so accidentally is a predicate that
		// is too broad.
		ca := newTestCA(t)
		srv := newFakeVaultServer(t, &fakeVault{ca: ca})
		dir := t.TempDir()

		m := mtlsManager(t, srv, dir) // AuthMethod stays "mtls"
		m.BootstrapLogin = func(context.Context) (string, error) { return "s.boot-token", nil }

		if err := m.authenticateMTLS(t.Context()); err != nil {
			t.Fatalf("authenticateMTLS: %v", err)
		}
		got, err := ReadTokenFile(m.TokenFilePath)
		if err != nil {
			t.Fatalf("ReadTokenFile: %v", err)
		}
		if got == "" {
			t.Error("plain mtls stopped persisting its token — this change is scoped to mtls+os only")
		}
	})
}

// TestInspectCertCredential covers the read-only credential view that `status`
// and `login-check` both reason from.
//
// The expired case is the one that matters. Re-issuance requires a still-valid
// certificate, so a lapsed one cannot mint a token and cannot renew itself — the
// host needs a fresh bootstrap. A caller that treated "present" as "fine" would
// report health on a host that can no longer authenticate at all, which under
// mtls+os (no token at rest to fall back on) means it simply stops working.
func TestInspectCertCredential(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		info, err := InspectCertCredential(t.TempDir())
		if err != nil {
			t.Fatalf("InspectCertCredential: %v", err)
		}
		if info.Present {
			t.Error("Present = true for an empty storage dir")
		}
	})

	t.Run("validNotExpired", func(t *testing.T) {
		dir := t.TempDir()
		writeCredFixture(t, dir, time.Now().Add(24*time.Hour))
		info, err := InspectCertCredential(dir)
		if err != nil {
			t.Fatalf("InspectCertCredential: %v", err)
		}
		if !info.Present {
			t.Fatal("Present = false for an enrolled credential")
		}
		if info.Expired {
			t.Error("Expired = true for a certificate valid for another day")
		}
		if info.Identity != "alice" {
			t.Errorf("Identity = %q, want alice", info.Identity)
		}
	})

	t.Run("expired", func(t *testing.T) {
		dir := t.TempDir()
		writeCredFixture(t, dir, time.Now().Add(-time.Hour))
		info, err := InspectCertCredential(dir)
		if err != nil {
			t.Fatalf("InspectCertCredential: %v", err)
		}
		if !info.Present {
			t.Fatal("Present = false for an enrolled-but-expired credential")
		}
		if !info.Expired {
			t.Error("Expired = false for a certificate whose NotAfter has passed — callers would report this host as healthy when it can no longer authenticate")
		}
	})
}

func writeCredFixture(t *testing.T, dir string, notAfter time.Time) {
	t.Helper()
	cred := &sealedCredential{
		Method:   "mtls+os",
		Backend:  "os",
		Identity: "alice",
		NotAfter: notAfter,
		CertPEM:  "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
	}
	if err := saveCredential(dir, cred); err != nil {
		t.Fatalf("saveCredential: %v", err)
	}
}

// TestStaleTokenSurvivesFailedLogin guards against enforcing the guarantee
// destructively.
//
// mtls+os is Windows-only, so on Linux or macOS the login fails at store-open.
// An earlier version of this change deleted the token file at daemon startup,
// before any login was attempted — which meant a host that had merely
// misconfigured the method (Windows-only, on Linux) lost a perfectly good token
// and then could not obtain another, because the method it had asked for could
// never work there. Removal must therefore be tied to a SUCCESSFUL login, which
// is exactly the moment the guarantee is claimed for.
func TestStaleTokenSurvivesFailedLogin(t *testing.T) {
	ca := newTestCA(t)
	srv := newFakeVaultServer(t, &fakeVault{ca: ca})
	dir := t.TempDir()

	m := mtlsManager(t, srv, dir)
	m.AuthMethod = "mtls+os"
	// No BootstrapLogin and no credential on disk, so seeding cannot complete:
	// this stands in for any login that fails before certLogin is reached.
	m.MTLS.BootstrapMethod = "oidc"

	if err := os.WriteFile(m.TokenFilePath, []byte("s.still-useful-token"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := m.authenticateMTLS(t.Context()); err == nil {
		t.Fatal("authenticateMTLS() = nil, want failure with no way to seed a credential")
	}

	if _, err := os.Stat(m.TokenFilePath); err != nil {
		t.Errorf("token file was removed despite the login failing (%v) — a misconfigured host would lose a working credential it cannot replace", err)
	}
}

// TestMTLSTPMStillSealsToken is the other half of the scope guard.
//
// This change must not alter mtls+tpm, which reaches a comparable
// no-plaintext-at-rest position by a different route: it keeps a file and seals
// it under the TPM. Only plain mtls was guarded before, which would have caught
// a predicate that was too broad by one method but not by two. Asserting the
// seal — rather than merely that a file exists — is what distinguishes "still
// persisting correctly" from "persisting in plaintext".
func TestMTLSTPMStillSealsToken(t *testing.T) {
	if !PersistTokenAtRest("mtls+tpm") {
		t.Fatal("mtls+tpm must still persist a token file")
	}
	if !SealTokenAtRest("mtls+tpm") {
		t.Fatal("mtls+tpm must still seal that file; a plaintext one would be a silent downgrade")
	}
	// And the two must not have been collapsed into one predicate: +os is
	// no-persist, +tpm is persist-and-seal. Conflating them would make one of
	// the two methods silently wrong.
	if PersistTokenAtRest("mtls+os") == PersistTokenAtRest("mtls+tpm") {
		t.Error("mtls+os and mtls+tpm must differ on persistence")
	}
	if SealTokenAtRest("mtls+os") == SealTokenAtRest("mtls+tpm") {
		t.Error("mtls+os and mtls+tpm must differ on sealing")
	}
}

// TestAuthenticateIgnoresStaleTokenUnderNoPersist pins the hole that made the
// guarantee false until pre-push review found it.
//
// Manager.Authenticate read the token file unconditionally, so a host running
// `dotvault sync` under mtls+os would ADOPT a stale plaintext token left by a
// previous method and return before Login — meaning certLogin never ran and
// never removed it. The file then lived on indefinitely AND was actively in
// use, which is worse than merely failing to delete it: the credential the
// method exists to eliminate becomes the one it authenticates with.
//
// The Vault here ACCEPTS any token, which is what makes the two behaviours
// cleanly distinguishable: adopting the stale file means LookupSelf succeeds
// and Authenticate returns nil, whereas ignoring it means falling through to a
// Login that cannot succeed without MTLS params. Reverting the gate must fail
// this.
func TestAuthenticateIgnoresStaleTokenUnderNoPersist(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "") // hermetic: a developer export must not leak in

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"s.stale-from-plain-mtls","ttl":3600}}`))
	}))
	t.Cleanup(srv.Close)

	vc, err := vault.NewClient(vault.Config{Address: srv.URL})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".dotvault-token")
	if err := os.WriteFile(tokenPath, []byte("s.stale-from-plain-mtls"), 0600); err != nil {
		t.Fatal(err)
	}

	m := &Manager{
		VaultClient:   vc,
		TokenFilePath: tokenPath,
		AuthMethod:    "mtls+os",
	}

	if err := m.Authenticate(t.Context()); err == nil {
		t.Fatal("Authenticate() = nil — the stale plaintext token was adopted and used, which is exactly what mtls+os must not do")
	}
	if got := vc.Token(); got == "s.stale-from-plain-mtls" {
		t.Errorf("client is holding the stale token %q", got)
	}

	// Counterpart: plain mtls must still reuse the file. Same server, same
	// file — only the method differs, so a gate that grew too broad shows up
	// here as an unexpected failure.
	m2 := &Manager{VaultClient: vc, TokenFilePath: tokenPath, AuthMethod: "mtls"}
	if err := m2.Authenticate(t.Context()); err != nil {
		t.Errorf("plain mtls stopped reusing its cached token: %v", err)
	}
}
