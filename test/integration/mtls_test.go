package integration

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/vault"
	"github.com/goodtune/dotvault/internal/vaulttest"
)

// Certificate auth against a real Vault.
//
// Everything else covering the mtls flow is a unit test against an httptest
// fake, which verifies control flow and invariants but never performs an actual
// TLS client-certificate handshake. These tests close that gap: a real CSR is
// signed by a real PKI engine, and the resulting certificate is presented to a
// real cert auth mount to obtain a real token. That exercises the parts a fake
// cannot — CSR encoding, the certificate chain Vault returns, the TLS handshake
// itself, and the shape of the login response.
//
// They cover the platform-neutral core shared by all three variants (mtls,
// mtls+tpm, mtls+os) using the `file` backend, so they run anywhere. The
// hardware backends (TPM sealing, Windows CNG storage) are out of scope — those
// need real hardware and remain verified by cross-compile and review.
//
// Requires the docker-compose stack (`docker compose up -d`), whose vault-init
// provisions the pki engine, the dotvault-client role, the cert auth mount, and
// the CA registration these tests depend on.

const (
	// Cert auth is served on the TLS listener, not the plain 8200 the rest of
	// the dev stack uses: Vault rejects a certificate login over a plain
	// connection outright ("tls connection required"), so this port exists
	// specifically to make the flow testable.
	testVaultTLSAddr = "https://127.0.0.1:8300"

	testPKIMount  = "pki"
	testPKIRole   = "dotvault-client"
	testCertMount = "cert"
	testCertRole  = "dotvault"
)

// rootToken reads the root token the vault-init container wrote to its shared
// volume. It stands in for the bootstrap credential: a human OIDC/LDAP login
// would normally supply a short-lived token carrying pki/sign, and the root
// token is the equivalent that needs no browser.
func rootToken(t *testing.T) string {
	t.Helper()
	return vaulttest.RootToken(t)
}

// vaultCACert extracts the dev TLS certificate from the Vault container and
// writes it where a client can trust it. Self-signed and generated at
// compose-up, so it cannot be committed and must be fetched at runtime.
func vaultCACert(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "exec", "dotvault-vault",
		"cat", "/vault/tls/vault.crt").Output()
	if err != nil {
		t.Skipf("cannot read the dev TLS certificate from the vault container: %v", err)
	}
	path := filepath.Join(t.TempDir(), "vault-ca.crt")
	if err := os.WriteFile(path, out, 0600); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}
	return path
}

// skipIfNoTLS skips when the TLS listener is absent, which means the compose
// stack predates it — a clear reason beats a connection-refused mid-test.
func skipIfNoTLS(t *testing.T) {
	t.Helper()
	cmd := exec.Command("curl", "-sk", testVaultTLSAddr+"/v1/sys/health")
	if err := cmd.Run(); err != nil {
		t.Skip("Vault has no TLS listener on 8300 — recreate the stack with `docker compose down -v && docker compose up -d`")
	}
}

// skipIfNoPKI skips when the compose stack predates the pki/cert provisioning,
// so an older running stack reports a clear reason instead of a confusing
// permission error mid-test.
func skipIfNoPKI(t *testing.T) {
	t.Helper()
	cmd := exec.Command("curl", "-sf", "http://127.0.0.1:8200/v1/pki/ca/pem")
	if err := cmd.Run(); err != nil {
		t.Skip("Vault has no pki engine mounted — recreate the stack with `docker compose down -v && docker compose up -d`")
	}
}

// mtlsParams builds the cert-auth configuration pointed at the dev stack,
// storing the credential envelope under a per-test directory so tests do not
// share state.
func mtlsParams(t *testing.T, user, ca string) *auth.MTLSParams {
	t.Helper()
	return &auth.MTLSParams{
		VaultAddress: testVaultTLSAddr,
		CACert:       ca,
		Method:       "mtls",
		CertMount:    testCertMount,
		CertRole:     testCertRole,
		PKIMount:     testPKIMount,
		PKIRole:      testPKIRole,
		KeyType:      "ec",
		CommonName:   user,
		TTL:          "1h",
		StorageDir:   t.TempDir(),
	}
}

// TestMTLSBootstrapAndCertLogin performs the full exchange end to end against a
// real Vault: bootstrap → generate key → pki/sign → cert-auth login.
//
// The bootstrap runs through Manager.BootstrapLogin — the seam this PR adds so
// the web SPA can drive enrolment — with the root token standing in for a human
// login. That means this test also proves the seam works against a real server,
// not just against a fake.
func TestMTLSBootstrapAndCertLogin(t *testing.T) {
	skipIfNoVault(t)
	skipIfNoTLS(t)
	skipIfNoPKI(t)

	const user = "mtlsuser"
	root := rootToken(t)
	ca := vaultCACert(t)
	ctx := context.Background()

	vc, err := vault.NewClient(vault.Config{Address: testVaultTLSAddr, CACert: ca})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	p := mtlsParams(t, user, ca)
	tokenFile := filepath.Join(t.TempDir(), ".dotvault-token")
	bootstrapCalls := 0

	mgr := &auth.Manager{
		VaultClient:   vc,
		TokenFilePath: tokenFile,
		AuthMethod:    "mtls",
		Username:      user,
		MTLS:          p,
		BootstrapLogin: func(context.Context) (string, error) {
			bootstrapCalls++
			return root, nil
		},
	}

	if err := mgr.Authenticate(ctx); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if bootstrapCalls != 1 {
		t.Errorf("BootstrapLogin called %d times, want exactly 1", bootstrapCalls)
	}

	// The client must now hold a real, working cert-auth token.
	tok := vc.Token()
	if tok == "" {
		t.Fatal("no token on the client after a successful certificate login")
	}
	if tok == root {
		t.Fatal("the client is holding the BOOTSTRAP token, not a cert-auth token — the pki/sign-capable credential must never become operational")
	}

	secret, err := vc.LookupSelf(ctx)
	if err != nil {
		t.Fatalf("the exchanged token does not work: %v", err)
	}

	// It must be a cert-auth token carrying the policy the cert role grants,
	// which is what proves the TLS handshake actually authenticated us rather
	// than some other path having produced a token.
	policies := toStrings(secret.Data["policies"])
	if !contains(policies, "dotvault") {
		t.Errorf("token policies = %v, want the dotvault policy from the cert role", policies)
	}

	// The credential envelope must have been persisted so later runs can log in
	// again without another bootstrap.
	credPath := filepath.Join(p.StorageDir, "credential.json")
	if _, err := os.Stat(credPath); err != nil {
		t.Fatalf("credential envelope was not persisted at %s: %v", credPath, err)
	}
	assertEnvelopeSane(t, credPath, user)

	// And the operational token must be cached for reuse.
	if _, err := os.Stat(tokenFile); err != nil {
		t.Errorf("token file was not written: %v", err)
	}
}

// TestMTLSCertLoginFromStore proves the unattended-recovery path works against a
// real Vault: with a credential already enrolled, a fresh login must succeed
// with NO bootstrap and no human.
//
// This is the path the daemon's token recovery and the public client facade both
// depend on, and the whole justification for calling certificate auth headless.
func TestMTLSCertLoginFromStore(t *testing.T) {
	skipIfNoVault(t)
	skipIfNoTLS(t)
	skipIfNoPKI(t)

	const user = "mtlsrecover"
	root := rootToken(t)
	ca := vaultCACert(t)
	ctx := context.Background()

	p := mtlsParams(t, user, ca)

	// Enrol once.
	seedClient, err := vault.NewClient(vault.Config{Address: testVaultTLSAddr, CACert: ca})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	seed := &auth.Manager{
		VaultClient:    seedClient,
		AuthMethod:     "mtls",
		Username:       user,
		MTLS:           p,
		BootstrapLogin: func(context.Context) (string, error) { return root, nil },
	}
	if err := seed.Authenticate(ctx); err != nil {
		t.Fatalf("initial enrolment: %v", err)
	}
	firstToken := seedClient.Token()

	// Now a completely fresh client and manager, with NO bootstrap hook at all.
	// If CertLoginFromStore reached for a bootstrap this would fail rather than
	// silently prompting, which is exactly the contract we want to pin.
	recoverClient, err := vault.NewClient(vault.Config{Address: testVaultTLSAddr, CACert: ca})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	recover := &auth.Manager{
		VaultClient: recoverClient,
		AuthMethod:  "mtls",
		Username:    user,
		MTLS:        p,
	}

	if err := recover.CertLoginFromStore(ctx); err != nil {
		t.Fatalf("CertLoginFromStore against a real Vault: %v", err)
	}

	newToken := recoverClient.Token()
	if newToken == "" {
		t.Fatal("recovery produced no token")
	}
	if newToken == firstToken {
		t.Error("recovery returned the same token; it should have minted a fresh one from the certificate")
	}
	if _, err := recoverClient.LookupSelf(ctx); err != nil {
		t.Fatalf("the recovered token does not work: %v", err)
	}
}

// TestMTLSDownscopedToConfiguredPolicies proves least-privilege downscoping is
// applied to a real cert-auth token, not just to the fake in unit tests.
//
// vault.policies is the operator's control over what a cached credential can
// do, so it failing open would be a silent privilege escalation.
func TestMTLSDownscopedToConfiguredPolicies(t *testing.T) {
	skipIfNoVault(t)
	skipIfNoTLS(t)
	skipIfNoPKI(t)

	const user = "mtlsdownscope"
	root := rootToken(t)
	ca := vaultCACert(t)
	ctx := context.Background()

	vc, err := vault.NewClient(vault.Config{Address: testVaultTLSAddr, CACert: ca})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	mgr := &auth.Manager{
		VaultClient: vc,
		AuthMethod:  "mtls",
		Username:    user,
		MTLS:        mtlsParams(t, user, ca),
		// The cert role grants "dotvault"; ask for a child restricted to it
		// with the implicit default policy stripped.
		Policy: auth.PolicyConstraint{
			Policies:        []string{"dotvault"},
			NoDefaultPolicy: true,
		},
		BootstrapLogin: func(context.Context) (string, error) { return root, nil },
	}

	if err := mgr.Authenticate(ctx); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	secret, err := vc.LookupSelf(ctx)
	if err != nil {
		t.Fatalf("LookupSelf: %v", err)
	}
	policies := toStrings(secret.Data["policies"])
	if !contains(policies, "dotvault") {
		t.Errorf("policies = %v, want dotvault", policies)
	}
	if contains(policies, "default") {
		t.Errorf("policies = %v, want the default policy stripped by no_default_policy", policies)
	}
}

// assertEnvelopeSane checks the persisted credential records what a later login
// needs: the right identity, a future expiry, and the certificate itself.
func assertEnvelopeSane(t *testing.T, path, wantUser string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	var env struct {
		Method   string    `json:"method"`
		Backend  string    `json:"backend"`
		Identity string    `json:"identity"`
		NotAfter time.Time `json:"not_after"`
		CertPEM  string    `json:"cert_pem"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("envelope is not valid JSON: %v", err)
	}
	if env.Identity != wantUser {
		t.Errorf("envelope identity = %q, want %q", env.Identity, wantUser)
	}
	if env.Backend != "file" {
		t.Errorf("envelope backend = %q, want file", env.Backend)
	}
	if !strings.Contains(env.CertPEM, "BEGIN CERTIFICATE") {
		t.Error("envelope carries no PEM certificate")
	}
	if env.NotAfter.Before(time.Now()) {
		t.Errorf("envelope NotAfter %s is already in the past", env.NotAfter)
	}
	// Vault PKI returns the leaf followed by its issuing CA; the OS-native
	// backend depends on that chain being present (parseLeafAndIssuer), so
	// assert the real server actually supplies it.
	if strings.Count(env.CertPEM, "BEGIN CERTIFICATE") < 2 {
		t.Error("envelope carries only one certificate; the issuing CA chain is missing, which mtls+os requires")
	}
}

func toStrings(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
