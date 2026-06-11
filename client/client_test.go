package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeVault stands up an httptest server that answers the handful of Vault
// endpoints this package exercises: token lookup-self and KV v2 reads. It
// lets the tests run without a live Vault and without the network.
type fakeVault struct {
	srv *httptest.Server
	// secrets maps "<mount>/<path>" to its data map.
	secrets map[string]map[string]any
	// tokenValid controls whether lookup-self succeeds.
	tokenValid bool
	// unreachable, when set, makes every endpoint return 502 (simulating a
	// dead upstream that still answers at the socket).
	unreachable bool
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	// The unreachable-path tests make the server answer 5xx, which the
	// Vault SDK retries with backoff by default (~3s per call). Disable
	// retries so the suite stays fast and deterministic on loaded CI
	// runners. NewClient reads this env at construction time.
	t.Setenv("VAULT_MAX_RETRIES", "0")
	fv := &fakeVault{secrets: map[string]map[string]any{}, tokenValid: true}
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		if fv.unreachable {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if !fv.tokenValid || r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"id": "tok", "ttl": 3600, "creation_ttl": 7200},
		})
	})

	// sys/health needs no auth; only a transport failure (modelled by
	// unreachable) makes ServerHealth error.
	mux.HandleFunc("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		if fv.unreachable {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"initialized": true, "sealed": false, "standby": false, "version": "1.0.0",
		})
	})

	// KV v2 reads land on /v1/<mount>/data/<path>.
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		if fv.unreachable {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		// Real Vault gates KV reads on the token, same as lookup-self, so the
		// fake does too — otherwise read-path tests couldn't exercise ErrDenied.
		if !fv.tokenValid || r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
			return
		}
		// Strip "/v1/" prefix, then split "<mount>/data/<path>".
		rest := r.URL.Path[len("/v1/"):]
		const marker = "/data/"
		i := strings.Index(rest, marker)
		if i < 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		mount := rest[:i]
		path := rest[i+len(marker):]
		data, ok := fv.secrets[mount+"/"+path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data":     data,
				"metadata": map[string]any{"version": 1},
			},
		})
	})

	fv.srv = httptest.NewServer(mux)
	t.Cleanup(fv.srv.Close)
	return fv
}

func newTestClient(t *testing.T, fv *fakeVault) *Client {
	t.Helper()
	c, err := New(&Config{
		Vault: VaultConfig{Address: fv.srv.URL, AuthMethod: "token"},
		// Point the token file somewhere empty by default; tests that want a
		// cached token set DOTVAULT_TOKEN or override.
		TokenFile: filepath.Join(t.TempDir(), ".vault-token"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNew_Defaults(t *testing.T) {
	c, err := New(&Config{Vault: VaultConfig{Address: "http://127.0.0.1:8200"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.cfg.Vault.KVMount != "kv" {
		t.Errorf("KVMount = %q, want kv", c.cfg.Vault.KVMount)
	}
	if c.cfg.Vault.UserPrefix != "users/" {
		t.Errorf("UserPrefix = %q, want users/", c.cfg.Vault.UserPrefix)
	}
	// TokenFile defaults to DefaultTokenFile(), which is "" when the home
	// directory can't be resolved (a documented contract), so only assert
	// non-empty when home actually resolves.
	if _, err := os.UserHomeDir(); err == nil && c.cfg.TokenFile == "" {
		t.Error("TokenFile should default to a non-empty path when home resolves")
	}
}

func TestNew_RequiresAddress(t *testing.T) {
	if _, err := New(&Config{}); err == nil {
		t.Fatal("expected error for empty address")
	}
	if _, err := New(nil); err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestUserPrefixNormalised(t *testing.T) {
	c, err := New(&Config{Vault: VaultConfig{Address: "http://x", UserPrefix: "team/users"}})
	if err != nil {
		t.Fatal(err)
	}
	if c.cfg.Vault.UserPrefix != "team/users/" {
		t.Errorf("UserPrefix = %q, want team/users/", c.cfg.Vault.UserPrefix)
	}
}

func TestAuthenticateCached_NoToken(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")
	fv := newFakeVault(t)
	c := newTestClient(t, fv)

	err := c.AuthenticateCached(context.Background())
	if !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("err = %v, want ErrLoginRequired", err)
	}
}

func TestAuthenticateCached_NoTokenEmptyFilePath(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")
	fv := newFakeVault(t)
	c, err := New(&Config{Vault: VaultConfig{Address: fv.srv.URL}, TokenFile: ""})
	if err != nil {
		t.Fatal(err)
	}
	// New fills an empty TokenFile via DefaultTokenFile(); force it back to
	// "" to model the home-unresolvable case, then check the message reads
	// cleanly rather than "...no token at " with a blank path.
	c.cfg.TokenFile = ""

	err = c.AuthenticateCached(context.Background())
	if !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("err = %v, want ErrLoginRequired", err)
	}
	if strings.Contains(err.Error(), "no token at ") {
		t.Errorf("error message has a blank path: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "no token file configured") {
		t.Errorf("error message = %q, want it to mention no token file configured", err.Error())
	}
}

func TestAuthenticateCached_EnvToken(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "good-token")
	fv := newFakeVault(t)
	c := newTestClient(t, fv)

	if err := c.AuthenticateCached(context.Background()); err != nil {
		t.Fatalf("AuthenticateCached: %v", err)
	}
	if c.Token() != "good-token" {
		t.Errorf("Token = %q, want good-token", c.Token())
	}
}

func TestAuthenticateCached_FileToken(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")
	fv := newFakeVault(t)
	tokenFile := filepath.Join(t.TempDir(), ".vault-token")
	if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := New(&Config{Vault: VaultConfig{Address: fv.srv.URL}, TokenFile: tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AuthenticateCached(context.Background()); err != nil {
		t.Fatalf("AuthenticateCached: %v", err)
	}
	if c.Token() != "file-token" {
		t.Errorf("Token = %q, want file-token (trimmed)", c.Token())
	}
}

func TestAuthenticateCached_InvalidToken(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "stale")
	fv := newFakeVault(t)
	fv.tokenValid = false
	c := newTestClient(t, fv)

	err := c.AuthenticateCached(context.Background())
	if !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("err = %v, want ErrLoginRequired for rejected token", err)
	}
}

func TestAuthenticateCached_Unreachable(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "tok")
	fv := newFakeVault(t)
	fv.unreachable = true
	c := newTestClient(t, fv)

	err := c.AuthenticateCached(context.Background())
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
}

func TestAuthenticate_UnreachableDoesNotLogin(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "tok")
	fv := newFakeVault(t)
	fv.unreachable = true
	c := newTestClient(t, fv)

	// AuthMethod "token" would error in Login; but Authenticate must
	// short-circuit on unreachable before reaching Login.
	err := c.Authenticate(context.Background())
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
}

func TestAuthenticate_NoTokenUnreachableDoesNotLogin(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")
	fv := newFakeVault(t)
	fv.unreachable = true
	c := newTestClient(t, fv)

	// No cached token: AuthenticateCached returns ErrLoginRequired with no
	// network call. Authenticate must then probe sys/health, find Vault
	// unreachable, and surface ErrUnreachable rather than entering the
	// interactive login flow.
	err := c.Authenticate(context.Background())
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
}

func TestAuthenticate_NoTokenReachableProceedsToLogin(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")
	fv := newFakeVault(t)
	c := newTestClient(t, fv) // AuthMethod "token"

	// No cached token but Vault is reachable: the health probe passes and
	// Authenticate proceeds to Login, which fails for AuthMethod "token"
	// (nothing to do) with ErrAuthFailed — proving the probe doesn't block
	// a reachable server from reaching the login flow.
	err := c.Authenticate(context.Background())
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("err = %v, want ErrAuthFailed", err)
	}
}

func TestReadKVField(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "good-token")
	fv := newFakeVault(t)
	fv.secrets["kv/users/tester/gh"] = map[string]any{"oauth_token": "ghp_abc", "user": "tester"}
	c := newTestClient(t, fv)
	if err := c.AuthenticateCached(context.Background()); err != nil {
		t.Fatal(err)
	}

	val, found, err := c.ReadKVField(context.Background(), "kv", "users/tester/gh", "oauth_token")
	if err != nil || !found || val != "ghp_abc" {
		t.Fatalf("got (%q, %v, %v), want (ghp_abc, true, nil)", val, found, err)
	}

	// Missing field on an existing secret → ("", false, nil).
	_, found, err = c.ReadKVField(context.Background(), "kv", "users/tester/gh", "nope")
	if err != nil || found {
		t.Fatalf("missing field: got (found=%v, err=%v), want (false, nil)", found, err)
	}

	// Missing secret path → ("", false, nil).
	_, found, err = c.ReadKVField(context.Background(), "kv", "users/tester/absent", "x")
	if err != nil || found {
		t.Fatalf("missing path: got (found=%v, err=%v), want (false, nil)", found, err)
	}
}

func TestReadKVField_Unreachable(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "good-token")
	fv := newFakeVault(t)
	c := newTestClient(t, fv)
	if err := c.AuthenticateCached(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Flip the server to reject everything as unreachable after auth.
	fv.unreachable = true
	_, _, err := c.ReadKVField(context.Background(), "kv", "users/tester/gh", "oauth_token")
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
}

func TestReadUserSecret(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "good-token")
	fv := newFakeVault(t)
	c := newTestClient(t, fv)
	if err := c.AuthenticateCached(context.Background()); err != nil {
		t.Fatal(err)
	}

	id, err := c.IdentityName()
	if err != nil {
		t.Fatalf("IdentityName: %v", err)
	}
	fv.secrets["kv/users/"+id+"/svc"] = map[string]any{"token": "sk-xyz"}

	val, found, err := c.ReadUserSecret(context.Background(), "svc", "token")
	if err != nil || !found || val != "sk-xyz" {
		t.Fatalf("got (%q, %v, %v), want (sk-xyz, true, nil)", val, found, err)
	}
}

func TestWithIdentity(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "good-token")
	fv := newFakeVault(t)
	c, err := New(&Config{
		Vault:     VaultConfig{Address: fv.srv.URL},
		TokenFile: filepath.Join(t.TempDir(), ".vault-token"),
	}, WithIdentity("override-user"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AuthenticateCached(context.Background()); err != nil {
		t.Fatal(err)
	}

	id, err := c.IdentityName()
	if err != nil || id != "override-user" {
		t.Fatalf("IdentityName = %q (err %v), want override-user", id, err)
	}

	// ReadUserSecret must compose the path with the overridden identity, not
	// the host OS user.
	fv.secrets["kv/users/override-user/gh"] = map[string]any{"oauth_token": "ghp_z"}
	val, found, err := c.ReadUserSecret(context.Background(), "gh", "oauth_token")
	if err != nil || !found || val != "ghp_z" {
		t.Fatalf("got (%q, %v, %v), want (ghp_z, true, nil)", val, found, err)
	}
}

func TestWithIdentity_EmptyFallsBack(t *testing.T) {
	fv := newFakeVault(t)
	base, err := New(&Config{Vault: VaultConfig{Address: fv.srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	over, err := New(&Config{Vault: VaultConfig{Address: fv.srv.URL}}, WithIdentity(""))
	if err != nil {
		t.Fatal(err)
	}
	baseID, err := base.IdentityName()
	if err != nil {
		t.Fatal(err)
	}
	overID, err := over.IdentityName()
	if err != nil {
		t.Fatal(err)
	}
	// An empty WithIdentity must be ignored, falling back to the OS user —
	// identical to constructing with no option.
	if overID == "" || overID != baseID {
		t.Fatalf("empty WithIdentity should fall back to OS user: base=%q override=%q", baseID, overID)
	}
}

func TestReadKVField_Denied(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "good-token")
	fv := newFakeVault(t)
	c := newTestClient(t, fv)
	if err := c.AuthenticateCached(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Authenticated, then the token loses access (e.g. policy change/revocation)
	// — a read must surface ErrDenied, distinct from ErrUnreachable.
	fv.tokenValid = false
	_, _, err := c.ReadKVField(context.Background(), "kv", "users/tester/gh", "oauth_token")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
}

func TestReadKVField_NonStringStringified(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "good-token")
	fv := newFakeVault(t)
	fv.secrets["kv/users/tester/meta"] = map[string]any{"count": 42, "on": true}
	c := newTestClient(t, fv)
	if err := c.AuthenticateCached(context.Background()); err != nil {
		t.Fatal(err)
	}
	val, found, err := c.ReadKVField(context.Background(), "kv", "users/tester/meta", "count")
	if err != nil || !found || val != "42" {
		t.Fatalf("got (%q, %v, %v), want (42, true, nil)", val, found, err)
	}
}
