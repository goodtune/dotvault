package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/goodtune/dotvault/internal/configsvc/store"
	"github.com/goodtune/dotvault/internal/configsvc/store/storetest"
)

// fakeVault is a minimal KVv2 façade for exercising the driver without a
// real server: kubernetes logins mint sequential tokens, a configurable set
// of tokens is answered with 403 so the re-login + retry path runs, and
// enough of the data/metadata surface (read, write, list, metadata delete)
// is implemented to pass the store conformance suite.
type fakeVault struct {
	t *testing.T

	mu            sync.Mutex
	logins        int
	jwtsSeen      []string
	tokensIssued  []string
	deniedTokens  map[string]bool
	leaseDuration int
	// secrets maps logical *data* paths (e.g.
	// "secret/data/base/layers/global") to their field maps.
	secrets map[string]map[string]any
}

func newFakeVault(t *testing.T) (*fakeVault, *httptest.Server) {
	f := &fakeVault{
		t:             t,
		deniedTokens:  map[string]bool{},
		leaseDuration: 3600,
		secrets:       map[string]map[string]any{},
	}
	ts := httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(ts.Close)
	return f, ts
}

func (f *fakeVault) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// The Vault SDK issues logical writes as PUT.
	if (r.Method == http.MethodPut || r.Method == http.MethodPost) && r.URL.Path == "/v1/auth/kubernetes/login" {
		var body struct {
			Role string `json:"role"`
			JWT  string `json:"jwt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.logins++
		f.jwtsSeen = append(f.jwtsSeen, body.JWT)
		token := fmt.Sprintf("k8s-token-%d", f.logins)
		f.tokensIssued = append(f.tokensIssued, token)
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{
				"client_token":   token,
				"lease_duration": f.leaseDuration,
			},
		})
		return
	}

	token := r.Header.Get("X-Vault-Token")
	if f.deniedTokens[token] {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"errors":["permission denied"]}`)
		return
	}

	logical := strings.TrimPrefix(r.URL.Path, "/v1/")
	isList := r.Method == "LIST" || (r.Method == http.MethodGet && r.URL.Query().Get("list") == "true")
	switch {
	case r.URL.Path == "/v1/auth/token/lookup-self":
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": token}})

	case isList:
		// LIST on a metadata path: synthesize direct children, folders
		// carrying a trailing slash.
		prefix := strings.Replace(logical, "/metadata/", "/data/", 1)
		prefix = strings.TrimSuffix(prefix, "/") + "/"
		seen := map[string]bool{}
		var keys []any
		for p := range f.secrets {
			if !strings.HasPrefix(p, prefix) {
				continue
			}
			rest := strings.TrimPrefix(p, prefix)
			if i := strings.Index(rest, "/"); i >= 0 {
				rest = rest[:i+1]
			}
			if !seen[rest] {
				seen[rest] = true
				keys = append(keys, rest)
			}
		}
		if len(keys) == 0 {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}})

	case r.Method == http.MethodGet && strings.Contains(logical, "/data/"):
		fields, ok := f.secrets[logical]
		if !ok {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"data": fields},
		})

	case (r.Method == http.MethodPut || r.Method == http.MethodPost) && strings.Contains(logical, "/data/"):
		var body struct {
			Data map[string]any `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.secrets[logical] = body.Data
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": 1}})

	case r.Method == http.MethodDelete && strings.Contains(logical, "/metadata/"):
		delete(f.secrets, strings.Replace(logical, "/metadata/", "/data/", 1))
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, `{"errors":["unhandled"]}`, http.StatusNotFound)
	}
}

func (f *fakeVault) putDoc(path, doc string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets[path] = map[string]any{"doc": doc}
}

func writeJWT(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "jwt")
	if err := os.WriteFile(path, []byte(content+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestVaultStoreConformance runs the driver-neutral suite against the fake —
// the same suite the sqlite driver passes and the integration test runs
// against a real Vault.
func TestVaultStoreConformance(t *testing.T) {
	_, ts := newFakeVault(t)
	st, err := store.OpenVault(context.Background(), store.VaultStoreConfig{
		Address: ts.URL,
		Mount:   "secret",
		Path:    "base",
		Auth:    "token",
		Token:   "unit-token",
	})
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	defer st.Close()
	storetest.Run(t, st)
}

func TestVaultStoreKubernetesReloginOn403(t *testing.T) {
	fake, ts := newFakeVault(t)
	jwtPath := writeJWT(t, t.TempDir(), "jwt-one")

	ctx := context.Background()
	st, err := store.OpenVault(ctx, store.VaultStoreConfig{
		Address:    ts.URL,
		Mount:      "secret",
		Path:       "dotvault-config",
		Auth:       "kubernetes",
		K8sRole:    "svc",
		K8sJWTPath: jwtPath,
	})
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	fake.mu.Lock()
	if fake.logins != 1 {
		t.Fatalf("logins after open = %d, want 1", fake.logins)
	}
	if fake.jwtsSeen[0] != "jwt-one" {
		t.Fatalf("login JWT = %q, want the (trimmed) file content", fake.jwtsSeen[0])
	}
	// Revoke the first token: the next read must re-login and retry. The
	// rotated JWT file must be re-read for that login.
	fake.deniedTokens["k8s-token-1"] = true
	fake.mu.Unlock()
	fake.putDoc("secret/data/dotvault-config/layers/global", "rules: []\n")
	writeJWT(t, filepath.Dir(jwtPath), "jwt-two")

	doc, ok, err := st.GetLayer(ctx, "global")
	if err != nil || !ok {
		t.Fatalf("GetLayer after revocation = ok=%v err=%v, want recovered read", ok, err)
	}
	if string(doc) != "rules: []\n" {
		t.Fatalf("GetLayer = %q", doc)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.logins != 2 {
		t.Fatalf("logins after 403 = %d, want 2 (re-login + retry)", fake.logins)
	}
	if fake.jwtsSeen[1] != "jwt-two" {
		t.Fatalf("re-login JWT = %q, want the rotated file content", fake.jwtsSeen[1])
	}
}

func TestVaultStoreKubernetesProactiveRelogin(t *testing.T) {
	fake, ts := newFakeVault(t)
	fake.leaseDuration = 0 // renewAt = now, so every subsequent op re-logs-in
	jwtPath := writeJWT(t, t.TempDir(), "jwt")

	ctx := context.Background()
	st, err := store.OpenVault(ctx, store.VaultStoreConfig{
		Address:    ts.URL,
		Auth:       "kubernetes",
		K8sRole:    "svc",
		K8sJWTPath: jwtPath,
	})
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if err := st.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.logins < 2 {
		t.Fatalf("logins = %d, want a proactive re-login before the post-lease op", fake.logins)
	}
}

func TestVaultStoreKubernetesPermanent403(t *testing.T) {
	fake, ts := newFakeVault(t)
	jwtPath := writeJWT(t, t.TempDir(), "jwt")

	ctx := context.Background()
	st, err := store.OpenVault(ctx, store.VaultStoreConfig{
		Address:    ts.URL,
		Auth:       "kubernetes",
		K8sRole:    "svc",
		K8sJWTPath: jwtPath,
	})
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	// Deny everything: the retry must not loop — exactly one re-login, then
	// the error surfaces.
	fake.mu.Lock()
	fake.deniedTokens["k8s-token-1"] = true
	fake.deniedTokens["k8s-token-2"] = true
	fake.deniedTokens["k8s-token-3"] = true
	fake.mu.Unlock()

	if _, _, err := st.GetLayer(ctx, "global"); err == nil {
		t.Fatal("GetLayer with permanent 403 succeeded, want error")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.logins != 2 {
		t.Fatalf("logins = %d, want exactly 2 (no retry loop)", fake.logins)
	}
}

func TestVaultStoreKubernetesMissingJWT(t *testing.T) {
	_, ts := newFakeVault(t)
	_, err := store.OpenVault(context.Background(), store.VaultStoreConfig{
		Address:    ts.URL,
		Auth:       "kubernetes",
		K8sRole:    "svc",
		K8sJWTPath: filepath.Join(t.TempDir(), "absent"),
	})
	if err == nil {
		t.Fatal("OpenVault with missing JWT succeeded, want error")
	}
}

func TestVaultStoreTokenEnvFallback(t *testing.T) {
	_, ts := newFakeVault(t)

	t.Setenv("VAULT_TOKEN", "env-token")
	st, err := store.OpenVault(context.Background(), store.VaultStoreConfig{
		Address: ts.URL,
		Auth:    "token",
	})
	if err != nil {
		t.Fatalf("OpenVault with VAULT_TOKEN: %v", err)
	}
	if err := st.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	t.Setenv("VAULT_TOKEN", "")
	if _, err := store.OpenVault(context.Background(), store.VaultStoreConfig{Address: ts.URL}); err == nil {
		t.Fatal("OpenVault with no token anywhere succeeded, want error")
	}
}
