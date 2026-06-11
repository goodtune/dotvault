package store

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
)

// fakeVault is a minimal Vault façade for exercising the driver's auth
// lifecycle without a real server: kubernetes logins mint sequential tokens,
// and a configurable set of tokens is answered with 403 so the re-login +
// retry path runs.
type fakeVault struct {
	t *testing.T

	mu            sync.Mutex
	logins        int
	jwtsSeen      []string
	tokensIssued  []string
	deniedTokens  map[string]bool
	leaseDuration int
	docs          map[string]string // data path → doc field
}

func newFakeVault(t *testing.T) (*fakeVault, *httptest.Server) {
	f := &fakeVault{
		t:             t,
		deniedTokens:  map[string]bool{},
		leaseDuration: 3600,
		docs:          map[string]string{},
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

	switch {
	case r.URL.Path == "/v1/auth/token/lookup-self":
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": token}})
	case strings.HasPrefix(r.URL.Path, "/v1/") && r.Method == http.MethodGet:
		doc, ok := f.docs[strings.TrimPrefix(r.URL.Path, "/v1/")]
		if !ok {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"data": map[string]any{"doc": doc}},
		})
	default:
		http.Error(w, `{"errors":["unhandled"]}`, http.StatusNotFound)
	}
}

func writeJWT(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "jwt")
	if err := os.WriteFile(path, []byte(content+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVaultStoreKubernetesReloginOn403(t *testing.T) {
	fake, ts := newFakeVault(t)
	jwtPath := writeJWT(t, t.TempDir(), "jwt-one")

	ctx := context.Background()
	st, err := OpenVault(ctx, VaultStoreConfig{
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
	fake.docs["secret/data/dotvault-config/layers/global"] = "rules: []\n"
	// Revoke the first token: the next read must re-login and retry. The
	// rotated JWT file must be re-read for that login.
	fake.deniedTokens["k8s-token-1"] = true
	fake.mu.Unlock()
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
	st, err := OpenVault(ctx, VaultStoreConfig{
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
	st, err := OpenVault(ctx, VaultStoreConfig{
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
	_, err := OpenVault(context.Background(), VaultStoreConfig{
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
	fake, ts := newFakeVault(t)
	_ = fake

	t.Setenv("VAULT_TOKEN", "env-token")
	st, err := OpenVault(context.Background(), VaultStoreConfig{
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
	if _, err := OpenVault(context.Background(), VaultStoreConfig{Address: ts.URL}); err == nil {
		t.Fatal("OpenVault with no token anywhere succeeded, want error")
	}
}
