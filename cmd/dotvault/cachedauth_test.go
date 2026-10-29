package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// fakeLookupVault answers lookup-self with 200 for token "good" and 403 for
// anything else.
func fakeLookupVault(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/auth/token/lookup-self" || r.Header.Get("X-Vault-Token") != "good" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"errors":["permission denied"]}`)
			return
		}
		fmt.Fprint(w, `{"data":{"ttl":3600}}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// servePeerToken stands up a peer socket lending token, returning its path.
func servePeerToken(t *testing.T, token string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dvkv") // short: sun_path is ~104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "peer.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"token":%q}`, token)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func cachedAuthTestConfig(addr string, sockets ...string) *config.Config {
	return &config.Config{Vault: config.VaultConfig{
		Address:      addr,
		AuthMethod:   "oidc",
		TokenSockets: config.SocketList(append([]string{}, sockets...)),
	}}
}

func TestCachedVaultClient(t *testing.T) {
	vaultSrv := fakeLookupVault(t)
	nowhere := filepath.Join(t.TempDir(), "absent.sock")

	setup := func(t *testing.T, env, file string) {
		t.Helper()
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		t.Setenv("DOTVAULT_TOKEN", env)
		if file != "" {
			if err := os.WriteFile(filepath.Join(home, ".dotvault-token"), []byte(file), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	ctx := context.Background()

	t.Run("env token", func(t *testing.T) {
		setup(t, "good", "")
		vc, err := cachedVaultClient(ctx, cachedAuthTestConfig(vaultSrv.URL, nowhere), "alice")
		if err != nil || vc.Token() != "good" {
			t.Fatalf("vc=%v err=%v", vc, err)
		}
	})

	t.Run("token file", func(t *testing.T) {
		setup(t, "", "good")
		if _, err := cachedVaultClient(ctx, cachedAuthTestConfig(vaultSrv.URL, nowhere), "alice"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("borrowed when nothing local", func(t *testing.T) {
		setup(t, "", "")
		sock := servePeerToken(t, "good")
		vc, err := cachedVaultClient(ctx, cachedAuthTestConfig(vaultSrv.URL, sock), "alice")
		if err != nil || vc.Token() != "good" {
			t.Fatalf("vc=%v err=%v", vc, err)
		}
	})

	t.Run("local token wins over a peer", func(t *testing.T) {
		setup(t, "", "bad")
		sock := servePeerToken(t, "good")
		_, err := cachedVaultClient(ctx, cachedAuthTestConfig(vaultSrv.URL, sock), "alice")
		if err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("err = %v, want the local token judged (and rejected) first", err)
		}
	})

	t.Run("rejected token points at login", func(t *testing.T) {
		setup(t, "bad", "")
		_, err := cachedVaultClient(ctx, cachedAuthTestConfig(vaultSrv.URL, nowhere), "alice")
		if !errors.Is(err, errCachedAuth) || !strings.Contains(err.Error(), "dotvault login") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("unreachable vault does not point at login", func(t *testing.T) {
		setup(t, "good", "")
		t.Setenv("VAULT_MAX_RETRIES", "0")
		dead := httptest.NewServer(http.NotFoundHandler())
		dead.Close()
		_, err := cachedVaultClient(ctx, cachedAuthTestConfig(dead.URL, nowhere), "alice")
		if !errors.Is(err, errCachedAuth) || !strings.Contains(err.Error(), "unreachable") || strings.Contains(err.Error(), "login") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("no token at all", func(t *testing.T) {
		setup(t, "", "")
		_, err := cachedVaultClient(ctx, cachedAuthTestConfig(vaultSrv.URL, nowhere), "alice")
		if !errors.Is(err, errCachedAuth) || !strings.Contains(err.Error(), "not authenticated") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("borrow-only says so", func(t *testing.T) {
		setup(t, "", "")
		cfg := cachedAuthTestConfig(vaultSrv.URL, nowhere)
		cfg.Vault.BorrowOnly = true
		cfg.Vault.AuthMethod = "mtls+os" // ignored under borrow_only: no cert login
		_, err := cachedVaultClient(ctx, cfg, "alice")
		if !errors.Is(err, errCachedAuth) || !strings.Contains(err.Error(), "borrow-only") {
			t.Fatalf("err = %v", err)
		}
	})
}
