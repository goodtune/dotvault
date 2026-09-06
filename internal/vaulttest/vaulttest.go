// Package vaulttest supplies the shared plumbing for tests that run against the
// docker-compose dev Vault.
//
// It exists because five packages each carried their own copy of a hardcoded
// "dev-root-token", which has never been a valid token: vault-init runs
// `vault operator init`, which mints a random root token and writes it to a
// volume. Those tests are guarded by a skip-if-Vault-is-down check, so with the
// stack down they skipped and with the stack up they failed 403 — meaning an
// entire tier of Vault-backed tests silently never ran. Centralising the lookup
// makes that impossible to reintroduce one package at a time.
package vaulttest

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// dockerTimeout bounds the container lookup. Without it a slow or wedged Docker
// daemon hangs the whole package until Go's 10-minute test timeout kills it,
// which is far worse than skipping: the stack being unavailable is exactly the
// case this helper is supposed to handle gracefully.
const dockerTimeout = 10 * time.Second

// RootToken returns the dev Vault's root token.
//
// DOTVAULT_TEST_ROOT_TOKEN wins when set, so CI (or a differently-named
// container) can supply it directly; otherwise it is read from the container
// where vault-init wrote it. A test that cannot obtain one skips rather than
// fails: the token is environmental, and a missing dev stack is not a defect in
// the code under test.
func RootToken(t *testing.T) string {
	t.Helper()
	if tok := strings.TrimSpace(os.Getenv("DOTVAULT_TEST_ROOT_TOKEN")); tok != "" {
		return tok
	}
	tok, err := cachedDockerToken()
	if err != nil {
		t.Skipf("cannot read the dev Vault root token (start the stack with `docker compose up -d`, or set DOTVAULT_TEST_ROOT_TOKEN): %v", err)
	}
	if tok == "" {
		t.Skip("the dev Vault has not finished initialising (no root token yet)")
	}
	return tok
}

var (
	dockerOnce  sync.Once
	dockerToken string
	dockerErr   error
)

// cachedDockerToken runs the container lookup at most once per test binary.
//
// Without caching, a package whose tests all call RootToken pays the full
// dockerTimeout on every one of them when the stack is down — turning a suite
// that should skip in milliseconds into minutes of dead waiting. The result is
// stable for a process's lifetime either way: the dev stack does not appear
// or vanish mid-run in any workflow this supports.
func cachedDockerToken() (string, error) {
	dockerOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", "exec", "dotvault-vault",
			"cat", "/vault/data/root-token").Output()
		if err != nil {
			dockerErr = err
			return
		}
		dockerToken = strings.TrimSpace(string(out))
	})
	return dockerToken, dockerErr
}
