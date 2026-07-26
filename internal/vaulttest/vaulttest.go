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
	"os"
	"os/exec"
	"strings"
	"testing"
)

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
	out, err := exec.Command("docker", "exec", "dotvault-vault",
		"cat", "/vault/data/root-token").Output()
	if err != nil {
		t.Skipf("cannot read the dev Vault root token (start the stack with `docker compose up -d`, or set DOTVAULT_TEST_ROOT_TOKEN): %v", err)
	}
	tok := strings.TrimSpace(string(out))
	if tok == "" {
		t.Skip("the dev Vault has not finished initialising (no root token yet)")
	}
	return tok
}
