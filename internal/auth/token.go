package auth

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/goodtune/dotvault/internal/perms"
)

// ReadTokenFile reads a Vault token from a file, trimming whitespace.
// Returns empty string (not error) if file doesn't exist.
func ReadTokenFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read token file: %w", err)
	}

	// Warn if token file has overly permissive permissions.
	if insecure, checkErr := perms.IsPrivateFile(path); checkErr == nil && insecure {
		slog.Warn("token file has insecure permissions", "path", path)
	}

	return strings.TrimSpace(string(data)), nil
}

// ReadTokenEnv reads the Vault token from the DOTVAULT_TOKEN environment
// variable. VAULT_TOKEN is deliberately ignored — it belongs to the `vault`
// CLI, and honouring it would let an unrelated shell session's token leak
// into the daemon (the Vault SDK's own VAULT_TOKEN pickup is likewise
// neutralised in internal/vault.NewClient).
func ReadTokenEnv() string {
	return os.Getenv("DOTVAULT_TOKEN")
}

// ResolveToken returns a Vault token, checking the DOTVAULT_TOKEN env var
// first, then the token file. Returns empty string if neither is set.
func ResolveToken(tokenFilePath string) string {
	if token := ReadTokenEnv(); token != "" {
		return token
	}
	token, _ := ReadTokenFile(tokenFilePath)
	return token
}

// WriteTokenFile writes a Vault token to a file with 0600 permissions.
func WriteTokenFile(path string, token string) error {
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	return nil
}
