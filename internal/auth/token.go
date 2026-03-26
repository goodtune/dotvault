package auth

import (
	"fmt"
	"os"
	"strings"
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
	return strings.TrimSpace(string(data)), nil
}

// ReadTokenEnv reads the Vault token from VAULT_TOKEN environment variable.
func ReadTokenEnv() string {
	return os.Getenv("VAULT_TOKEN")
}

// ResolveToken returns a Vault token, checking VAULT_TOKEN env var first,
// then the token file. Returns empty string if neither is set.
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
