package auth

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/term"
)

func (m *Manager) authenticateLDAP(ctx context.Context) error {
	mount := m.AuthMount
	if mount == "" {
		mount = "ldap"
	}

	// Prompt for password
	password, err := promptPassword(fmt.Sprintf("LDAP password for %s: ", m.Username))
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}

	// Authenticate via Vault
	data := map[string]interface{}{
		"password": password,
	}
	secret, err := m.VaultClient.Raw().Logical().WriteWithContext(ctx,
		fmt.Sprintf("auth/%s/login/%s", mount, m.Username), data)
	if err != nil {
		return fmt.Errorf("LDAP authentication: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("no auth data in LDAP response")
	}

	token := secret.Auth.ClientToken
	m.VaultClient.SetToken(token)

	if err := WriteTokenFile(m.TokenFilePath, token); err != nil {
		slog.Warn("failed to write token file", "error", err)
	}

	slog.Info("LDAP authentication successful")
	return nil
}

func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after password input
	if err != nil {
		return "", err
	}
	return string(password), nil
}
