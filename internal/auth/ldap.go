package auth

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"golang.org/x/term"
)

func (m *Manager) authenticateLDAP(ctx context.Context) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("LDAP auth requires a terminal or web mode (web.enabled: true)")
	}

	mount := m.AuthMount
	if mount == "" {
		mount = "ldap"
	}

	password, err := promptPassword(fmt.Sprintf("LDAP password for %s: ", m.Username))
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}

	lt := NewLoginTracker(m.VaultClient)
	const sessionID = "cli"
	lt.StartLogin(sessionID, mount, m.Username, password)

	mfaMessagePrinted := false
	totpPrompted := false
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			lt.Clear(sessionID)
			return fmt.Errorf("authentication cancelled: %w", ctx.Err())
		case <-ticker.C:
			status := lt.GetStatus(sessionID)
			if status == nil {
				return fmt.Errorf("login session lost")
			}

			switch status.State {
			case "pending":
				continue
			case "mfa_required":
				if len(status.MFAMethods) > 0 && status.MFAMethods[0].UsesPasscode && (!totpPrompted || status.Error != "") {
					totpPrompted = true
					passcode, err := promptPassword("MFA passcode: ")
					if err != nil {
						lt.Clear(sessionID)
						return fmt.Errorf("read MFA passcode: %w", err)
					}
					lt.SubmitTOTP(sessionID, passcode)
				} else if !mfaMessagePrinted {
					mfaMessagePrinted = true
					fmt.Fprintln(os.Stderr, "Waiting for MFA approval (check your device)...")
				}
			case "authenticated":
				token := status.Token
				lt.Clear(sessionID)
				m.VaultClient.SetToken(token)
				if err := WriteTokenFile(m.TokenFilePath, token); err != nil {
					slog.Warn("failed to write token file", "error", err)
				}
				slog.Info("LDAP authentication successful")
				return nil
			case "failed":
				lt.Clear(sessionID)
				return fmt.Errorf("LDAP authentication: %s", status.Error)
			}
		}
	}
}

func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(password), nil
}
