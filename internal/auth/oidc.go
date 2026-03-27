package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/pkg/browser"
)

func (m *Manager) authenticateOIDC(ctx context.Context) error {
	mount := m.AuthMount
	if mount == "" {
		mount = "oidc"
	}

	// Start local callback listener on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start callback listener: %w", err)
	}
	defer listener.Close()

	callbackPort := listener.Addr().(*net.TCPAddr).Port
	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/oidc/callback", callbackPort)

	// Request auth URL from Vault
	data := map[string]interface{}{
		"redirect_uri": callbackURL,
		"role":         m.AuthRole,
	}
	secret, err := m.VaultClient.Raw().Logical().WriteWithContext(ctx,
		fmt.Sprintf("auth/%s/oidc/auth_url", mount), data)
	if err != nil {
		return fmt.Errorf("get OIDC auth URL: %w", err)
	}

	authURL, ok := secret.Data["auth_url"].(string)
	if !ok || authURL == "" {
		return fmt.Errorf("no auth_url in OIDC response")
	}

	// Channel to receive the callback result
	type callbackResult struct {
		code  string
		state string
		err   error
	}
	resultCh := make(chan callbackResult, 1)

	// Handle the callback
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if code == "" {
			errMsg := r.URL.Query().Get("error")
			resultCh <- callbackResult{err: fmt.Errorf("OIDC callback error: %s", errMsg)}
			fmt.Fprint(w, "Authentication failed. You can close this window.")
			return
		}
		resultCh <- callbackResult{code: code, state: state}
		fmt.Fprint(w, "Authentication successful! You can close this window.")
	})

	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Shutdown(ctx)

	// Open browser
	slog.Info("opening browser for OIDC authentication", "url", authURL)
	if err := browser.OpenURL(authURL); err != nil {
		slog.Warn("failed to open browser, please visit URL manually", "url", authURL, "error", err)
	}

	// Wait for callback
	select {
	case result := <-resultCh:
		if result.err != nil {
			return result.err
		}

		// Exchange code for token via Vault
		loginData := map[string]interface{}{
			"code":  result.code,
			"state": result.state,
		}
		loginSecret, err := m.VaultClient.Raw().Logical().WriteWithContext(ctx,
			fmt.Sprintf("auth/%s/oidc/callback", mount), loginData)
		if err != nil {
			return fmt.Errorf("OIDC token exchange: %w", err)
		}
		if loginSecret == nil || loginSecret.Auth == nil {
			return fmt.Errorf("no auth data in OIDC callback response")
		}

		token := loginSecret.Auth.ClientToken
		m.VaultClient.SetToken(token)

		if err := WriteTokenFile(m.TokenFilePath, token); err != nil {
			slog.Warn("failed to write token file", "error", err)
		}

		slog.Info("OIDC authentication successful")
		return nil

	case <-ctx.Done():
		return fmt.Errorf("OIDC auth timed out: %w", ctx.Err())
	}
}
