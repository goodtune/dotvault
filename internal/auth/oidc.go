package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"syscall"

	"github.com/pkg/browser"
)

// openBrowser opens authURL in the user's default browser. Indirected so
// tests can stub it out — authenticateOIDC otherwise pops a real browser tab.
var openBrowser = browser.OpenURL

// defaultOIDCCallbackPort is the local TCP port authenticateOIDC tries first
// for the OAuth redirect_uri when vault.oidc_callback_port is unset. It
// matches the `vault` CLI's own default (`vault login -method=oidc`), so a
// Vault role/IdP already allow-listing the vault CLI's redirect URI
// typically works for dotvault without any change.
const defaultOIDCCallbackPort = 8250

// listenForOIDCCallback binds the local HTTP listener used for the OIDC
// redirect_uri. It tries the configured (or default) fixed port first, so
// operators can register one predictable redirect_uri with both the Vault
// auth role and the identity provider instead of relying on RFC 8252
// loopback (port-agnostic) redirect matching, which not every IdP
// implements. If that port is already bound by another process (e.g. a
// concurrent login, or the `vault` CLI itself — syscall.EADDRINUSE), it
// falls back to an OS-assigned random port and logs why — a working, if
// less operable, fallback rather than a hard failure. Any other bind
// failure (permission denied on a privileged port, a firewall/policy block)
// is returned as a hard error instead of being silently masked by the same
// fallback: those conditions won't clear themselves on the next login the
// way a transient port conflict does, so failing loudly surfaces the
// misconfiguration instead of quietly degrading to the less reliable
// random-port path forever.
func listenForOIDCCallback(configuredPort int) (net.Listener, int, error) {
	port := configuredPort
	if port <= 0 {
		port = defaultOIDCCallbackPort
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		if !errors.Is(err, syscall.EADDRINUSE) {
			return nil, 0, fmt.Errorf("bind OIDC callback port %d: %w", port, err)
		}
		slog.Warn("OIDC callback port already in use, falling back to a random port; register a fixed redirect_uri with Vault and your identity provider for a more predictable login", "port", port, "error", err)
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, 0, err
		}
	}
	return listener, listener.Addr().(*net.TCPAddr).Port, nil
}

func (m *Manager) authenticateOIDC(ctx context.Context) error {
	mount := m.AuthMount
	if mount == "" {
		mount = "oidc"
	}

	listener, callbackPort, err := listenForOIDCCallback(m.OIDCCallbackPort)
	if err != nil {
		return fmt.Errorf("start callback listener: %w", err)
	}
	defer listener.Close()

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
		return fmt.Errorf("no auth_url in OIDC response: Vault returned success but no URL, which typically means the redirect_uri was rejected; verify that %q is present verbatim (scheme, host, and path — Vault ignores only the port) in the allowed_redirect_uris of auth mount %q role %q, and that your identity provider also allows this exact redirect URI",
			callbackURL, mount, m.AuthRole)
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
	if err := openBrowser(authURL); err != nil {
		slog.Warn("failed to open browser, please visit URL manually", "url", authURL, "error", err)
	}

	// Wait for callback
	select {
	case result := <-resultCh:
		if result.err != nil {
			return result.err
		}

		// Exchange code for token via Vault
		callbackPath := fmt.Sprintf("auth/%s/oidc/callback", mount)
		loginData := map[string][]string{
			"code":  {result.code},
			"state": {result.state},
		}
		loginSecret, err := m.VaultClient.Raw().Logical().ReadWithDataWithContext(ctx,
			callbackPath, loginData)
		if err != nil {
			return fmt.Errorf("OIDC token exchange: %w", err)
		}
		if loginSecret == nil || loginSecret.Auth == nil {
			return fmt.Errorf("no auth data in OIDC callback response")
		}

		token, err := Downscope(ctx, m.VaultClient, loginSecret.Auth.ClientToken, m.Policy)
		if err != nil {
			return err
		}
		m.VaultClient.SetToken(token)

		if err := WriteTokenFile(m.TokenFilePath, token, SealTokenAtRest(m.AuthMethod)); err != nil {
			slog.Warn("failed to write token file", "error", err)
		}

		slog.Info("OIDC authentication successful")
		return nil

	case <-ctx.Done():
		return fmt.Errorf("OIDC auth timed out: %w", ctx.Err())
	}
}
