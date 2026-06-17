package auth

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/goodtune/dotvault/internal/perms"
	"github.com/goodtune/dotvault/internal/securestore"
)

// sealedTokenPrefix marks a token file whose body is a TPM-sealed, base64
// envelope rather than a plaintext token. The "$dotvault…$" shape cannot
// collide with a real Vault token (tokens are dotted identifiers like
// "hvs.…"), so ReadTokenFile can detect the format from the content alone —
// which is what lets every reader (daemon, CLI, public client) consume a
// sealed token without being told the auth method.
const sealedTokenPrefix = "$dotvault-tpm-sealed$v1$"

// sealData / unsealData are indirected through package vars so the envelope
// format and call-site policy can be unit-tested without a physical TPM.
var (
	sealData   = securestore.SealData
	unsealData = securestore.UnsealData
)

// ReadTokenFile reads a Vault token from a file, trimming whitespace.
// Returns empty string (not error) if the file doesn't exist.
//
// A file written by WriteTokenFile with sealing on carries sealedTokenPrefix;
// this transparently unseals it via the TPM. A plaintext file is returned
// verbatim, so existing token files keep working and migration is free.
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

	s := strings.TrimSpace(string(data))
	if b64, ok := strings.CutPrefix(s, sealedTokenPrefix); ok {
		handle, decErr := base64.StdEncoding.DecodeString(b64)
		if decErr != nil {
			return "", fmt.Errorf("decode sealed token file: %w", decErr)
		}
		plain, unErr := unsealData(handle)
		if unErr != nil {
			// No secret material in this message — only the cause. Surfaced so
			// a parallel `dotvault login` / status can see why the cached
			// token could not be used (missing/cleared TPM, or the blob was
			// copied from another machine), then re-authenticate.
			slog.Warn("could not unseal TPM-sealed token file; re-authentication required",
				"path", path, "error", unErr)
			return "", fmt.Errorf("unseal token file: %w", unErr)
		}
		return strings.TrimSpace(string(plain)), nil
	}
	return s, nil
}

// ReadTokenEnv reads the Vault token from the DOTVAULT_TOKEN environment
// variable. VAULT_TOKEN is deliberately ignored — it belongs to the `vault`
// CLI, and honouring it would let an unrelated shell session's token leak
// into the daemon (the Vault SDK's own VAULT_TOKEN pickup is likewise
// neutralised in internal/vault.NewClient).
//
// An env-var token is necessarily plaintext: there is no way to TPM-seal an
// environment value. The "+tpm" sealing applies only to the token file.
func ReadTokenEnv() string {
	return os.Getenv("DOTVAULT_TOKEN")
}

// ResolveToken returns a Vault token, checking the DOTVAULT_TOKEN env var
// first, then the token file. Returns empty string if neither is set. A
// sealed token file that cannot be unsealed resolves to "" (the warning is
// logged in ReadTokenFile), which the auth flow treats as "no usable token,
// re-authenticate" — never a silent plaintext fallback.
func ResolveToken(tokenFilePath string) string {
	if token := ReadTokenEnv(); token != "" {
		return token
	}
	token, _ := ReadTokenFile(tokenFilePath)
	return token
}

// WriteTokenFile writes a Vault token to a file with 0600 permissions. When
// seal is true the token is sealed under the TPM (machine-bound) and written
// as a self-describing sealed envelope that ReadTokenFile transparently
// unseals. Sealing requires a working TPM (Linux/Windows); seal=true on a host
// with no hardware backend returns an error rather than silently writing
// plaintext — the same no-silent-fallback contract as mtls+tpm key sealing.
func WriteTokenFile(path string, token string, seal bool) error {
	payload := []byte(token)
	if seal {
		sealed, err := sealData([]byte(token))
		if err != nil {
			return fmt.Errorf("seal token to TPM: %w", err)
		}
		payload = []byte(sealedTokenPrefix + base64.StdEncoding.EncodeToString(sealed))
	}
	if err := os.WriteFile(path, payload, 0600); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	return nil
}
