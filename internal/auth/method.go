package auth

import "strings"

// tpmSuffix is appended to a base auth method to request TPM-sealing of the
// cached Vault token at rest, e.g. "oidc+tpm", "ldap+tpm", "mtls+tpm". It is a
// general modifier: it works with any base method and is independent of the
// cert-key sealing that "mtls+tpm" additionally performs (the cert flow keys
// off the full "mtls+tpm" string via securestore.ModeForMethod).
const tpmSuffix = "+tpm"

// osSuffix selects the OS-native certificate store as the backend for a cert
// key, e.g. "mtls+os". Unlike "+tpm" it is meaningful only on "mtls" (it picks
// the securestore "os" backend via securestore.ModeForMethod) and, deliberately,
// does NOT seal the cached token at rest — the OS store protects the certificate
// key, while the operational token stays a plaintext 0600 file exactly as plain
// "mtls". The suffix exists so the login dispatch can still route "mtls+os" to
// the same cert flow as its "mtls" base.
const osSuffix = "+os"

// modifierSuffixes are the trailing modifiers BaseMethod strips to recover the
// underlying auth flow. Order is irrelevant — a method carries at most one.
var modifierSuffixes = []string{tpmSuffix, osSuffix}

// SealTokenAtRest reports whether the auth method requests TPM-sealing of the
// token file — the "+tpm" suffix. When true, WriteTokenFile seals the token
// under the TPM and writes a self-describing sealed envelope, which
// ReadTokenFile transparently unseals on read (so the daemon, the CLI, and the
// public client/ facade all consume it without knowing the method). The "+os"
// modifier does NOT seal the token (it governs cert-key storage only).
func SealTokenAtRest(method string) bool {
	return strings.HasSuffix(method, tpmSuffix)
}

// BaseMethod strips a modifier suffix ("+tpm" or "+os"), returning the
// underlying auth flow: "oidc", "ldap", "token", or "mtls". The login dispatch
// switches on this so a modified variant routes to the same flow as its base.
func BaseMethod(method string) string {
	for _, suffix := range modifierSuffixes {
		if strings.HasSuffix(method, suffix) {
			return strings.TrimSuffix(method, suffix)
		}
	}
	return method
}
