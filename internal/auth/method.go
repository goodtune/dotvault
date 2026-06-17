package auth

import "strings"

// tpmSuffix is appended to a base auth method to request TPM-sealing of the
// cached Vault token at rest, e.g. "oidc+tpm", "ldap+tpm", "mtls+tpm". It is a
// general modifier: it works with any base method and is independent of the
// cert-key sealing that "mtls+tpm" additionally performs (the cert flow keys
// off the full "mtls+tpm" string via securestore.ModeForMethod).
const tpmSuffix = "+tpm"

// SealTokenAtRest reports whether the auth method requests TPM-sealing of the
// token file — the "+tpm" suffix. When true, WriteTokenFile seals the token
// under the TPM and writes a self-describing sealed envelope, which
// ReadTokenFile transparently unseals on read (so the daemon, the CLI, and the
// public client/ facade all consume it without knowing the method).
func SealTokenAtRest(method string) bool {
	return strings.HasSuffix(method, tpmSuffix)
}

// BaseMethod strips the "+tpm" sealing modifier, returning the underlying
// auth flow: "oidc", "ldap", "token", or "mtls". The login dispatch switches
// on this so a "+tpm" variant routes to the same flow as its base.
func BaseMethod(method string) string {
	return strings.TrimSuffix(method, tpmSuffix)
}
