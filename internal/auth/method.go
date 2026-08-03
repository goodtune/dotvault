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
// the securestore "os" backend via securestore.ModeForMethod). The suffix exists
// so the login dispatch can still route "mtls+os" to the same cert flow as its
// "mtls" base.
//
// It does not seal the token file, because on "mtls+os" it does not write one
// at all — see PersistTokenAtRest.
const osSuffix = "+os"

// methodMTLSOS is the one auth method that keeps no Vault token at rest. It is
// named rather than composed from osSuffix because the no-persist behaviour is
// specific to this method, not to the suffix — see PersistTokenAtRest.
// Unexported: callers ask the predicate, not the constant.
const methodMTLSOS = "mtls" + osSuffix

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

// PersistTokenAtRest reports whether the operational Vault token may be cached
// on disk at all. It is false for exactly one method — "mtls+os" — and true for
// every other, including any other base wearing the "+os" suffix.
//
// The literal comparison is deliberate. The suffix parses on any base for
// uniformity (BaseMethod strips it), but nothing else about "+os" is
// implemented off "mtls": there is no auth_method allowlist, so a config naming
// "oidc+os" loads and routes to authenticateOIDC, which writes the token file
// unconditionally and never consults this predicate. Keying off the bare suffix
// would make this function claim no-persist for a flow that then persists
// anyway — a guarantee stated but not enforced, which is worse than not
// claiming it. This godoc is the canonical statement of that reasoning; other
// sites applying the gate should point here rather than restate it.
//
// The point of "mtls+os" is that the credential lives inside the OS-native
// certificate store and never leaves it: the CNG key is generated
// non-exportable and verified so at generation time. A plaintext 0600 token
// file sitting beside that store would undo the guarantee — it is a bearer
// credential for the same Vault identity, obtainable by anything that can read
// one file, protected by nothing the OS store provides.
//
// Unlike "+tpm", which keeps a file and seals it, "+os" keeps no file. Sealing
// under the OS store is not available in the way the TPM offers it: the CNG key
// is deliberately non-exportable and sign-oriented, and "mtls+os" accepts EC
// P-256 as well as RSA, so there is no decrypt primitive that works for both key
// types. Wrapping the token under some *other* Windows facility (DPAPI, say)
// would protect it, but it would also create a second durable secret-bearing
// artefact outside the certificate store — precisely what this method exists to
// avoid.
//
// Not writing the token costs little, because it is not load-bearing here. The
// certificate is the credential; an operational token is re-derived from it by
// Manager.CertLoginFromStore with no human involvement, so the file was only
// ever a latency optimisation. Callers that previously read it need a different
// answer under this method — see the call sites in cmd/dotvault and
// client.AuthenticateCached.
func PersistTokenAtRest(method string) bool {
	return method != methodMTLSOS
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
