//go:build !windows

package securestore

// openOSStore reports no OS-native certificate-store backend on non-Windows
// platforms. The backend is implemented with github.com/google/certtostore,
// which is Windows-only (CNG). A Linux backend would target a PKCS#11 module
// (NSS/p11-kit) and a macOS backend the Keychain/Secure Enclave via
// Security.framework — both are future work — so until then "mtls+os" returns
// ErrUnsupported here rather than silently degrading to an on-disk key. This
// file imports nothing from certtostore, keeping the default Linux/macOS builds
// pure-Go and CGO-free.
func openOSStore() (Storage, error) {
	return nil, ErrUnsupported
}
