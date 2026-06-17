//go:build !linux && !windows

package securestore

// openHardware reports no hardware backend on platforms without a TPM
// integration. macOS would slot a Secure Enclave backend in here once the
// binary is code-signed with the keychain-access-groups entitlement; until
// then "mtls+tpm" returns ErrUnsupported rather than silently degrading to a
// plaintext on-disk key.
func openHardware() (Storage, error) {
	return nil, ErrUnsupported
}
