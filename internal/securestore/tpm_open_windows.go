//go:build windows

package securestore

import (
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
)

// openTPMDevice opens the Windows TPM via TBS (the TPM Base Services system
// component, tbs.dll). Any logged-in standard user can access it with no
// elevation, no signing, and no group membership; the go-tpm windows
// OpenTPM takes no path argument and uses TBS directly.
func openTPMDevice() (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM()
}
