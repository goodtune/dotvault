//go:build linux

package securestore

import (
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
)

// openTPMDevice opens the Linux TPM resource manager device. /dev/tpmrm0 is
// the in-kernel resource manager (preferred over the raw /dev/tpm0), which
// multiplexes access so dotvault does not need exclusive ownership of the
// chip. A standard user needs membership of the tss group; no elevation.
func openTPMDevice() (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM("/dev/tpmrm0")
}
