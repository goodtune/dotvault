//go:build !windows && !darwin && !linux && !freebsd && !netbsd && !openbsd && !dragonfly && !illumos

package clipboard

import "errors"

func platformSet(_ string) error {
	return errors.New("clipboard is not supported on this platform")
}
