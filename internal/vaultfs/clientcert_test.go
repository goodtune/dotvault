package vaultfs

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/goodtune/dotvault/internal/clientcert"
)

// certErrno separates "try again shortly" (EAGAIN) from a sign that failed
// (EIO) and from the caller going away (EINTR). The case that matters most is
// a caller whose own deadline ran out while a sign was still in flight: the
// sign continues detached and a retry gets its result, so it is EAGAIN, not
// the EIO a sign that itself timed out against Vault earns.
func TestCertErrno(t *testing.T) {
	waited := func(cause error) error {
		return fmt.Errorf("client certificate for %q: %w", "client.pem", fmt.Errorf("%w: %w", clientcert.ErrSignInProgress, cause))
	}
	cases := []struct {
		name string
		err  error
		want syscall.Errno
	}{
		{"no token", clientcert.ErrNoToken, syscall.EAGAIN},
		{"paced", fmt.Errorf("wrapped: %w", clientcert.ErrSignPaced), syscall.EAGAIN},
		{"caller deadline while a sign is in flight", waited(context.DeadlineExceeded), syscall.EAGAIN},
		{"caller cancelled while a sign is in flight", waited(context.Canceled), syscall.EINTR},
		{"caller cancelled", context.Canceled, syscall.EINTR},
		{"the sign itself timed out", fmt.Errorf("clientcert: sign via pki/sign/r: %w", context.DeadlineExceeded), syscall.EIO},
		{"denied", errors.New("clientcert: sign via pki/sign/r: permission denied"), syscall.EIO},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := certErrno("read", ClientPEMFile, tc.err); got != tc.want {
				t.Errorf("certErrno(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
