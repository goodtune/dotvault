//go:build !windows

package securestore

import (
	"errors"
	"testing"
)

// On non-Windows platforms the OS-native certificate-store backend is not built;
// Open("os") must report ErrUnsupported so "mtls+os" fails fast and clearly
// rather than silently degrading to a weaker store.
func TestOpenOSBackendUnsupportedOffWindows(t *testing.T) {
	if _, err := Open("os"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Open(\"os\") err = %v, want ErrUnsupported", err)
	}
}
