//go:build !windows

package perms

import "os"

// IsPrivateFile reports whether path is accessible only by its owner.
// On Unix this checks that the file mode is exactly 0600.
func IsPrivateFile(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.Mode().Perm() != 0o600, nil
}

// IsGroupWorldWritable reports whether path is writable by group or others.
// On Unix this checks for the 0022 bits in the file mode.
func IsGroupWorldWritable(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.Mode().Perm()&0o022 != 0, nil
}
