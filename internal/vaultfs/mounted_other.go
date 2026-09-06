//go:build !(linux || darwin || freebsd)

package vaultfs

// IsMounted always reports false where nothing can be mounted, so callers do
// not have to branch on the platform to render status.
func IsMounted(dir string) (bool, error) { return false, nil }
