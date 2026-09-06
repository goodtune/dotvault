//go:build !(linux || darwin || freebsd)

package vaultfs

// This build has no FUSE implementation. Windows is the case that matters:
// the closest equivalent is WinFsp, which is a DLL reached through cgo, and
// dotvault builds every shipped binary with CGO_ENABLED=0. Rather than carry
// a dependency that cannot be built here, the surface reports that it does
// not exist and the daemon carries on without it — the same shape
// internal/tray and internal/securestore use.

// mount reports that this platform cannot mount a filesystem. Service.Run
// surfaces the error; nothing else in the package is platform-specific.
func mount(mountpoint string, tree *Tree, opts Options) (mountedFS, error) {
	return nil, ErrUnsupported
}

// clearStaleMount has nothing to clear where nothing can be mounted.
func clearStaleMount(dir string, statErr error) bool { return false }
