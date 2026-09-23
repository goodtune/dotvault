//go:build !linux

package tokenwatch

// NewMatch returns a no-op Watcher on platforms without inotify; Run blocks
// until ctx is cancelled and onChange is never invoked. Callers re-resolve
// on demand instead — see internal/peer.Pool.
func NewMatch(dir string, match func(name string) bool, onChange func(name string)) (*Watcher, error) {
	return &Watcher{}, nil
}
