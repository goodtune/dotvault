//go:build linux

package tokenwatch

import (
	"bytes"
	"unsafe"

	"golang.org/x/sys/unix"
)

// NewMatch registers an inotify watch on dir and returns a Watcher whose Run
// calls onChange(name) for every create / close-write / moved-to event whose
// entry name satisfies match. It generalises New — which watches one literal
// name — for the peer socket pool, where one directory holds many sockets
// selected by a glob. Registration is synchronous, as for New.
func NewMatch(dir string, match func(name string) bool, onChange func(name string)) (*Watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	if _, err := unix.InotifyAddWatch(fd, dir, watchMask); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &Watcher{fd: fd, match: match, onChange: onChange}, nil
}

// matchedNames returns the entry names in buf, in order, that satisfy match.
// Duplicates are preserved: a burst of events for one socket is harmless to
// the callers (both are idempotent) and collapsing them here would hide the
// count from a test.
func matchedNames(buf []byte, match func(string) bool) []string {
	var out []string
	offset := 0
	for offset+unix.SizeofInotifyEvent <= len(buf) {
		raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
		nameLen := int(raw.Len)
		start := offset + unix.SizeofInotifyEvent
		end := start + nameLen
		if nameLen > 0 && end <= len(buf) {
			evName := buf[start:end]
			if i := bytes.IndexByte(evName, 0); i >= 0 {
				evName = evName[:i]
			}
			if n := string(evName); match(n) {
				out = append(out, n)
			}
		}
		offset = end
	}
	return out
}
