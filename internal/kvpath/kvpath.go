// Package kvpath owns the grammar of a path relative to a user's KV root, and
// the policy deciding which of those paths the user may write.
//
// It is deliberately a leaf: it imports nothing outside the standard library,
// so internal/config can validate a configured path list against exactly the
// rule internal/vaultfs enforces at the mount and internal/dockervol applies
// to a volume's `secrets=` option. A second implementation of "what does a
// relative KV path look like" is how the gates drift apart, and the direction
// they drift is always toward permissive.
package kvpath

import (
	"errors"
	"strings"
)

// ErrInvalidName is returned for a path component a KV path cannot carry: an
// empty name, "." or "..", or one containing a slash or NUL.
var ErrInvalidName = errors.New("invalid path component")

// Clean validates a slash-separated path relative to a user's KV root and
// returns it in canonical form (no leading or trailing slash, no empty
// segments); "" is the root.
//
// It deliberately does not use path.Clean: Vault treats logical path segments
// literally and does not collapse "..", so cleaning a path here would let
// "a/../b" resolve to a different Vault path than the one the caller named.
// Anything that is not already canonical is rejected instead.
func Clean(p string) (string, error) {
	p = strings.Trim(p, "/")
	if p == "" {
		return "", nil
	}
	for _, seg := range strings.Split(p, "/") {
		if err := ValidateName(seg); err != nil {
			return "", err
		}
	}
	return p, nil
}

// ValidateName checks a single path component.
func ValidateName(name string) error {
	if name == "" || name == "." || name == ".." {
		return ErrInvalidName
	}
	if strings.ContainsAny(name, "/\x00") {
		return ErrInvalidName
	}
	return nil
}
