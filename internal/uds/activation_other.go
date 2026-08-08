//go:build !linux

package uds

import "net"

// Socket activation is systemd's convention and therefore Linux-only.
// macOS's launchd has its own, incompatible fd-passing API and Windows has
// no Unix-socket surface at all, so elsewhere these are inert: every lookup
// reports "no activation" and the self-bind path runs unchanged. Mirrors
// internal/sdnotify's build split.

// ActivatedListener reports no activation on non-Linux platforms.
func ActivatedListener(name string) (net.Listener, string, error) {
	return nil, "", nil
}

// DrainUnclaimedActivation is a no-op off Linux.
func DrainUnclaimedActivation(keep ...string) {}
