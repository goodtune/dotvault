//go:build !linux

package uds

import "net"

// Socket activation is systemd's convention and therefore Linux-only.
// macOS's launchd has its own, incompatible fd-passing API and Windows has
// no Unix-socket surface at all, so elsewhere these are inert: every lookup
// reports "no activation" and the self-bind path runs unchanged. The
// go-systemd activation import is confined to the linux build; the daemon
// (sd_notify) package is imported everywhere but returns before touching a
// socket when NOTIFY_SOCKET is unset, so it is inert outside systemd.

// ActivatedListener reports no activation on non-Linux platforms.
func ActivatedListener(name string) (net.Listener, string, error) {
	return nil, "", nil
}

// DrainUnclaimedActivation is a no-op off Linux.
func DrainUnclaimedActivation(keep ...string) {}
