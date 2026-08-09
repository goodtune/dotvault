package sshfwd

import (
	"errors"
	"net"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/knownhosts"
)

// State is a managed remote's externally visible condition.
type State string

const (
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateReconnecting State = "reconnecting"
	StateOffline      State = "offline"
	StateAuthError    State = "authentication-error"
	StateHostKeyError State = "host-key-error"
	StateDisabled     State = "disabled"
)

// ErrorClass is the internal failure taxonomy. Collapsing everything into
// "offline" would make the common misconfigurations — an unauthorised
// principal, AllowStreamLocalForwarding off — indistinguishable from a flat
// battery, so the class drives both the reported state and the backoff floor.
type ErrorClass string

const (
	ClassNone        ErrorClass = ""
	ClassDNS         ErrorClass = "dns"
	ClassUnreachable ErrorClass = "network-unreachable"
	ClassRefused     ErrorClass = "connection-refused"
	ClassHandshake   ErrorClass = "handshake"
	ClassAuth        ErrorClass = "authentication"
	ClassHostKey     ErrorClass = "host-key"
	ClassBind        ErrorClass = "remote-socket-bind"
	ClassHomeProbe   ErrorClass = "home-probe"
	ClassConfig      ErrorClass = "config"
	ClassOther       ErrorClass = "other"
)

// RemoteStatus is one remote's runtime state, as served on
// GET /api/v1/status and rendered by `dotvault ssh list`.
//
// None of it is written back to ssh.yaml: reconnect counts and last errors are
// runtime facts, and persisting them would churn the user's config file.
type RemoteStatus struct {
	Host         string `json:"host"`
	State        string `json:"state"`
	RemoteSocket string `json:"remote_socket"`
	Target       string `json:"target"`

	ConnectedSince    *time.Time `json:"connected_since,omitempty"`
	Reconnects        int        `json:"reconnects"`
	ActiveConnections int        `json:"active_connections"`
	LastError         string     `json:"last_error"`
}

// Classify maps an error to its class.
func Classify(err error) ErrorClass {
	if err == nil {
		return ClassNone
	}

	switch {
	case errors.Is(err, ErrHostKeyUnknown):
		return ClassHostKey
	case errors.Is(err, syscall.ECONNREFUSED):
		return ClassRefused
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return ClassUnreachable
	case errors.Is(err, ErrAuth):
		return ClassAuth
	case errors.Is(err, ErrBind):
		return ClassBind
	case errors.Is(err, ErrHandshake):
		return ClassHandshake
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ClassDNS
	}

	var keyErr *knownhosts.KeyError
	if errors.As(err, &keyErr) {
		return ClassHostKey
	}

	return ClassOther
}
