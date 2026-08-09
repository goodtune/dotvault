package sshfwd

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ErrHostKeyUnknown reports a host whose key is neither pinned in ssh.yaml nor
// signed by a configured certificate authority. It is distinct from a
// *mismatch*: unknown is the normal state before `dotvault ssh add` pins a
// key, and the CLI turns it into a fingerprint prompt rather than an error.
var ErrHostKeyUnknown = errors.New("host key is not pinned and no configured CA signed it")

// HostKeyPolicy decides whether to trust a remote's host key.
//
// There is deliberately no runtime trust-on-first-use. Pinning happens exactly
// once, during `dotvault ssh add`, which is an explicit human gesture; the
// daemon reconnecting in the background must never make that decision on the
// user's behalf.
type HostKeyPolicy struct {
	// CAs are known_hosts @cert-authority lines from the system config.
	CAs []string

	// Pinned is this host's key in authorized_keys form, empty when unpinned.
	Pinned string

	// Insecure disables verification entirely (system config opt-in).
	Insecure bool
}

// Callback returns the ssh.HostKeyCallback implementing the policy. When
// observed is non-nil the presented key is stored there before any accept or
// reject decision, so a caller that rejects can still report the fingerprint
// it saw — which is exactly what `ssh add` needs to prompt.
func (p HostKeyPolicy) Callback(observed *ssh.PublicKey) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if observed != nil {
			*observed = key
		}

		if p.Insecure {
			// Logged on every attempt, naming the host: a security downgrade
			// must not be settable once and then invisible.
			slog.Warn("ssh host key verification disabled by insecure_ignore_host_key",
				"host", hostname)
			return nil
		}

		if cert, ok := key.(*ssh.Certificate); ok {
			// Certificates are checked before any pinned-key comparison: a
			// *ssh.Certificate also satisfies ssh.PublicKey, and comparing it
			// byte-wise against a pinned raw key would always fail.
			return p.checkCert(hostname, remote, cert)
		}

		if p.Pinned != "" {
			pinned, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p.Pinned))
			if err != nil {
				return fmt.Errorf("parse pinned host key for %s: %w", hostname, err)
			}
			if string(pinned.Marshal()) == string(key.Marshal()) {
				return nil
			}
			return fmt.Errorf("host key for %s changed: pinned %s, offered %s",
				hostname, ssh.FingerprintSHA256(pinned), ssh.FingerprintSHA256(key))
		}

		return fmt.Errorf("%s: %w (offered %s)", hostname, ErrHostKeyUnknown, ssh.FingerprintSHA256(key))
	}
}

// checkCert validates a host certificate against the configured CAs.
//
// golang.org/x/crypto/ssh/knownhosts exposes no reader-based constructor, only
// New(files ...string), so the CA lines are written to one temporary
// known_hosts-format file and handed to New — reusing its OpenSSH host-pattern
// grammar (*, ?, comma lists) rather than hand-rolling the match, which would
// risk silently trusting a CA for hosts it was never configured to cover.
func (p HostKeyPolicy) checkCert(hostname string, remote net.Addr, cert *ssh.Certificate) error {
	if len(p.CAs) == 0 {
		return fmt.Errorf("%s: %w (offered host certificate, no certificate_authorities configured)",
			hostname, ErrHostKeyUnknown)
	}

	cb, err := p.caCallback()
	if err != nil {
		return fmt.Errorf("%s: load configured certificate authorities: %w", hostname, err)
	}

	if err := cb(hostname, remote, cert); err != nil {
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) && len(keyErr.Want) == 0 {
			// knownhosts reports "no entry at all" the same way it reports a
			// pattern mismatch; either way no configured CA covers this host.
			return fmt.Errorf("%s: %w (offered host certificate, no matching CA)", hostname, ErrHostKeyUnknown)
		}
		return fmt.Errorf("%s: host certificate rejected: %w", hostname, err)
	}
	return nil
}

// caCallback builds the knownhosts.HostKeyCallback for the configured CA
// lines. The temp file exists only for the duration of the New() call: New
// reads and parses it eagerly, so the callback it returns has no further
// dependency on the file once construction completes.
func (p HostKeyPolicy) caCallback() (ssh.HostKeyCallback, error) {
	f, err := os.CreateTemp("", "dotvault-sshfwd-ca-*")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	defer os.Remove(path)

	for _, line := range p.CAs {
		if _, err := f.WriteString(line + "\n"); err != nil {
			f.Close()
			return nil, err
		}
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	return knownhosts.New(path)
}
