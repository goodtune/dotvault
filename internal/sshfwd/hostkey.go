package sshfwd

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ErrHostKeyUnknown reports a host whose key is neither pinned in ssh.yaml nor
// signed by a configured certificate authority. It is distinct from a
// *mismatch*: unknown is the normal state before `dotvault ssh add` pins a
// key, and the CLI turns it into a fingerprint prompt rather than an error.
var ErrHostKeyUnknown = errors.New("host key is not pinned and no configured CA signed it")

// ErrHostKeyMismatch reports a host that presented a key or certificate
// different from what was pinned or that a configured CA rejected — the
// possible-MITM case, as opposed to ErrHostKeyUnknown's normal
// not-yet-pinned state. Kept distinct so Classify maps it to ClassHostKey
// rather than the generic handshake class: a changed host key must surface as
// a host-key problem in status, not blend into ordinary transport churn.
var ErrHostKeyMismatch = errors.New("host key or certificate rejected")

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

	// caMu/caCB cache the knownhosts callback built from CAs, so parsing
	// doesn't happen on every certificate-bearing handshake — see
	// cachedCACallback. Only a *successful* build is cached: caCB stays nil
	// after a failure, so the next verification attempt retries rather than
	// being permanently poisoned by one bad attempt. That distinction matters
	// because buildCACallback can fail two very different ways — a
	// knownhosts parse error is deterministic (CAs is static config, so
	// caching that failure forever would be correct and desirable), but a
	// temp-file I/O error can be transient (a momentarily full or read-only
	// TMPDIR, fd exhaustion) — and a cache that can't tell them apart would
	// wedge a policy that hit a passing filesystem hiccup on its first
	// verification, on a daemon whose entire purpose is resilient
	// reconnection.
	caMu sync.Mutex
	caCB ssh.HostKeyCallback
}

// Callback returns the ssh.HostKeyCallback implementing the policy. When
// observed is non-nil the presented key is stored there before any accept or
// reject decision, so a caller that rejects can still report the fingerprint
// it saw — which is exactly what `ssh add` needs to prompt.
//
// A nil error under Insecure means "not verified", not "verified" — the key
// was never checked against anything. A caller that persists observed as a
// trusted pin must refuse to do so when p.Insecure is set; otherwise it pins
// whatever key answered the TCP connection, and that pin survives Insecure
// being turned back off later.
//
// The returned callback is not safe to share across concurrent dials when
// observed is non-nil: the SSH client invokes it on its own goroutine, and
// concurrent dials sharing one *observed would race. Call Callback fresh
// (with its own observed, or nil) for each connection attempt; the
// HostKeyPolicy value itself may be reused across dials — its CA callback
// cache (see the caMu/caCB fields) is shared and survives across calls to
// Callback, so a successfully-parsed CA set is only ever parsed once.
func (p *HostKeyPolicy) Callback(observed *ssh.PublicKey) ssh.HostKeyCallback {
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
			return fmt.Errorf("host key for %s changed: pinned %s, offered %s: %w",
				hostname, ssh.FingerprintSHA256(pinned), ssh.FingerprintSHA256(key), ErrHostKeyMismatch)
		}

		return fmt.Errorf("%s: %w (offered %s)", hostname, ErrHostKeyUnknown, ssh.FingerprintSHA256(key))
	}
}

// checkCert validates a host certificate against the configured CAs.
func (p *HostKeyPolicy) checkCert(hostname string, remote net.Addr, cert *ssh.Certificate) error {
	if len(p.CAs) == 0 {
		return fmt.Errorf("%s: %w (offered host certificate, no certificate_authorities configured)",
			hostname, ErrHostKeyUnknown)
	}

	cb, err := p.cachedCACallback()
	if err != nil {
		return fmt.Errorf("%s: load configured certificate authorities: %w", hostname, err)
	}

	// cb is knownhosts.New's CertChecker.CheckHostKey. It enforces CertType
	// == HostCert, ValidAfter/ValidBefore against time.Now, ValidPrincipals
	// membership, and the CA signature/revocation status — none of that is
	// duplicated here, and none of it is visible in this file. A future
	// change away from knownhosts.New (e.g. hand-rolling the host-pattern
	// match) would silently drop all four checks.
	//
	// On this path ErrHostKeyUnknown covers exactly one situation: no CAs
	// configured at all (the len(p.CAs)==0 branch above). Everything cb can
	// reject — a host not covered by any configured CA's pattern, a bad
	// signature, an expired certificate, a wrong principal, a certificate
	// presented with the wrong CertType — is a hard rejection below, never
	// folded into ErrHostKeyUnknown. That is deliberate: those are operator
	// configuration errors or invalid certificates, not the "haven't pinned
	// this host yet" case `ssh add`'s fingerprint prompt exists for. Widening
	// ErrHostKeyUnknown to also cover "no matching CA pattern" would drag
	// bad-signature and expired certificates in with it, since knownhosts
	// reports both as the same "no authorities for hostname" error.
	if err := cb(hostname, remote, cert); err != nil {
		return fmt.Errorf("%s: host certificate rejected: %w: %w", hostname, ErrHostKeyMismatch, err)
	}
	return nil
}

// cachedCACallback lazily builds and caches the knownhosts callback for
// p.CAs. A successful build is cached so parsing the CA lines happens at
// most once per HostKeyPolicy value, not on every certificate-bearing
// handshake: without this, a background daemon reconnecting on a poll loop
// would create, write, parse, and unlink a temp file on every single
// attempt, making host-key verification depend on a writable TMPDIR and a
// free fd at handshake time.
//
// A failed build is deliberately NOT cached, so the next call retries
// buildCACallback from scratch. Caching failure would be correct for a
// deterministic error (a malformed CA line in static config always fails the
// same way), but buildCACallback's temp-file I/O can also fail transiently —
// and there's no way to tell the two apart here — so retrying is the safe
// default: a config error keeps failing (at the cost of re-parsing on every
// attempt, bounded by the caller's reconnect backoff, same as before this
// cache existed), while a passing filesystem hiccup heals on the very next
// verification instead of wedging this policy until a new one is
// constructed.
func (p *HostKeyPolicy) cachedCACallback() (ssh.HostKeyCallback, error) {
	p.caMu.Lock()
	defer p.caMu.Unlock()
	if p.caCB != nil {
		return p.caCB, nil
	}
	cb, err := p.buildCACallback()
	if err != nil {
		return nil, err
	}
	p.caCB = cb
	return cb, nil
}

// createTempFile is os.CreateTemp behind a variable so tests can inject a
// transient failure and verify cachedCACallback retries after one, rather
// than wedging (see hostkey_test.go).
var createTempFile = os.CreateTemp

// buildCACallback parses p.CAs into an ssh.HostKeyCallback.
//
// golang.org/x/crypto/ssh/knownhosts exposes no reader-based constructor,
// only New(files ...string), so the CA lines are written to one temporary
// known_hosts-format file and handed to New — reusing its OpenSSH
// host-pattern grammar (*, ?, comma lists) rather than hand-rolling the
// match, which would risk silently trusting a CA for hosts it was never
// configured to cover.
//
// knownhosts.New also wires the returned CertChecker's HostKeyFallback to the
// same parsed line database, which means a *plain* (non-@cert-authority) line
// in p.CAs would be usable as a raw-key trust anchor if that fallback were
// ever consulted. It never is here: this callback is only invoked from
// checkCert, which is only reached when the presented key is a
// *ssh.Certificate (see the type assertion in Callback), so HostKeyFallback
// is dead code in this wiring and a stray non-CA line in p.CAs grants nothing.
func (p *HostKeyPolicy) buildCACallback() (ssh.HostKeyCallback, error) {
	f, err := createTempFile("", "dotvault-sshfwd-ca-*")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	defer os.Remove(path)

	for i, line := range p.CAs {
		// ssh.MarshalAuthorizedKey (the expected source of the key portion of
		// a CA line) already appends a trailing newline, so only an
		// *embedded* newline is checked here. Left unchecked, one would turn
		// a single configured entry into two known_hosts lines, smuggling in
		// a second, possibly broader-pattern CA. CAs comes from the
		// admin-owned system config, not a user-writable surface, but the
		// check costs nothing.
		trimmed := strings.TrimRight(line, "\r\n")
		if strings.ContainsAny(trimmed, "\r\n") {
			f.Close()
			return nil, fmt.Errorf("certificate_authorities[%d] contains an embedded newline", i)
		}
		if _, err := f.WriteString(trimmed + "\n"); err != nil {
			f.Close()
			return nil, err
		}
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	return knownhosts.New(path)
}
