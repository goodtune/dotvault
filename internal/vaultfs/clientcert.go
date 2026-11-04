package vaultfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"syscall"
	"time"

	"github.com/goodtune/dotvault/internal/clientcert"
)

// The client certificate files served at the mount root when a
// clientcert.Source is set. None of them can collide with a secret, since
// every secret's filename ends in FileExtension; only a KV folder can carry
// one of these names, and the certificate wins (see Tree.Readdir).
const (
	// ClientCertFile is the certificate: leaf followed by the CA chain.
	ClientCertFile = "client.crt"
	// ClientKeyFile is the private key, PKCS#8 PEM.
	ClientKeyFile = "client.key"
	// ClientPEMFile is the certificate followed by the key, in one file, so
	// a tool that reads it in one go can never pair a certificate with the
	// key of a different rotation.
	ClientPEMFile = "client.pem"
)

// IsClientCertPath reports whether p names one of the client certificate
// files. Only the mount root carries them, so "sub/client.crt" is an ordinary
// (missing) path. p is compared as given: the canonical spelling of a root
// path is the bare name, and any other spelling is rejected by cleanPath
// before it could matter.
func IsClientCertPath(p string) bool {
	switch p {
	case ClientCertFile, ClientKeyFile, ClientPEMFile:
		return true
	}
	return false
}

// errNoPair reports a source that returned neither a pair nor an error.
var errNoPair = errors.New("vaultfs: client certificate source returned no certificate")

// SetClientCert makes the tree serve the client certificate files from s, or
// stop serving them when s is nil. It is called once by NewService, before
// the tree is mounted; it is not synchronised against concurrent readers.
func (t *Tree) SetClientCert(s clientcert.Source) {
	t.clientCert = s
	// A root listing cached before the change would show the wrong set of
	// files for a whole cache window.
	t.cache.invalidateAll()
}

// servesClientCert reports whether p is a certificate file this tree serves:
// a source is set and p is one of the three names at the root.
func (t *Tree) servesClientCert(p string) bool {
	return t.clientCert != nil && IsClientCertPath(p)
}

// clientCertDocument renders one certificate file from the source's current
// pair.
//
// It never reads or writes t.cache. The certificate rotates on its own
// schedule (every few minutes for an ephemeral one), the source already
// caches the pair until it is due for replacement, and a second cache here
// would only serve a superseded certificate for up to cache_ttl longer.
//
// The bytes are copied rather than sliced: the pair is shared with every
// other caller of the source and must not be reachable through a document a
// consumer might modify.
func (t *Tree) clientCertDocument(ctx context.Context, path string) (*Document, error) {
	pair, err := t.clientCert.Current(ctx)
	if err != nil {
		// The source's errors are content-free by contract; the wrap adds
		// only the path.
		return nil, fmt.Errorf("client certificate for %q: %w", displayPath(path), err)
	}
	if pair == nil {
		return nil, errNoPair
	}
	var b []byte
	switch path {
	case ClientCertFile:
		b = bytes.Clone(pair.CertPEM)
	case ClientKeyFile:
		b = bytes.Clone(pair.KeyPEM)
	default:
		b = pair.Combined()
	}
	return &Document{Bytes: b, ModTime: pair.NotBefore, Version: 0}, nil
}

// certFailureLogInterval is how often the same client certificate failure is
// logged again. Every stat, lookup and open of a certificate file reaches the
// source, so a persistent failure (a policy without pki/sign) would otherwise
// log once per read; the line still has to carry the cause, since an errno
// cannot.
const certFailureLogInterval = 10 * time.Minute

// maxCertFailureKeys bounds certFailureLog's memory. The error text includes
// the file name, so one cause occupies up to three keys.
const maxCertFailureKeys = 32

// certFailureLog rate-limits the WARN for a client certificate failure: each
// distinct error is logged at once, then at most every certFailureLogInterval.
type certFailureLog struct {
	mu   sync.Mutex
	last map[string]time.Time
	now  func() time.Time
}

var certFailures = &certFailureLog{now: time.Now}

// shouldLog reports whether msg is due to be logged, and records it if so.
func (l *certFailureLog) shouldLog(msg string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if at, ok := l.last[msg]; ok && now.Sub(at) < certFailureLogInterval {
		return false
	}
	if l.last == nil || len(l.last) >= maxCertFailureKeys {
		l.last = make(map[string]time.Time)
	}
	l.last[msg] = now
	return true
}

// logCertFailure logs a client certificate failure that is about to become an
// errno, with the error (which names the PKI role and Vault's answer, and by
// the source's contract never carries key or certificate material). A
// transient answer (certTransient) is logged at DEBUG on every call, since it
// clears on its own and is reported as EAGAIN.
func logCertFailure(op, path string, err error) {
	if certTransient(err) {
		slog.Debug("vaultfs: client certificate not available yet", "op", op, "path", displayPath(path), "error", err)
		return
	}
	if errors.Is(err, context.Canceled) || !certFailures.shouldLog(err.Error()) {
		return
	}
	slog.Warn("vaultfs: client certificate unavailable", "op", op, "path", displayPath(path), "error", err)
}

// certErrno maps a client certificate failure onto an errno. A source that is
// waiting for a token, pacing its next sign or waiting out a token
// replacement is transient and says so with EAGAIN, and so is an operation
// whose own deadline (opTimeout) ran out while a sign was still in flight: the
// sign continues detached, so a retry gets its result (see certTransient). Anything else is EIO, including a sign that itself timed out against
// Vault. An interrupted call stays EINTR, since that is the caller going away
// rather than the source failing. Logging goes
// through logCertFailure, which names the cause (logErrno's per-errno lines
// would log a denial on every read and without the error), and no
// certificate error carries PEM.
func certErrno(op, path string, err error) syscall.Errno {
	logCertFailure(op, path, err)
	switch {
	case certTransient(err):
		return syscall.EAGAIN
	case errors.Is(err, context.Canceled):
		return syscall.EINTR
	}
	return syscall.EIO
}

// certTransient reports whether a client certificate error clears on its own,
// so a reader should be told EAGAIN: no token yet (ErrNoToken), the next sign
// paced (ErrSignPaced), the token being replaced (ErrReauthInProgress), or the
// operation's own deadline running out while a sign was still in flight
// (ErrSignInProgress wrapping DeadlineExceeded). An explicit cancel is the
// caller going away and is not transient, so ErrSignInProgress wrapping
// Canceled stays EINTR. The one definition certErrno, logCertFailure and
// logErrno share.
func certTransient(err error) bool {
	switch {
	case errors.Is(err, clientcert.ErrNoToken), errors.Is(err, clientcert.ErrSignPaced),
		errors.Is(err, clientcert.ErrReauthInProgress):
		return true
	case errors.Is(err, clientcert.ErrSignInProgress):
		return !errors.Is(err, context.Canceled)
	}
	return false
}
