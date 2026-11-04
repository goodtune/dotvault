// Package clientcert is the vocabulary for serving a mutual-TLS client
// certificate to tools: the FUSE mount, Docker volumes and the client library
// all read one through the Source interface and receive a Pair.
//
// It is a leaf on purpose. It holds the types, the error sentinels and the
// status projection, and imports nothing from dotvault, so a consumer (vaultfs,
// dockervol, web) can depend on it without pulling in internal/auth or
// internal/config. The two implementations and the selection between them live
// in internal/clientcert/source: the held source re-serves the certificate
// this host already logs in to Vault with, under plain mtls; the ephemeral
// source, everywhere else, generates a key in memory, has Vault's PKI engine
// sign it with the daemon's current token, and replaces it before it expires.
// Neither persists anything.
//
// Key material and PEM never appear in errors or log lines. Only the serial,
// NotAfter, common name, mount and role are logged.
package clientcert

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"time"
)

// Source names, as reported in Pair.Source and status output.
const (
	SourceHeld      = "held"
	SourceEphemeral = "ephemeral"
)

// Pair is one client certificate and its private key, plus the facts about it
// consumers need to decide when to read it again. CertPEM, KeyPEM and
// Combined are the three files a consumer writes (client.crt, client.key,
// client.pem), all produced from the same Pair so they can never disagree.
type Pair struct {
	CertPEM    []byte // client.crt: leaf followed by the CA chain
	KeyPEM     []byte // client.key: PKCS#8 PEM
	NotBefore  time.Time
	NotAfter   time.Time
	RefreshAt  time.Time // NotBefore + (NotAfter-NotBefore)/2
	Serial     string
	CommonName string
	Source     string // SourceHeld | SourceEphemeral
}

// Combined returns client.pem: the certificate bytes followed by the key
// bytes, with a newline between them when CertPEM lacks a trailing one so the
// two PEM blocks never share a line. The result is a fresh slice.
func (p *Pair) Combined() []byte {
	out := make([]byte, 0, len(p.CertPEM)+1+len(p.KeyPEM))
	out = append(out, p.CertPEM...)
	if len(p.CertPEM) > 0 && p.CertPEM[len(p.CertPEM)-1] != '\n' {
		out = append(out, '\n')
	}
	return append(out, p.KeyPEM...)
}

// TLSCertificate assembles the pair for a crypto/tls client, which also
// checks that the key matches the leaf.
func (p *Pair) TLSCertificate() (tls.Certificate, error) {
	return tls.X509KeyPair(p.CertPEM, p.KeyPEM)
}

// Fingerprint is the hex SHA-256 of the leaf certificate's DER, for status
// output and tests. Empty when CertPEM holds no certificate.
func (p *Pair) Fingerprint() string {
	der := LeafDER(p.CertPEM)
	if der == nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// LeafDER returns the DER of the first CERTIFICATE block in pemBytes, or nil.
func LeafDER(pemBytes []byte) []byte {
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil
		}
		if block.Type == "CERTIFICATE" {
			return block.Bytes
		}
	}
}

// Source yields the client certificate to serve right now. Implementations
// are safe for concurrent use and may sign or reload on demand, so Current
// can block on Vault for as long as ctx allows. The returned Pair is shared
// with every other caller and must be treated as read-only.
type Source interface {
	Current(ctx context.Context) (*Pair, error)
}

// ErrNoToken is returned when a certificate must be signed but there is no
// Vault token to sign it with, and no still-valid certificate to serve
// instead.
var ErrNoToken = errors.New("clientcert: no Vault token to sign a certificate with")

// ErrSignPaced is returned when no valid certificate is cached, a new one
// would have to be signed, and sign pacing does not allow an attempt yet
// (minSignInterval since the last attempt made with the same token), while
// there is no failure on record to report instead. A token different from the
// last attempt's is never paced this way, so in practice it means a PKI role
// whose max_ttl is shorter than the interval; it still names no cause, since
// pacing alone cannot tell. It is transient: a later call signs. Consumers can
// tell pacing apart from a real failure with errors.Is.
var ErrSignPaced = errors.New("clientcert: next certificate sign is paced; retry shortly")

// ErrNoUsername is returned when the common-name template needs
// {{.token_username}} and the token's metadata records neither a username nor
// a common name. It never falls back to anything silently: a certificate
// subject is an identity, and guessing grants somebody else's.
var ErrNoUsername = errors.New("clientcert: the Vault token carries no username (meta.username or meta.common_name); set client_cert.common_name to {{.os_user}} or configure the auth method to record one")

// ErrSignInProgress is returned, wrapping the caller's ctx.Err(), when the
// caller's context ended while it waited on a sign that is still in flight.
// The sign is not abandoned: it runs detached under its own timeout, and a
// later call is answered with its result. So a caller deadline here is
// transient (the FUSE mount answers EAGAIN), unlike a sign that failed on its
// own, which never wraps this sentinel.
var ErrSignInProgress = errors.New("clientcert: still waiting on a certificate sign in progress")
