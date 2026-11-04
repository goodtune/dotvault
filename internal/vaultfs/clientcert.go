package vaultfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"

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
