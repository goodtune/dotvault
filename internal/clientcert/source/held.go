package source

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/clientcert"
	"github.com/goodtune/dotvault/internal/vault"
)

// statCredential and exportHeld are auth's, as variables so a test can stand
// in for the envelope and land a rotation exactly where it wants one.
var (
	statCredential = auth.StatCredential
	exportHeld     = auth.ExportHeldCertificate
)

// held serves the certificate this host already logs in to Vault with, under
// plain mtls. It owns no key and signs nothing: the daemon rotates the
// credential, and held notices by watching the envelope file.
type held struct {
	dir, method, username string
	reissueBefore         time.Duration

	// mu serialises Current, which does file I/O under it.
	mu sync.Mutex
	// cur is the most recent pair exported, kept even after a failure so
	// Last can report it. loaded says cur still corresponds to the envelope
	// at version, the stat auth took before reading it.
	cur     *clientcert.Pair
	loaded  bool
	version auth.CredentialVersion
	lastErr error

	// last mirrors cur and lastErr under its own lock, so Last (and with it
	// /api/v1/status) never waits behind a Current blocked on a hung cache
	// directory.
	last struct {
		sync.Mutex
		pair *clientcert.Pair
		err  error
	}
}

// NewHeld returns a clientcert.Source serving the held mtls certificate stored under
// storageDir. username must be the current OS user and must not be empty: an
// empty username disables the envelope's identity check, which is what stops
// one account serving another's certificate. reissueBefore is
// vault.mtls.reissue_before and sets RefreshAt; zero (or a value that would
// put RefreshAt before NotBefore) falls back to the certificate's half-life.
func NewHeld(storageDir, method, username string, reissueBefore time.Duration) clientcert.Source {
	return &held{dir: storageDir, method: method, username: username, reissueBefore: reissueBefore}
}

// Current re-exports the credential only when the envelope file changed, or
// when the cached certificate has expired. Errors from auth.ExportHeldCertificate
// pass through unchanged, so callers can test them with errors.Is against
// auth.ErrNoCertCredential and auth.ErrHeldNotExportable.
func (h *held) Current(ctx context.Context) (*clientcert.Pair, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// The cheap check only decides whether to export. The version recorded
	// beside the content is the one the export itself reports, which auth
	// takes before it reads the file: a rotation landing between the two then
	// pairs the older version with the newer content and costs one more
	// reload, never the reverse, which would hide the rotation.
	if v, err := statCredential(h.dir); err == nil && h.loaded && v == h.version && time.Now().Before(h.cur.NotAfter) {
		return h.cur, nil
	}

	hc, err := exportHeld(h.dir, h.method, h.username)
	if err != nil {
		h.loaded = false
		h.lastErr = err
		h.publish()
		return nil, err
	}
	p, err := h.pairFrom(hc)
	if err != nil {
		h.loaded = false
		h.lastErr = err
		h.publish()
		return nil, err
	}
	h.cur, h.version, h.loaded, h.lastErr = p, hc.Version, true, nil
	h.publish()
	return p, nil
}

// publish copies cur and lastErr to what Last reads. Called with h.mu held.
func (h *held) publish() {
	h.last.Lock()
	h.last.pair, h.last.err = h.cur, h.lastErr
	h.last.Unlock()
}

// Last returns the most recent pair served and the most recent error, without
// touching the filesystem.
func (h *held) Last() (*clientcert.Pair, error) {
	h.last.Lock()
	defer h.last.Unlock()
	return h.last.pair, h.last.err
}

func (h *held) pairFrom(hc *auth.HeldCertificate) (*clientcert.Pair, error) {
	der := clientcert.LeafDER(hc.CertPEM)
	if der == nil {
		return nil, fmt.Errorf("clientcert: held credential: %w: no certificate in the envelope", auth.ErrNoCertCredential)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("clientcert: held credential: %w: parse certificate: %w", auth.ErrNoCertCredential, err)
	}
	refresh := leaf.NotAfter.Add(-h.reissueBefore)
	if h.reissueBefore <= 0 || !refresh.After(leaf.NotBefore) {
		refresh = leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	}
	return &clientcert.Pair{
		CertPEM:    hc.CertPEM,
		KeyPEM:     hc.KeyPEM,
		NotBefore:  leaf.NotBefore,
		NotAfter:   leaf.NotAfter,
		RefreshAt:  refresh,
		Serial:     vault.FormatSerial(leaf.SerialNumber),
		CommonName: leaf.Subject.CommonName,
		Source:     clientcert.SourceHeld,
	}, nil
}
