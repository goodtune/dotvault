package clientcert

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/vault"
)

// credentialFile is the name of the envelope auth writes under the mtls
// storage directory. It is repeated here (rather than exported from auth)
// only so the held source can stat it cheaply on every Current.
const credentialFile = "credential.json"

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
	// as it was when statKey was taken.
	cur     *Pair
	loaded  bool
	statKey envelopeStat
	lastErr error

	// last mirrors cur and lastErr under its own lock, so Last (and with it
	// /api/v1/status) never waits behind a Current blocked on a hung cache
	// directory.
	last struct {
		sync.Mutex
		pair *Pair
		err  error
	}
}

// envelopeStat is what identifies one version of the envelope file. The full
// nanosecond mtime and the size are both compared, so a rewrite within the
// same second is still seen unless it also keeps the size and lands on the
// identical mtime.
type envelopeStat struct {
	modTime time.Time
	size    int64
}

// NewHeld returns a Source serving the held mtls certificate stored under
// storageDir. username must be the current OS user and must not be empty: an
// empty username disables the envelope's identity check, which is what stops
// one account serving another's certificate. reissueBefore is
// vault.mtls.reissue_before and sets RefreshAt; zero (or a value that would
// put RefreshAt before NotBefore) falls back to the certificate's half-life.
func NewHeld(storageDir, method, username string, reissueBefore time.Duration) Source {
	return &held{dir: storageDir, method: method, username: username, reissueBefore: reissueBefore}
}

// Current re-exports the credential only when the envelope file changed, or
// when the cached certificate has expired. Errors from auth.ExportHeldCertificate
// pass through unchanged, so callers can test them with errors.Is against
// auth.ErrNoCertCredential and auth.ErrHeldNotExportable.
func (h *held) Current(ctx context.Context) (*Pair, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Stat before exporting: a rotation after this point changes the file
	// away from the key we record, so the next call reloads.
	var key envelopeStat
	if fi, err := os.Stat(filepath.Join(h.dir, credentialFile)); err == nil {
		key = envelopeStat{modTime: fi.ModTime(), size: fi.Size()}
		if h.loaded && key == h.statKey && time.Now().Before(h.cur.NotAfter) {
			return h.cur, nil
		}
	}

	hc, err := auth.ExportHeldCertificate(h.dir, h.method, h.username)
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
	h.cur, h.statKey, h.loaded, h.lastErr = p, key, true, nil
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
func (h *held) Last() (*Pair, error) {
	h.last.Lock()
	defer h.last.Unlock()
	return h.last.pair, h.last.err
}

func (h *held) pairFrom(hc *auth.HeldCertificate) (*Pair, error) {
	der := leafDER(hc.CertPEM)
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
	return &Pair{
		CertPEM:    hc.CertPEM,
		KeyPEM:     hc.KeyPEM,
		NotBefore:  leaf.NotBefore,
		NotAfter:   leaf.NotAfter,
		RefreshAt:  refresh,
		Serial:     vault.FormatSerial(leaf.SerialNumber),
		CommonName: leaf.Subject.CommonName,
		Source:     SourceHeld,
	}, nil
}
