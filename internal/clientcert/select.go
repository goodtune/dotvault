package clientcert

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/config"
)

// lastReporter is implemented by every Source this package returns, for the
// status block. Last returns the most recent pair served and the most recent
// error without any I/O and without signing.
type lastReporter interface {
	Last() (*Pair, error)
}

// Params is everything source selection needs, flattened out of the config so
// the client/ facade, which has its own config projection, can build one and
// share the single selection function below.
type Params struct {
	Enabled       bool
	Held          bool             // config.ClientCertHeld()
	Method        string           // vault.auth_method, for NewHeld
	StorageDir    string           // vault.mtls storage dir
	ReissueBefore time.Duration    // vault.mtls.reissue_before
	Ephemeral     EphemeralOptions // PKIRole may be "" (then no fallback); OSUser is also the held username
}

// ParamsFromConfig projects cfg onto Params. osUser is the OS account the
// daemon runs as (paths.Username()) and mtlsStorageDir the resolved envelope
// directory; both are resolved by the caller because they depend on the
// platform, not on the config alone.
func ParamsFromConfig(cfg *config.Config, osUser, mtlsStorageDir string) Params {
	ttl := cfg.ClientCert.TTL
	if ttl <= 0 {
		ttl = config.DefaultClientCertTTL
	}
	return Params{
		Enabled:       cfg.ClientCert.Enabled,
		Held:          cfg.ClientCertHeld(),
		Method:        cfg.Vault.AuthMethod,
		StorageDir:    mtlsStorageDir,
		ReissueBefore: cfg.Vault.MTLS.ReissueBeforeDur,
		Ephemeral: EphemeralOptions{
			PKIMount:   cfg.ClientCertPKIMount(),
			PKIRole:    cfg.ClientCertPKIRole(),
			CommonName: cfg.ClientCertCommonName(),
			TTL:        ttl,
			KeyType:    cfg.ClientCert.KeyType,
			KeyBits:    cfg.ClientCert.KeyBits,
			OSUser:     osUser,
		},
	}
}

// NewFromParams is the one place a Source is chosen. It returns nil, nil when
// the feature is disabled.
//
// Held (plain mtls) serves the credential this host already holds. When that
// fails with auth.ErrNoCertCredential — nothing enrolled yet, expired, issued
// to someone else — and a PKI role is resolvable, it falls back to the
// ephemeral source; without a role the held error is what the caller sees.
// Every other configuration uses the ephemeral source alone. s may be nil
// only for a held configuration with no role.
func NewFromParams(p Params, s Signer) (Source, error) {
	if !p.Enabled {
		return nil, nil
	}
	if !p.Held {
		return NewEphemeral(s, p.Ephemeral)
	}
	if p.Ephemeral.OSUser == "" {
		return nil, errors.New("clientcert: the held certificate needs the current OS username to check whose it is")
	}
	h := NewHeld(p.StorageDir, p.Method, p.Ephemeral.OSUser, p.ReissueBefore)
	if p.Ephemeral.PKIRole == "" {
		return h, nil
	}
	e, err := NewEphemeral(s, p.Ephemeral)
	if err != nil {
		return nil, err
	}
	return &fallback{held: h, eph: e}, nil
}

// New is NewFromParams over a loaded config.
func New(cfg *config.Config, s Signer, osUser, mtlsStorageDir string) (Source, error) {
	return NewFromParams(ParamsFromConfig(cfg, osUser, mtlsStorageDir), s)
}

// fallback tries the held source and, only when the host has no usable held
// credential, the ephemeral one.
type fallback struct {
	held, eph Source

	mu   sync.Mutex
	used Source // the source whose answer Current last returned
}

func (f *fallback) Current(ctx context.Context) (*Pair, error) {
	p, err := f.held.Current(ctx)
	src := f.held
	if err != nil && errors.Is(err, auth.ErrNoCertCredential) {
		p, err = f.eph.Current(ctx)
		src = f.eph
	}
	f.mu.Lock()
	f.used = src
	f.mu.Unlock()
	return p, err
}

// Last reports whichever source answered most recently, or the held source
// before any call.
func (f *fallback) Last() (*Pair, error) {
	f.mu.Lock()
	src := f.used
	f.mu.Unlock()
	if src == nil {
		src = f.held
	}
	return src.(lastReporter).Last()
}

var (
	_ lastReporter = (*held)(nil)
	_ lastReporter = (*ephemeral)(nil)
	_ lastReporter = (*fallback)(nil)
)
