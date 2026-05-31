package agent

import (
	"context"
	"time"

	"golang.org/x/crypto/ssh"
)

// Status is a serialisable snapshot of the agent's currently resolvable
// identities, per source. It is surfaced in the web dashboard (parallel to
// per-rule sync state) and printed by `dotvault status`.
type Status struct {
	Endpoint string         `json:"endpoint"`
	Sources  []SourceStatus `json:"sources"`
}

// SourceStatus reports one configured source's resolution result.
type SourceStatus struct {
	Name       string           `json:"name"`
	Type       string           `json:"type"`
	Error      string           `json:"error,omitempty"`
	Identities []IdentityStatus `json:"identities"`
}

// IdentityStatus describes a single advertised key or certificate.
type IdentityStatus struct {
	Comment     string `json:"comment,omitempty"`
	Fingerprint string `json:"fingerprint"`
	IsCert      bool   `json:"is_cert"`
	// ExpiresAt / TTLSeconds are populated only for certificates with a
	// bounded validity window.
	ExpiresAt  string `json:"expires_at,omitempty"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
}

// Status gathers a fresh snapshot, querying every source. A source that fails
// to resolve (unknown engine, Vault read error, missing CA role) is reported
// with its Error set rather than aborting the whole snapshot — mirroring the
// per-rule isolation of the sync engine.
func (b *Backend) Status(ctx context.Context) Status {
	st := Status{Endpoint: b.endpoint}
	for _, src := range b.sources {
		ss := SourceStatus{Name: src.Name(), Type: src.Type()}
		ids, err := src.Identities(ctx)
		if err != nil {
			ss.Error = err.Error()
		}
		for _, id := range ids {
			ss.Identities = append(ss.Identities, identityStatus(id))
		}
		st.Sources = append(st.Sources, ss)
	}
	return st
}

func identityStatus(id Identity) IdentityStatus {
	is := IdentityStatus{
		Comment:     id.Comment,
		Fingerprint: ssh.FingerprintSHA256(id.PubKey),
	}
	if _, ok := id.PubKey.(*ssh.Certificate); ok {
		is.IsCert = true
	}
	if !id.Expiry.IsZero() {
		is.ExpiresAt = id.Expiry.UTC().Format(time.RFC3339)
		if ttl := time.Until(id.Expiry); ttl > 0 {
			is.TTLSeconds = int64(ttl.Seconds())
		}
	}
	return is
}
