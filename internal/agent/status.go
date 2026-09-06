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
	Name  string `json:"name"`
	Type  string `json:"type"`
	Error string `json:"error,omitempty"`

	// Upstreams names the agent endpoints the relay is currently proxying to,
	// the only visible answer to "what did auto-detection actually find?".
	// Answering it needs three states, not two: absent for a source that
	// reports no upstreams at all, `[]` for a relay that found nothing to
	// shadow, and a list otherwise. That middle state is the whole point — no
	// other agent running is a legitimate outcome, not an error — and it is
	// why this is a pointer. A plain slice cannot carry it: encoding/json's
	// omitempty drops a non-nil empty slice exactly as it drops a nil one, so
	// the first two states would serialise identically.
	//
	// Absence tracks whether the source implements upstreamReporter, not its
	// Type: a relay that failed to construct is an errSource typed "agent"
	// with no Endpoints (factory.go), so `type == "agent"` does not imply the
	// field is present. Key off the field, not the type.
	Upstreams *[]string `json:"upstreams,omitempty"`

	Identities []IdentityStatus `json:"identities"`
}

// upstreamReporter is implemented by a source that proxies to other agents, so
// Status can name them. Kept as a local optional interface rather than a
// method on Source: only the upstream source has anything to say here, and a
// kv/vault-ca source should not have to carry a stub.
type upstreamReporter interface {
	Endpoints() []string
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
		// After Identities, so an auto-detecting source reports the endpoints
		// from the scan just performed rather than the previous one.
		if ur, ok := src.(upstreamReporter); ok {
			// Copy, which also normalises nil to empty: this source reports
			// upstreams, so "nothing found" must serialise as [] rather than
			// null. Copying matters because Status retains the pointer —
			// upstreamSource hands back a defensive copy today, but the
			// upstreamReporter contract does not require one, and aliasing a
			// source's live slice would share it past that source's lock.
			eps := append([]string{}, ur.Endpoints()...)
			ss.Upstreams = &eps
		}
		// Non-nil for the same reason as Upstreams: a source with no
		// resolvable identities owes `[]`, not null.
		ss.Identities = make([]IdentityStatus, 0, len(ids))
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
