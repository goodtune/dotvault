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

	// Upstreams names the agent endpoints an "agent" source is currently
	// proxying to. It is the only visible answer to "what did auto-detection
	// actually find?" — an empty list on an enabled auto source means nothing
	// was found to shadow, which is a legitimate state (no other agent is
	// running) and so deliberately not an error.
	Upstreams []string `json:"upstreams,omitempty"`

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
			ss.Upstreams = ur.Endpoints()
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
