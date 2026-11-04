package clientcert

import "time"

// Status states.
const (
	// StateIdle means nothing has asked for the certificate yet and nothing
	// has failed: not an error, just not yet served.
	StateIdle = "idle"
	// StateServing means a certificate was served and the most recent
	// attempt did not fail.
	StateServing = "serving"
	// StateError means the most recent attempt failed. A previously served
	// certificate may still be reported alongside it.
	StateError = "error"
	// StateExpired means the last certificate served has passed its NotAfter
	// and nothing has failed since: nobody has asked for a replacement, so
	// none was made. The next read replaces it.
	StateExpired = "expired"
)

// Status is the public face of a Source for /api/v1/status. It is served
// unauthenticated, so it carries the facts a certificate's own public part
// would show (subject, serial, expiry) and never the PEM, the key or any
// fingerprint of the key.
type Status struct {
	State      string    `json:"state"`
	Source     string    `json:"source,omitempty"`
	CommonName string    `json:"common_name,omitempty"`
	Serial     string    `json:"serial,omitempty"`
	NotAfter   time.Time `json:"not_after,omitzero"`
	LastError  string    `json:"last_error,omitempty"`
}

// StatusOf reports the last pair a Source served and the last error it hit.
// It never signs, never reads the envelope and never contacts Vault, so it is
// safe to call from a status handler at any rate. A nil Source, or one that
// does not report, yields the zero Status.
func StatusOf(s Source) Status {
	return statusAt(s, time.Now())
}

func statusAt(s Source, now time.Time) Status {
	r, ok := s.(lastReporter)
	if !ok {
		return Status{}
	}
	p, err := r.Last()
	st := Status{State: StateIdle}
	if p != nil {
		st.State = StateServing
		st.Source = p.Source
		st.CommonName = p.CommonName
		st.Serial = p.Serial
		st.NotAfter = p.NotAfter
		if !now.Before(p.NotAfter) {
			// Reporting "serving" beside a past not_after would claim a
			// certificate is being presented that no service would accept.
			st.State = StateExpired
		}
	}
	if err != nil {
		st.State = StateError
		st.LastError = err.Error()
	}
	return st
}
