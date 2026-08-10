// SSH managed-forward CRUD. Unlike the peer-action endpoints in browse.go /
// notify.go / clipboard.go, these are CSRF-protected in the ordinary way. That
// exemption exists because a bare curl over a forwarded socket cannot run the
// issue-then-spend handshake; both consumers here — the SPA and `dotvault ssh`
// — can, so there is no reason to weaken the control.
//
// Every mutation goes through sshfwd.Registry rather than touching ssh.yaml,
// so the CLI and the browser share one validation path, one trust gesture and
// one writer by construction.
package web

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/goodtune/dotvault/internal/sshfwd"
)

// sshBodyLimit caps the request body for the SSH CRUD endpoints. These
// payloads are a handful of short fields (a hostname, a socket path, a
// fingerprint); 64 KiB is generous and matches the cap the peer-action
// endpoints use for their own, comparably small bodies (browseBodyLimit in
// browse.go). Without it, json.Decode buffers string tokens as it scans, so
// an unbounded body — a single huge "host" value, say — can force a large
// allocation before the decoder gets anywhere near rejecting it.
const sshBodyLimit = 1 << 16 // 64 KiB

// sshRemoteView is the wire shape for a Remote. sshfwd.Remote carries only
// yaml tags (it round-trips ssh.yaml, not JSON), so this package owns its own
// JSON projection rather than reaching into that struct's tags — the same
// pattern api.go's ruleResponse uses for sync rules.
type sshRemoteView struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	RemoteSocket string `json:"remote_socket"`
	HostKey      string `json:"host_key,omitempty"`
	Enabled      bool   `json:"enabled"`
}

func toSSHRemoteView(r sshfwd.Remote) sshRemoteView {
	return sshRemoteView{
		Host:         r.Host,
		Port:         r.PortOrDefault(),
		RemoteSocket: r.RemoteSocket,
		HostKey:      r.HostKey,
		Enabled:      r.EnabledOrDefault(),
	}
}

// sshRemoteRequest is the body of POST /api/v1/ssh/remotes. Force and
// AcceptFingerprint carry sshfwd.AddOptions; the rest builds the candidate
// sshfwd.Remote passed to Registry.Add.
type sshRemoteRequest struct {
	Host         string `json:"host"`
	Port         int    `json:"port,omitempty"`
	RemoteSocket string `json:"remote_socket,omitempty"`
	HostKey      string `json:"host_key,omitempty"`
	Enabled      *bool  `json:"enabled,omitempty"`

	Force             bool   `json:"force,omitempty"`
	AcceptFingerprint string `json:"accept_fingerprint,omitempty"`
}

// sshPatchRequest is the body of PATCH /api/v1/ssh/remotes/{host}. It maps
// field for field onto sshfwd.Patch — a nil field leaves the current value
// untouched, matching Patch's own contract.
type sshPatchRequest struct {
	Enabled      *bool   `json:"enabled,omitempty"`
	RemoteSocket *string `json:"remote_socket,omitempty"`
	Port         *int    `json:"port,omitempty"`
}

// handleSSHList returns every configured remote.
func (s *Server) handleSSHList(w http.ResponseWriter, r *http.Request) {
	reg := s.sshRegistrySnapshot()
	if reg == nil {
		writeError(w, "managed SSH forwards are not configured", http.StatusServiceUnavailable)
		return
	}

	remotes, err := reg.List()
	if err != nil {
		// A List failure means ssh.yaml itself is unreadable or corrupt —
		// not a caller error, so 500 rather than the 400 the other three
		// handlers use for a rejected request.
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	views := make([]sshRemoteView, len(remotes))
	for i, rem := range remotes {
		views[i] = toSSHRemoteView(rem)
	}
	writeJSON(w, map[string]any{"remotes": views})
}

// handleSSHAdd registers a new remote, or updates an existing one (Add is
// idempotent on host). An unpinned host's key surfaces as a 409 carrying the
// fingerprint a caller must echo back via accept_fingerprint to commit — the
// same confirmation gesture the CLI uses, so a browser session cannot
// degrade the trust decision into blind trust-on-first-use.
func (s *Server) handleSSHAdd(w http.ResponseWriter, r *http.Request) {
	reg := s.sshRegistrySnapshot()
	if reg == nil {
		writeError(w, "managed SSH forwards are not configured", http.StatusServiceUnavailable)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, sshBodyLimit)
	var req sshRemoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Host == "" {
		writeError(w, "host is required", http.StatusBadRequest)
		return
	}

	remote := sshfwd.Remote{
		Host:         req.Host,
		Port:         req.Port,
		RemoteSocket: req.RemoteSocket,
		HostKey:      req.HostKey,
		Enabled:      req.Enabled,
	}
	opts := sshfwd.AddOptions{
		Force:             req.Force,
		AcceptFingerprint: req.AcceptFingerprint,
	}

	got, err := reg.Add(r.Context(), remote, opts)
	if err != nil {
		if errors.Is(err, sshfwd.ErrConfirmHostKey) {
			var confirm *sshfwd.HostKeyConfirmation
			if !errors.As(err, &confirm) {
				// registry.go only ever raises ErrConfirmHostKey by
				// returning a *HostKeyConfirmation literal, so this can't
				// happen today — but trusting that invariant silently
				// would mean a future change to how it's wrapped turns
				// into a nil-pointer panic here instead of a clean error.
				writeError(w, "internal error handling host key confirmation", http.StatusInternalServerError)
				return
			}
			writeJSONStatus(w, http.StatusConflict, map[string]string{
				"host":        confirm.Host,
				"fingerprint": confirm.Fingerprint,
			})
			return
		}
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	writeJSONStatus(w, http.StatusCreated, toSSHRemoteView(*got))
}

// handleSSHPatch applies a partial update to an existing remote.
func (s *Server) handleSSHPatch(w http.ResponseWriter, r *http.Request) {
	reg := s.sshRegistrySnapshot()
	if reg == nil {
		writeError(w, "managed SSH forwards are not configured", http.StatusServiceUnavailable)
		return
	}

	// {host} is a mux wildcard, not a value ValidateRemote has already
	// checked — Go's mux matches it against the escaped path segment but
	// hands PathValue the unescaped result, so "foo%2Fbar" and "foo%00bar"
	// arrive here as "foo/bar" and "foo\x00bar" rather than being rejected
	// as an invalid route. Reject the same shapes ValidateRemote itself
	// would reject for Host before this ever reaches Registry.
	host := r.PathValue("host")
	if err := sshfwd.ValidateHost(host); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, sshBodyLimit)
	var req sshPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	got, err := reg.Patch(r.Context(), host, sshfwd.Patch{
		Enabled:      req.Enabled,
		RemoteSocket: req.RemoteSocket,
		Port:         req.Port,
	})
	if err != nil {
		if errors.Is(err, sshfwd.ErrHostNotFound) {
			writeError(w, err.Error(), http.StatusNotFound)
			return
		}
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	writeJSON(w, toSSHRemoteView(*got))
}

// handleSSHDelete removes a remote. Deleting an unknown host is a 404, not
// the idempotent success Registry.Remove itself models — the caller asked to
// remove a specific host and there is nothing useful to report back beyond
// "no such entry" (unlike Registry.Remove's internal callers, which want
// idempotency to make retries safe).
func (s *Server) handleSSHDelete(w http.ResponseWriter, r *http.Request) {
	reg := s.sshRegistrySnapshot()
	if reg == nil {
		writeError(w, "managed SSH forwards are not configured", http.StatusServiceUnavailable)
		return
	}

	// See handleSSHPatch's comment: {host} arrives unescaped from the mux
	// wildcard and must be validated the same way ValidateRemote validates
	// a Host before it reaches Registry.
	host := r.PathValue("host")
	if err := sshfwd.ValidateHost(host); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	found, err := reg.Remove(r.Context(), host)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !found {
		writeError(w, "no remote configured for that host", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
