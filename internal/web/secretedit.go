// Secret editing: create, replace and delete for the subtrees named by
// web.editable_paths.
//
// Everything here funnels through editPolicy, which owns the two rules — the
// path must sit strictly inside a configured subtree, and it must not be a
// path dotvault writes for itself. Both the JSON API and the browser's form
// POSTs call the same two service methods below, so a screen cannot offer an
// edit the request behind it would refuse, and a future CLI gets the
// behaviour for free.
//
// The document a caller supplies is parsed by vaultfs.ParseDocument, the same
// parser the FUSE mount's write path uses. That is what makes "what you can
// write through the mount" and "what you can save in the browser" one set
// rather than two that drift.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/kvpath"
	"github.com/goodtune/dotvault/internal/vaultfs"
)

// secretBodyLimit caps a secret-edit request body. A KVv2 secret is small by
// construction, and the FUSE mount already refuses a document over 1 MiB
// (vaultfs maxDocumentSize); matching that here keeps the two write surfaces
// agreeing on what is too big, and bounds the allocation json decoding can be
// made to perform before it rejects anything.
const secretBodyLimit = 1 << 20 // 1 MiB

// secretEditTimeout bounds the Vault work behind one edit. It matches the
// 30s the read paths in ui_secrets.go already use.
const secretEditTimeout = 30 * time.Second

// errSecretExists is returned when a create would replace an existing secret.
// Create and replace are deliberately different operations here even though
// Vault's KVv2 write is an upsert: a create form that silently overwrote a
// secret whose path the user mistyped would destroy a credential without ever
// showing it to them.
var errSecretExists = errors.New("a secret already exists at this path")

// errSecretMissing is returned when a replace or delete names nothing.
var errSecretMissing = errors.New("no secret exists at this path")

// editPolicy builds the current policy: the statically-configured editable
// subtrees, minus whatever dotvault currently writes for itself.
//
// It is rebuilt per request rather than cached because its two inputs have
// different lifetimes. web is a static config section, so the roots are fixed
// for the process; the enrolment set is dynamic — a remote config document
// can add one on a refresh tick — and a policy cached at construction would
// keep offering to edit a path that has since become an enrolment target.
// The inputs are a handful of short strings, so rebuilding costs nothing
// worth the staleness.
func (s *Server) editPolicy() kvpath.EditPolicy {
	enrolments := s.getEnrolments()
	managed := make([]string, 0, len(enrolments))
	for key := range enrolments {
		managed = append(managed, key)
	}
	sort.Strings(managed)
	return kvpath.NewEditPolicy(s.cfg.EditablePaths, managed)
}

// secretEditability reports whether rel may be edited and, when it may not,
// whether the reason is that dotvault manages the path itself.
//
// Both answers come from one Allow call rather than from the UI inferring a
// reason. Inferring it was wrong: "not editable but inside an editable
// subtree" is true of a secret sitting at *exactly* a configured root, which
// is refused because the root is a direct child of the key space and not
// because any enrolment owns it — so the page told the user it was managed by
// an enrolment that did not exist. Only the policy knows which rule refused.
func (s *Server) secretEditability(rel string) (editable, managed bool) {
	_, err := s.editPolicy().Allow(rel)
	switch {
	case err == nil:
		return true, false
	case errors.Is(err, kvpath.ErrManaged):
		return false, true
	default:
		return false, false
	}
}

// writeEditableSecret replaces the secret at rel with data, creating it when
// mustBeNew. It returns the cleaned path so callers can log and redirect
// using the canonical spelling rather than whatever the request carried.
//
// The existence probe before the write is not a transaction — Vault offers a
// compare-and-set on KVv2 and this does not use it, so a concurrent writer
// between the probe and the write is not excluded. That is deliberate: the
// only concurrent writer that matters is this daemon's own enrolment engines,
// and the policy has already refused every path they own. What the probe buys
// is that a mistyped create path is reported rather than silently clobbering
// a neighbour, which is a mistake a person makes far more often than two
// writers race.
func (s *Server) writeEditableSecret(ctx context.Context, rel string, data map[string]any, mustBeNew bool) (string, error) {
	clean, err := s.editPolicy().Allow(rel)
	if err != nil {
		return "", err
	}
	existing, err := s.vault.ReadKVv2(ctx, s.kvMount, s.userKVPrefix()+clean)
	if err != nil {
		// A read failure is not evidence either way, and guessing would mean
		// either refusing a legitimate create or clobbering on a blip.
		slog.Error("secret edit: existence check failed", "path", clean, "error", err)
		return "", fmt.Errorf("could not check whether a secret already exists at %q", clean)
	}
	switch {
	case mustBeNew && existing != nil:
		return "", fmt.Errorf("%q: %w", clean, errSecretExists)
	case !mustBeNew && existing == nil:
		return "", fmt.Errorf("%q: %w", clean, errSecretMissing)
	}
	if err := s.vault.WriteKVv2(ctx, s.kvMount, s.userKVPrefix()+clean, data); err != nil {
		slog.Error("secret edit: write failed", "path", clean, "error", err)
		return "", fmt.Errorf("failed to write secret %q", clean)
	}
	// Field *count*, never names or values: a field name can itself be
	// telling ("aws_root_key"), and this line lands wherever the OTel log
	// bridge fans stderr out to.
	slog.Info("secret written via web UI", "path", clean, "fields", len(data), "created", mustBeNew)
	return clean, nil
}

// deleteEditableSecret removes the secret at rel and every one of its
// versions — DeleteKVv2 is a metadata delete, which is what the FUSE mount's
// `rm` already means, so "delete" means the same thing on both write
// surfaces. It is not recoverable, which is why the browser gesture behind it
// asks the user to type the secret's name.
func (s *Server) deleteEditableSecret(ctx context.Context, rel string) (string, error) {
	clean, err := s.editPolicy().Allow(rel)
	if err != nil {
		return "", err
	}
	existing, err := s.vault.ReadKVv2(ctx, s.kvMount, s.userKVPrefix()+clean)
	if err != nil {
		slog.Error("secret edit: existence check failed", "path", clean, "error", err)
		return "", fmt.Errorf("could not check whether a secret exists at %q", clean)
	}
	if existing == nil {
		return "", fmt.Errorf("%q: %w", clean, errSecretMissing)
	}
	if err := s.vault.DeleteKVv2(ctx, s.kvMount, s.userKVPrefix()+clean); err != nil {
		slog.Error("secret edit: delete failed", "path", clean, "error", err)
		return "", fmt.Errorf("failed to delete secret %q", clean)
	}
	slog.Info("secret deleted via web UI", "path", clean)
	return clean, nil
}

// readEditableDocument reads the secret at rel and renders it as the JSON
// document the editor edits — the same bytes the FUSE mount serves for that
// secret, via the same renderer.
func (s *Server) readEditableDocument(ctx context.Context, rel string) (string, error) {
	secret, err := s.vault.ReadKVv2(ctx, s.kvMount, s.userKVPrefix()+rel)
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", errSecretMissing
	}
	doc, err := vaultfs.RenderDocument(&vaultfs.Secret{
		Data:        secret.Data,
		Version:     secret.Version,
		CreatedTime: secret.CreatedTime,
	})
	if err != nil {
		return "", err
	}
	return string(doc.Bytes), nil
}

// secretEditStatus maps a service-layer error onto an HTTP status. The policy
// refusals are 403 rather than 404: the path exists as far as the reader is
// concerned (the same user can read it), and pretending otherwise would make
// a read-only path indistinguishable from a typo.
func secretEditStatus(err error) int {
	switch {
	case errors.Is(err, kvpath.ErrNotEditable), errors.Is(err, kvpath.ErrManaged):
		return http.StatusForbidden
	case errors.Is(err, kvpath.ErrInvalidName), errors.Is(err, vaultfs.ErrInvalidDocument):
		return http.StatusBadRequest
	case errors.Is(err, errSecretExists):
		return http.StatusConflict
	case errors.Is(err, errSecretMissing):
		return http.StatusNotFound
	default:
		return http.StatusBadGateway
	}
}

// secretEditRequest is the wire shape for a create or replace. The key is
// "fields" so the body mirrors what GET /api/v1/secrets/{path}?reveal=true
// returns: a caller can read a secret, edit the object it got back, and send
// it straight here. It is json.RawMessage rather than a decoded map because
// the bytes are handed to vaultfs.ParseDocument, which applies the mount's
// rules — json.Number for lossless round-tripping of large integers, and the
// refusal of `null`, a non-object, or an object with no fields.
type secretEditRequest struct {
	Fields json.RawMessage `json:"fields"`
}

// apiSecretPath extracts and canonicalises the path from a secrets-API URL.
// The route is registered as a prefix rather than a {path...} wildcard to
// match the existing GET handler, so the trim is done the same way.
func apiSecretPath(r *http.Request) string {
	return strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/")
}

// decodeSecretEdit reads a create/replace body into a KVv2 data map.
func decodeSecretEdit(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, secretBodyLimit)
	var req secretEditRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		// The body is secret material, so the decoder's error — which quotes
		// the offending token — must not reach the response or a log line.
		writeError(w, "request body is not valid JSON", http.StatusBadRequest)
		return nil, false
	}
	// Decode stops at the end of the first complete value and ignores
	// whatever follows, so a body carrying two objects would silently write
	// the first. ParseDocument makes the same check for the inner document;
	// this is the outer envelope's half of it.
	if dec.More() {
		writeError(w, "request body carries trailing content", http.StatusBadRequest)
		return nil, false
	}
	if len(req.Fields) == 0 {
		writeError(w, `request body must carry a "fields" object`, http.StatusBadRequest)
		return nil, false
	}
	data, err := vaultfs.ParseDocument(req.Fields)
	if err != nil {
		writeError(w, "fields must be a JSON object with at least one field", http.StatusBadRequest)
		return nil, false
	}
	return data, true
}

// handleSecretWrite serves POST (create) and PUT (replace) on
// /api/v1/secrets/{path}. Both are CSRF-protected in the ordinary way: the
// consumers are the browser and, in time, the CLI, and both can run the
// issue-then-spend handshake — the peer-action exemption does not apply.
func (s *Server) handleSecretWrite(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIRead(w) {
		return
	}
	data, ok := decodeSecretEdit(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), secretEditTimeout)
	defer cancel()

	clean, err := s.writeEditableSecret(ctx, apiSecretPath(r), data, r.Method == http.MethodPost)
	if err != nil {
		writeError(w, err.Error(), secretEditStatus(err))
		return
	}
	status := http.StatusOK
	if r.Method == http.MethodPost {
		status = http.StatusCreated
	}
	// writeJSONStatus, not WriteHeader-then-writeJSON: net/http snapshots the
	// header map at WriteHeader, so setting Content-Type afterwards is a
	// no-op and the 201 would go out untyped.
	writeJSONStatus(w, status, map[string]any{"path": clean, "status": "written"})
}

// handleSecretDelete serves DELETE on /api/v1/secrets/{path}, removing the
// secret and every version of it.
func (s *Server) handleSecretDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireUIRead(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), secretEditTimeout)
	defer cancel()

	clean, err := s.deleteEditableSecret(ctx, apiSecretPath(r))
	if err != nil {
		writeError(w, err.Error(), secretEditStatus(err))
		return
	}
	writeJSON(w, map[string]any{"path": clean, "status": "deleted"})
}
