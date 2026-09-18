// Secret editing: create, replace and delete for the folders named by
// web.editable_paths.
//
// Everything here funnels through editPolicy, which owns the three rules — the
// path must be a direct child of a configured folder (the key space is one
// folder deep), it must not be the folder itself, and it must not be a path
// dotvault writes for itself. Both the JSON API and the browser's form
// POSTs call the same two service methods below, so a screen cannot offer an
// edit the request behind it would refuse, and a future CLI gets the
// behaviour for free.
//
// The two surfaces write differently on purpose. The JSON API takes a whole
// document and *replaces*, parsed by vaultfs.ParseDocument — the same parser
// the FUSE mount's write path uses, so what a programmatic caller can write
// here is exactly what it could write through the mount. The browser posts
// one field at a time and *patches* (see applyFieldEdit), because a form is
// what a person wants and a document is what a machine wants.
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
	"github.com/goodtune/dotvault/internal/vault"
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

// errFieldExists is returned when a rename would land on a field that already
// exists. Two fields would otherwise become one silently, and the one that
// loses is the one the user was not looking at.
var errFieldExists = errors.New("a field of that name already exists")

// errNoFields is returned when a submission would leave a secret with no
// fields at all. Vault rejects such a write, and an empty form is far more
// likely a mistake than a deliberate erasure — deleting is its own gesture,
// behind its own confirmation.
var errNoFields = errors.New("a secret must have at least one field")

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
// subtree" is also true of a secret sitting at *exactly* a configured root,
// which is refused because the root is a direct child of the key space and
// not because any enrolment owns it — so the page told the user it was
// managed by an enrolment that did not exist. Only the policy knows which
// rule refused.
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

// replaceEditableSecret is the JSON API's whole-document write: it replaces
// the data section rather than patching a field, which is what a programmatic
// caller wants and what keeps the API's contract identical to the mount's.
//
// Create and replace stay distinct despite KVv2's write being an upsert, and
// the distinction is enforced by check-and-set rather than by a probe: cas 0
// means "only if absent", so a create over an existing secret is refused by
// Vault instead of by a read whose window another writer can land in.
func (s *Server) replaceEditableSecret(ctx context.Context, rel string, data map[string]any, mustBeNew bool) (string, error) {
	clean, err := s.editPolicy().Allow(rel)
	if err != nil {
		return "", err
	}
	cas := 0
	if !mustBeNew {
		_, version, err := s.readEditableSecret(ctx, clean)
		if err != nil {
			if errors.Is(err, errSecretMissing) {
				return "", fmt.Errorf("%q: %w", clean, errSecretMissing)
			}
			slog.Error("secret edit: read failed", "path", clean, "error", err)
			return "", fmt.Errorf("failed to read secret %q", clean)
		}
		cas = version
	}
	if err := s.vault.WriteKVv2CAS(ctx, s.kvMount, s.userKVPrefix()+clean, data, cas); err != nil {
		if errors.Is(err, vault.ErrCASMismatch) {
			if mustBeNew {
				// cas 0 refused means the secret already exists.
				return "", fmt.Errorf("%q: %w", clean, errSecretExists)
			}
			return "", fmt.Errorf("%q: %w", clean, vault.ErrCASMismatch)
		}
		slog.Error("secret edit: write failed", "path", clean, "error", err)
		return "", fmt.Errorf("failed to write secret %q", clean)
	}
	slog.Info("secret written via web UI", "path", clean, "fields", len(data), "created", mustBeNew)
	return clean, nil
}

// fieldEdit is one change to one field of one secret, carrying the version the
// user was looking at when they made it.
type fieldEdit struct {
	// Name is the field being written. Rename is expressed as Was != Name.
	Name string
	// Was is the field's name before the edit; empty when adding a field.
	Was string
	// Value is the new value; ignored when Delete is set.
	Value string
	// Delete removes the field instead of writing it.
	Delete bool
	// Version is the KVv2 version the form was rendered from. It is the whole
	// point of this type: every write is a check-and-set against it, so an
	// edit made against a stale view is refused by Vault rather than
	// overwriting whatever landed in between. Zero means "this secret does
	// not exist yet", which is KVv2's own spelling of a create.
	Version int
}

// applyFieldEdit folds one edit onto the data as it stands, or reports why it
// cannot.
//
// The row a form came from represents one field, named e.Was if it already
// existed and e.Name if it is new. Every branch below works from that, which
// is what keeps a rename and a removal from being conflated: the edit row
// ships `was`, an editable name and a "Remove field" button in one form, so a
// user who renames and then removes posts both — and taking the two at face
// value dropped the old field *and* whatever now held the new name.
func applyFieldEdit(current map[string]any, e fieldEdit) (map[string]any, error) {
	result := make(map[string]any, len(current)+1)
	for k, v := range current {
		result[k] = v
	}
	// The field this row stands for, whatever the name box now says.
	subject := e.Name
	if e.Was != "" {
		subject = e.Was
	}
	if e.Delete {
		delete(result, subject)
		return result, nil
	}
	// A submission lands on a name that already exists in exactly two ways —
	// a rename onto it, and an add of it — and both mean the same thing: two
	// fields become one with nothing said about it, and the one that loses is
	// the one the user was not looking at. CAS cannot catch this; the version
	// is current and the write is legitimate. Only the edit of a field's own
	// value is allowed to land on an existing name, which is `was == name`.
	adding := e.Was == ""
	renaming := e.Was != "" && e.Was != e.Name
	if adding || renaming {
		if _, taken := current[e.Name]; taken {
			return nil, fmt.Errorf("%q: %w", e.Name, errFieldExists)
		}
	}
	if renaming {
		delete(result, e.Was)
	}
	// The value to compare against is the one the row was *showing*, which on
	// a rename is still stored under the old name. Looking it up by the new
	// name meant a rename could never match — so renaming `count` without
	// touching its textarea rewrote the number 1000000 as the string
	// "1000000", and flattened a CRLF value: exactly the "changed without
	// being edited" this comparison exists to prevent.
	if existing, present := current[subject]; present &&
		normalizeFormNewlines(displayFieldValue(existing)) == e.Value {
		// Unchanged: keep the stored value, with its original type and line
		// endings, rather than the string the form round-tripped it through.
		// Both sides are normalized because a browser submits every textarea
		// with CRLF whatever the value held, so a CRLF value would otherwise
		// never equal its own stored form and every save would rewrite it.
		result[e.Name] = existing
		return result, nil
	}
	result[e.Name] = e.Value
	return result, nil
}

// writeSecretField applies one field edit under check-and-set, returning the
// version the secret is now at.
//
// The CAS is what replaced the old read-probe-then-write: the probe could only
// narrow the window in which another writer lands, never close it, and the
// loser's change vanished silently. Vault decides instead, so a stale edit is
// refused with vault.ErrCASMismatch and the user is told to look again. It
// also gives creation for free — cas 0 means "only if absent", so a create
// racing another create is settled by the server rather than by a probe.
// It returns the canonical path it wrote, which is what the caller redirects
// to: the posted spelling may be non-canonical ("/personal/token/"), and
// sending the user back to that would build a URL with an empty segment in it.
func (s *Server) writeSecretField(ctx context.Context, rel string, e fieldEdit) (string, error) {
	clean, err := s.editPolicy().Allow(rel)
	if err != nil {
		return "", err
	}
	if err := checkEditorPath(clean); err != nil {
		return "", err
	}
	if !editorSafeName(e.Name) {
		return "", fmt.Errorf("a field name: %w", errUnrenderableName)
	}

	current := map[string]any{}
	if e.Version > 0 {
		current, _, err = s.readEditableSecret(ctx, clean)
		if err != nil {
			if errors.Is(err, errSecretMissing) {
				// It existed when the page was rendered and does not now, so
				// the view is stale in the same way a version mismatch is.
				return "", fmt.Errorf("%q: %w", clean, vault.ErrCASMismatch)
			}
			slog.Error("secret edit: read failed", "path", clean, "error", err)
			return "", fmt.Errorf("failed to read secret %q", clean)
		}
	}
	result, err := applyFieldEdit(current, e)
	if err != nil {
		return "", err
	}
	if len(result) == 0 {
		// KVv2 does not store a fieldless secret. Removing the last field is
		// a delete of the secret, which is its own confirmed gesture.
		return "", fmt.Errorf("%q: %w", clean, errNoFields)
	}
	if err := s.vault.WriteKVv2CAS(ctx, s.kvMount, s.userKVPrefix()+clean, result, e.Version); err != nil {
		if errors.Is(err, vault.ErrCASMismatch) {
			if e.Version == 0 {
				// cas 0 means "only if absent", so its refusal says the
				// secret exists — not that it moved on. Reporting a stale
				// version here would send the user to reload a page whose
				// content was never the problem.
				return "", fmt.Errorf("%q: %w", clean, errSecretExists)
			}
			slog.Info("secret edit refused: stale version", "path", clean, "version", e.Version)
			return "", fmt.Errorf("%q: %w", clean, vault.ErrCASMismatch)
		}
		slog.Error("secret edit: write failed", "path", clean, "error", err)
		return "", fmt.Errorf("failed to write secret %q", clean)
	}
	// Field count, never names or values: a field name can itself be telling,
	// and every record is mirrored to the OTel log bridge.
	slog.Info("secret field written via web UI", "path", clean,
		"fields", len(result), "from_version", e.Version, "deleted", e.Delete)
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
	exists, err := s.secretExists(ctx, clean)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("%q: %w", clean, errSecretMissing)
	}
	if err := s.vault.DeleteKVv2(ctx, s.kvMount, s.userKVPrefix()+clean); err != nil {
		slog.Error("secret edit: delete failed", "path", clean, "error", err)
		return "", fmt.Errorf("failed to delete secret %q", clean)
	}
	slog.Info("secret deleted via web UI", "path", clean)
	return clean, nil
}

// secretExists probes whether a secret is present. A read failure is not
// evidence either way, so it is reported rather than resolved.
func (s *Server) secretExists(ctx context.Context, rel string) (bool, error) {
	secret, err := s.vault.ReadKVv2(ctx, s.kvMount, s.userKVPrefix()+rel)
	if err != nil {
		slog.Error("secret edit: existence check failed", "path", rel, "error", err)
		return false, fmt.Errorf("could not check whether a secret exists at %q", rel)
	}
	return secret != nil, nil
}

// readEditableSecret reads the data section and the version it came from.
func (s *Server) readEditableSecret(ctx context.Context, rel string) (map[string]any, int, error) {
	secret, err := s.vault.ReadKVv2(ctx, s.kvMount, s.userKVPrefix()+rel)
	if err != nil {
		return nil, 0, err
	}
	if secret == nil {
		return nil, 0, errSecretMissing
	}
	if secret.Data == nil {
		return map[string]any{}, secret.Version, nil
	}
	return secret.Data, secret.Version, nil
}

// displayFieldValue renders one KVv2 value as the string an input box holds:
// a string verbatim, anything else as compact JSON.
//
// The round trip through this function is what lets an *unedited* field keep
// its original type and line endings. A key/value form can only carry
// strings, so re-submitting a number would otherwise quietly rewrite 3 as
// "3"; applyFieldEdit compares the submitted string against this rendering
// and, when they match, keeps the value it already had.
//
// It is therefore also what fills the edit box, and that is not an
// optimisation but the whole guarantee: a second rendering — the page once
// pretty-printed composites with MarshalIndent — can never equal this one,
// so re-saving an untouched object silently rewrote it as a string of
// indented JSON. One definition, or the unchanged-check is decorative.
func displayFieldValue(v any) string {
	if str, ok := v.(string); ok {
		return str
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// secretEditStatus maps a service-layer error onto an HTTP status. The policy
// refusals are 403 rather than 404: the path exists as far as the reader is
// concerned (the same user can read it), and pretending otherwise would make
// a read-only path indistinguishable from a typo.
func secretEditStatus(err error) int {
	switch {
	case errors.Is(err, kvpath.ErrNotEditable), errors.Is(err, kvpath.ErrManaged),
		errors.Is(err, kvpath.ErrSecretDepth):
		// A depth refusal sits with the other policy refusals rather than with
		// the malformed-request cases: the path is well-formed and may well
		// exist, it is simply not somewhere this configuration grants editing.
		return http.StatusForbidden
	case errors.Is(err, kvpath.ErrInvalidName), errors.Is(err, vaultfs.ErrInvalidDocument),
		errors.Is(err, errNoFields):
		return http.StatusBadRequest
	case errors.Is(err, errUnrenderableName):
		// The request is well-formed; it just names something this form
		// cannot represent.
		return http.StatusUnprocessableEntity
	case errors.Is(err, errSecretExists), errors.Is(err, errFieldExists),
		errors.Is(err, vault.ErrCASMismatch):
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

	clean, err := s.replaceEditableSecret(ctx, apiSecretPath(r), data, r.Method == http.MethodPost)
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
