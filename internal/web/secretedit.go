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
// The two surfaces write differently on purpose. The JSON API takes a whole
// document and *replaces*, parsed by vaultfs.ParseDocument — the same parser
// the FUSE mount's write path uses, so what a programmatic caller can write
// here is exactly what it could write through the mount. The browser posts
// name/value rows and *patches* (see applyFieldPatch), because a form is what
// a person wants and a document is what a machine wants.
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

// errRenameOrphan reports a rename whose copy succeeded but whose delete did
// not, so the secret now exists at both paths. It is its own sentinel because
// the caller must send the user to the *new* path — the secret is there and
// correct — rather than to the old one, where a retry would meet the
// rename-target probe and fail forever.
var errRenameOrphan = errors.New("the secret was copied but the original could not be removed")

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

// secretExists probes whether a secret is present. A read failure is not
// evidence either way, and guessing would mean either refusing a legitimate
// create or clobbering on a blip — so it is reported rather than resolved.
// Shared by create and by rename so the two cannot drift apart.
func (s *Server) secretExists(ctx context.Context, rel string) (bool, error) {
	secret, err := s.vault.ReadKVv2(ctx, s.kvMount, s.userKVPrefix()+rel)
	if err != nil {
		slog.Error("secret edit: existence check failed", "path", rel, "error", err)
		return false, fmt.Errorf("could not check whether a secret already exists at %q", rel)
	}
	return secret != nil, nil
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
	exists, err := s.secretExists(ctx, clean)
	if err != nil {
		return "", err
	}
	switch {
	case mustBeNew && exists:
		return "", fmt.Errorf("%q: %w", clean, errSecretExists)
	case !mustBeNew && !exists:
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

// readEditableFields reads the secret at rel and returns its data section.
func (s *Server) readEditableFields(ctx context.Context, rel string) (map[string]any, error) {
	secret, err := s.vault.ReadKVv2(ctx, s.kvMount, s.userKVPrefix()+rel)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, errSecretMissing
	}
	if secret.Data == nil {
		return map[string]any{}, nil
	}
	return secret.Data, nil
}

// displayFieldValue renders one KVv2 value as the string an input box holds:
// a string verbatim, anything else as compact JSON.
//
// The round trip through this function is what lets an *unedited* field keep
// its original type and line endings. A key/value form can only carry strings, so re-submitting
// a number would otherwise quietly rewrite 3 as "3"; applyFieldPatch compares
// the submitted string against this rendering and, when they match, keeps the
// value it already had rather than the string standing in for it.
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

// fieldPatch is one editor submission, expressed as the change the user made
// rather than as the document they ended up with.
//
// Submitted holds every row the form posted, keyed by field name. Original
// holds the names the form was *rendered* from. The difference between them
// is what carries the deletions: a name in Original with no row in Submitted
// is a field the user cleared, where a name in neither is simply one the form
// never knew about.
type fieldPatch struct {
	Submitted map[string]string
	Original  map[string]struct{}
}

// applyFieldPatch folds a submission onto the secret's live data and reports
// whether anything actually changed.
//
// The live data is read at save time, not carried through the form, so a field
// another writer added between the page load and the save survives: it is in
// neither Submitted nor Original, and this leaves it alone. That is the whole
// reason the editor patches rather than replacing — a whole-document write
// would silently delete it, and the concurrent writer here is not hypothetical
// (the same secret is reachable through the FUSE mount and the JSON API).
func applyFieldPatch(current map[string]any, p fieldPatch) (result map[string]any, changed bool) {
	result = make(map[string]any, len(current)+len(p.Submitted))
	for k, v := range current {
		result[k] = v
	}
	for name, value := range p.Submitted {
		existing, present := current[name]
		if present && normalizeFormNewlines(displayFieldValue(existing)) == value {
			// Untouched: keep the stored value, with its original type *and*
			// its original line endings, rather than the string the form
			// round-tripped it through.
			//
			// Both sides are normalized before comparing, and that is the
			// whole point. A browser submits every textarea with CRLF line
			// endings whatever the value actually held, so a secret stored
			// with CRLF comes back as CRLF, is normalized to LF, and would
			// never equal its own raw stored form — every save would rewrite
			// it, including a save that touched a different field or nothing
			// at all. Comparing like with like is what makes "a value you do
			// not edit is written back byte for byte" true rather than nearly
			// true.
			continue
		}
		result[name] = value
		changed = true
	}
	for name := range p.Original {
		if _, kept := p.Submitted[name]; kept {
			continue
		}
		if _, present := result[name]; present {
			delete(result, name)
			changed = true
		}
	}
	return result, changed
}

// patchEditableSecret applies a field patch to the secret at rel, optionally
// renaming it to newRel. It returns the path the secret now lives at and
// whether a write happened at all.
//
// A rename is a copy-then-delete because KVv2 has no rename: the new path is
// written first so a failure between the two leaves the original intact (and
// at worst a duplicate) rather than losing the secret. Renaming onto an
// existing path is refused for the same reason create is — it would destroy a
// credential the user never saw.
func (s *Server) patchEditableSecret(ctx context.Context, rel, newRel string, p fieldPatch) (string, bool, error) {
	clean, err := s.editPolicy().Allow(rel)
	if err != nil {
		return "", false, err
	}
	target := clean
	if newRel != "" {
		if target, err = s.editPolicy().Allow(newRel); err != nil {
			return "", false, err
		}
	}
	current, err := s.readEditableFields(ctx, clean)
	if err != nil {
		if errors.Is(err, errSecretMissing) {
			return "", false, fmt.Errorf("%q: %w", clean, errSecretMissing)
		}
		slog.Error("secret edit: read failed", "path", clean, "error", err)
		return "", false, fmt.Errorf("failed to read secret %q", clean)
	}
	result, changed := applyFieldPatch(current, p)
	renaming := target != clean
	if !changed && !renaming {
		// Nothing to do, so nothing is refused either: a secret whose data
		// section is already empty must not turn a no-op save into an error.
		return clean, false, nil
	}
	if len(result) == 0 {
		// The same rule the mount applies: KVv2 does not store a fieldless
		// secret, and clearing every field is far more likely a mistake than
		// a deliberate erasure. Deleting is a separate, confirmed gesture.
		return "", false, fmt.Errorf("%q: %w", clean, errNoFields)
	}
	if renaming {
		exists, err := s.secretExists(ctx, target)
		if err != nil {
			return "", false, err
		}
		if exists {
			return "", false, fmt.Errorf("%q: %w", target, errSecretExists)
		}
	}
	if err := s.vault.WriteKVv2(ctx, s.kvMount, s.userKVPrefix()+target, result); err != nil {
		slog.Error("secret edit: write failed", "path", target, "error", err)
		return "", false, fmt.Errorf("failed to write secret %q", target)
	}
	if renaming {
		// Only after the new copy is durable. A failure here leaves both
		// paths populated, which is visible and recoverable; the reverse
		// order could leave neither.
		if err := s.vault.DeleteKVv2(ctx, s.kvMount, s.userKVPrefix()+clean); err != nil {
			slog.Error("secret edit: delete of renamed original failed", "path", clean, "error", err)
			return target, true, fmt.Errorf("%w: it is now at %q, but %q could not be removed and still holds a copy",
				errRenameOrphan, target, clean)
		}
		slog.Info("secret renamed via web UI", "from", clean, "to", target, "fields", len(result))
		return target, true, nil
	}
	slog.Info("secret patched via web UI", "path", target, "fields", len(result))
	return target, true, nil
}

// secretEditStatus maps a service-layer error onto an HTTP status. The policy
// refusals are 403 rather than 404: the path exists as far as the reader is
// concerned (the same user can read it), and pretending otherwise would make
// a read-only path indistinguishable from a typo.
func secretEditStatus(err error) int {
	switch {
	case errors.Is(err, kvpath.ErrNotEditable), errors.Is(err, kvpath.ErrManaged):
		return http.StatusForbidden
	case errors.Is(err, kvpath.ErrInvalidName), errors.Is(err, vaultfs.ErrInvalidDocument),
		errors.Is(err, errNoFields):
		return http.StatusBadRequest
	case errors.Is(err, errUnrenderableName):
		// The request is well-formed; it just names something this form
		// cannot represent.
		return http.StatusUnprocessableEntity
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
