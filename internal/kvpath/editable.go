package kvpath

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrNotEditable is returned for a path outside every configured editable
// subtree — including the user's key-space root itself, which is never
// editable however the roots are configured.
var ErrNotEditable = errors.New("path is not in an editable key space")

// ErrManaged is returned for a path inside an editable subtree that dotvault
// itself writes: an enrolment's target. The credential there is owned by the
// enrolment engine, which will overwrite an edit at its next run or refresh,
// so offering to edit it would be offering to lose the change silently.
var ErrManaged = errors.New("path is managed by an enrolment")

// EditPolicy decides whether the web UI may create, replace or delete the
// secret at a relative KV path. It answers one question — "may this path be
// written" — for every surface that needs it, so the read-only-ness of a
// screen and the refusal of the request behind it cannot disagree.
//
// Two rules, in order:
//
//  1. The path must lie strictly *inside* one of the configured roots. A root
//     names a subtree, so root "personal" admits "personal/token" and
//     "personal/aws/dev" but not "personal" itself — a secret at that exact
//     path is a direct child of the key-space root, which is the thing the
//     configuration exists to keep out of reach. Nothing is editable when no
//     roots are configured, which is the default.
//
//  2. The path must not be one dotvault writes for itself. Enrolment targets
//     are passed in as managed paths rather than inferred here, because they
//     are reload-dynamic (a remote config document can change the enrolment
//     set on a refresh tick) while the roots are static.
//
// The zero value is a usable policy that permits nothing.
type EditPolicy struct {
	roots   []string
	managed map[string]struct{}
}

// NewEditPolicy builds a policy from the configured editable roots and the
// set of dotvault-managed paths. Both are cleaned here; entries that are not
// valid relative paths, and roots naming the key-space root itself, are
// dropped rather than rejected — config load is where a bad root is reported
// to the operator, and a policy that fails closed on anything it cannot parse
// is the safe behaviour for the request path.
func NewEditPolicy(roots []string, managed []string) EditPolicy {
	p := EditPolicy{}
	seen := map[string]struct{}{}
	for _, raw := range roots {
		clean, err := Clean(raw)
		if err != nil || clean == "" {
			continue
		}
		if _, dup := seen[clean]; dup {
			continue
		}
		seen[clean] = struct{}{}
		p.roots = append(p.roots, clean)
	}
	sort.Strings(p.roots)
	for _, raw := range managed {
		clean, err := Clean(raw)
		if err != nil || clean == "" {
			continue
		}
		if p.managed == nil {
			p.managed = map[string]struct{}{}
		}
		p.managed[clean] = struct{}{}
	}
	return p
}

// Enabled reports whether any subtree is editable at all. A false answer is
// what the UI keys its read-only presentation off, so the "no editing
// configured" case renders exactly as it did before this feature existed.
func (p EditPolicy) Enabled() bool { return len(p.roots) > 0 }

// Roots returns the configured editable subtrees in sorted order. The UI uses
// it to offer a starting path when creating a secret, and to mark which
// folders in the sidebar carry editing controls.
func (p EditPolicy) Roots() []string {
	out := make([]string, len(p.roots))
	copy(out, p.roots)
	return out
}

// Allow reports whether the secret at rel may be created, replaced or
// deleted, returning the cleaned path on success. A nil error is the only
// permission to write; every caller checks it before touching Vault.
func (p EditPolicy) Allow(rel string) (string, error) {
	clean, err := Clean(rel)
	if err != nil {
		return "", fmt.Errorf("%q: %w", rel, err)
	}
	if clean == "" {
		return "", fmt.Errorf("the key space root: %w", ErrNotEditable)
	}
	if !p.inRoot(clean) {
		return "", fmt.Errorf("%q: %w", clean, ErrNotEditable)
	}
	if _, managed := p.managed[clean]; managed {
		return "", fmt.Errorf("%q: %w", clean, ErrManaged)
	}
	return clean, nil
}

// Allows is the boolean form, for templates deciding whether to render a
// control. It deliberately shares Allow's implementation rather than
// re-deriving the rule, so a screen can never offer an edit the request
// behind it would refuse.
func (p EditPolicy) Allows(rel string) bool {
	_, err := p.Allow(rel)
	return err == nil
}

// AllowsWithin reports whether any path could be created under dir — that is,
// whether dir is a configured root or sits inside one. It is what a folder
// listing asks to decide whether to offer "New secret", and it is a weaker
// question than Allows: the root "personal" is not itself editable, but a
// secret may certainly be created inside it.
func (p EditPolicy) AllowsWithin(dir string) bool {
	clean, err := Clean(dir)
	if err != nil {
		return false
	}
	if clean == "" {
		// The key-space root contains every editable subtree, but naming a
		// path there is not itself creating one inside a root — the create
		// form's path field is what resolves that, and Allow judges it.
		return false
	}
	for _, root := range p.roots {
		if clean == root || strings.HasPrefix(clean, root+"/") {
			return true
		}
	}
	return false
}

// inRoot reports strict containment: clean must be *below* a root, never the
// root itself. See the EditPolicy doc comment for why.
func (p EditPolicy) inRoot(clean string) bool {
	for _, root := range p.roots {
		if strings.HasPrefix(clean, root+"/") {
			return true
		}
	}
	return false
}
