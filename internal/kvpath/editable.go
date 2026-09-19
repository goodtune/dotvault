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

// ErrRootDepth is returned for an editable root that is not a single path
// segment. See EditPolicy for why the key space is only one folder deep.
var ErrRootDepth = errors.New("an editable root must be a single path segment")

// ErrRootSeparator is returned for an editable root containing a backslash.
// Vault paths are slash-separated, so a backslash is an ordinary character in
// a segment rather than a separator — see CleanEditableRoot for why that is
// worth refusing rather than accepting literally.
var ErrRootSeparator = errors.New("an editable root must not contain a backslash")

// ErrSecretDepth is returned for a path that sits below an editable root but
// deeper than its immediate children.
var ErrSecretDepth = errors.New("a secret must sit directly inside an editable root")

// EditPolicy decides whether the web UI may create, replace or delete the
// secret at a relative KV path. It answers one question — "may this path be
// written" — for every surface that needs it, so the read-only-ness of a
// screen and the refusal of the request behind it cannot disagree.
//
// Three rules, in order:
//
//  1. A configured root is exactly one segment ("personal"), and an editable
//     secret is exactly one segment below it ("personal/token"). The user's
//     key space is **one folder deep** — the same shape validateEnrolmentKey
//     enforces for an enrolment key, which is flat ("gh") or grouped once
//     ("databricks/prod") and never more. Editing is a view onto that layout,
//     not a second one, so "personal/aws/dev" is not a secret this policy can
//     be asked about and "scratch/notes" is not a root.
//
//  2. The path must lie strictly *inside* a root, never be one: root
//     "personal" admits "personal/token" and refuses "personal" itself — a
//     secret at that exact path is a direct child of the key-space root,
//     which is the thing the configuration exists to keep out of reach.
//     Nothing is editable when no roots are configured, which is the default.
//
//  3. The path must not be one dotvault writes for itself. Enrolment targets
//     are passed in as managed paths rather than inferred here, because they
//     are reload-dynamic (a remote config document can change the enrolment
//     set on a refresh tick) while the roots are static.
//
// The zero value is a usable policy that permits nothing.
type EditPolicy struct {
	roots   []string
	managed map[string]struct{}
}

// CleanEditableRoot canonicalises one web.editable_paths entry and enforces
// that it names a single path segment. It is the one definition of that rule:
// config load calls it to report a bad entry to the operator, and
// NewEditPolicy calls it to drop one, so the policy can never admit a root the
// configuration would have refused.
func CleanEditableRoot(rel string) (string, error) {
	clean, err := Clean(rel)
	if err != nil {
		return "", err
	}
	if clean == "" {
		return "", fmt.Errorf("the key space root: %w", ErrNotEditable)
	}
	if strings.Contains(clean, "/") {
		// Unquoted: every caller already reports the entry it was given, and
		// the raw spelling is more use to an operator than the canonical one.
		return "", ErrRootDepth
	}
	// A backslash is not a separator in a Vault path, so "personal\notes"
	// passes the single-segment test above and then names a real, writable
	// folder at the literal path users/<you>/personal\notes/ — the silent
	// grant these errors exist to prevent, and the likeliest typo from a GPO
	// admin who types Windows paths all day. validateEnrolmentKey refuses it
	// for the same reason; this is that rule, not a new one.
	if strings.Contains(clean, `\`) {
		return "", ErrRootSeparator
	}
	return clean, nil
}

// NewEditPolicy builds a policy from the configured editable roots and the
// set of dotvault-managed paths. Both are cleaned here; entries that are not
// valid relative paths, roots naming the key-space root itself, and roots
// deeper than one segment are dropped rather than rejected — config load is
// where a bad root is reported to the operator, and a policy that fails closed
// on anything it cannot parse is the safe behaviour for the request path.
func NewEditPolicy(roots []string, managed []string) EditPolicy {
	p := EditPolicy{}
	seen := map[string]struct{}{}
	for _, raw := range roots {
		clean, err := CleanEditableRoot(raw)
		if err != nil {
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
		// Distinguish "below a root but too deep" from "outside every root".
		// The first is a real path the user may well be looking at through
		// the mount, so naming the depth rule tells them why it is read-only
		// here; reporting it as outside the subtree would be a lie.
		if p.underRoot(clean) {
			return "", fmt.Errorf("%q: %w", clean, ErrSecretDepth)
		}
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

// AllowsWithin reports whether a secret could be created in dir — that is,
// whether dir is a configured root. It is what a folder listing asks to decide
// whether to offer "New secret", and it is a weaker question than Allows: the
// root "personal" is not itself editable, but a secret may certainly be
// created inside it. With the key space one folder deep (see EditPolicy) a
// root is also the only such folder, so this is exactly "is dir a root".
func (p EditPolicy) AllowsWithin(dir string) bool {
	clean, err := Clean(dir)
	if err != nil {
		return false
	}
	// Only a root itself can host a new secret: with the key space one folder
	// deep there is nothing below a root but its secrets, so a deeper dir is
	// not a folder a secret could be created in. The key-space root falls out
	// of the same comparison — a root is never empty, so "" matches none.
	for _, root := range p.roots {
		if clean == root {
			return true
		}
	}
	return false
}

// inRoot reports strict containment at the one legal depth: clean must be a
// *direct child* of a root, never the root itself and never deeper. See the
// EditPolicy doc comment for why.
func (p EditPolicy) inRoot(clean string) bool {
	for _, root := range p.roots {
		// Clean has already trimmed trailing slashes and refused empty
		// segments, so rest is non-empty whenever below is true.
		rest, below := strings.CutPrefix(clean, root+"/")
		if below && !strings.Contains(rest, "/") {
			return true
		}
	}
	return false
}

// underRoot reports containment at any depth, which is what separates a path
// refused for being too deep from one refused for being outside every root.
// It is the complement of inRoot's one-level rule; both, and the single
// segment CleanEditableRoot requires of a root, are the same "one folder deep"
// stated by EditPolicy's doc comment, which is where to change it.
func (p EditPolicy) underRoot(clean string) bool {
	for _, root := range p.roots {
		if strings.HasPrefix(clean, root+"/") {
			return true
		}
	}
	return false
}
