package configsvc

import (
	"fmt"
	"sort"
	"strings"
)

// Dimension is one axis a layer can be addressed by. The vocabulary is
// fixed; each dimension maps to a client-asserted request value:
//
//	os     ← X-Dotvault-OS (lowercased)
//	group  ← the groups resolver applied to the user (multi-valued)
//	device ← X-Dotvault-Hostname (lowercased)
//	user   ← X-Dotvault-User
type Dimension string

const (
	DimOS     Dimension = "os"
	DimGroup  Dimension = "group"
	DimDevice Dimension = "device"
	DimUser   Dimension = "user"
)

// canonicalDimensions is the fixed order dimensions appear in within a kind
// — the spelling is "os+group", never "group+os" — so a combination has
// exactly one kind string and exactly one key shape in the store.
var canonicalDimensions = []Dimension{DimOS, DimGroup, DimDevice, DimUser}

func dimensionIndex(d Dimension) int {
	for i, c := range canonicalDimensions {
		if c == d {
			return i
		}
	}
	return -1
}

// Kind is a set of dimensions a layer is addressed by, held in canonical
// order. The empty Kind is the global layer.
type Kind []Dimension

// ParseKind parses a kind string: "global", a single dimension, or a
// "+"-joined combination in canonical spelling.
func ParseKind(s string) (Kind, error) {
	if s == "global" {
		return Kind{}, nil
	}
	if s == "" {
		return nil, fmt.Errorf("kind must not be empty (want \"global\", a dimension, or a \"+\"-joined combination)")
	}
	parts := strings.Split(s, "+")
	kind := make(Kind, 0, len(parts))
	for _, p := range parts {
		d := Dimension(p)
		if dimensionIndex(d) < 0 {
			return nil, fmt.Errorf("kind %q: unknown dimension %q (want os, group, device, user)", s, p)
		}
		for _, seen := range kind {
			if seen == d {
				return nil, fmt.Errorf("kind %q: dimension %q repeated", s, p)
			}
		}
		kind = append(kind, d)
	}
	for i := 1; i < len(kind); i++ {
		if dimensionIndex(kind[i]) < dimensionIndex(kind[i-1]) {
			canonical := append(Kind(nil), kind...)
			sort.Slice(canonical, func(a, b int) bool {
				return dimensionIndex(canonical[a]) < dimensionIndex(canonical[b])
			})
			return nil, fmt.Errorf("kind %q: dimensions must be spelled in canonical order %q — one combination, one spelling, one key shape", s, canonical.String())
		}
	}
	return kind, nil
}

// String renders the canonical kind string ("global" for the empty kind).
func (k Kind) String() string {
	if len(k) == 0 {
		return "global"
	}
	parts := make([]string, len(k))
	for i, d := range k {
		parts[i] = string(d)
	}
	return strings.Join(parts, "+")
}

// Composition is the operator-declared, ordered list of dimension
// combinations the service composes. Each entry defines both which
// dimensions must all match a request and its position in the merge order —
// precedence is exactly the declared order, with no implicit specificity
// rules. A combination not in the list is never looked up and never served.
type Composition struct {
	order []Kind
}

// DefaultComposition is the order used when the config declares none: the
// original fixed sequence, so existing deployments compose byte-identical
// documents (and keep their ETags) without any migration.
func DefaultComposition() *Composition {
	return &Composition{order: []Kind{{}, {DimOS}, {DimGroup}, {DimUser}}}
}

// ParseCompositionOrder validates an explicit order list. Constraints are
// well-formedness only — valid kinds, no duplicates, at least one entry;
// the ordering BETWEEN entries is deliberately unconstrained (the operator
// decides precedence by ordering the list).
func ParseCompositionOrder(entries []string) (*Composition, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("composition.order must list at least one entry")
	}
	seen := make(map[string]bool, len(entries))
	order := make([]Kind, 0, len(entries))
	for _, entry := range entries {
		kind, err := ParseKind(entry)
		if err != nil {
			return nil, fmt.Errorf("composition.order: %w", err)
		}
		if seen[kind.String()] {
			return nil, fmt.Errorf("composition.order: entry %q listed twice", kind.String())
		}
		seen[kind.String()] = true
		order = append(order, kind)
	}
	return &Composition{order: order}, nil
}

// Kinds returns the canonical strings of the configured order.
func (c *Composition) Kinds() []string {
	out := make([]string, len(c.order))
	for i, k := range c.order {
		out[i] = k.String()
	}
	return out
}

// AllowsKey reports whether key's kind is in the configured order. The
// write paths (admin layer PUT, seed) gate on this so a layer cannot be
// published into a slot the composition will never look up — a typo'd
// combination fails loudly at publish time instead of silently never
// serving.
func (c *Composition) AllowsKey(key string) error {
	kind, _, err := SplitLayerKey(key)
	if err != nil {
		return err
	}
	want := kind.String()
	for _, k := range c.order {
		if k.String() == want {
			return nil
		}
	}
	return fmt.Errorf("layer key %q: kind %q is not in the configured composition order (%s) and would never be served", key, want, strings.Join(c.Kinds(), " → "))
}

// NormalizeDevice canonicalises a hostname into the device dimension value:
// lowercased and cut at the first dot. The same machine reports differently
// per platform — Windows an uppercase NetBIOS name (LAPTOP-7), macOS
// typically name.local, Linux usually the short name — and the first label,
// lowercased, is the value that is stable across all three, so that is what
// device layers are keyed on.
func NormalizeDevice(hostname string) string {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if i := strings.IndexByte(hostname, '.'); i >= 0 {
		hostname = hostname[:i]
	}
	return hostname
}

// RequestDims carries one request's dimension values. OS and User are the
// mandatory identity; Device is optional (older clients may not send a
// hostname) — kinds referencing a dimension with no value are skipped.
// Groups is multi-valued.
type RequestDims struct {
	OS     string
	User   string
	Device string
	Groups []string
}

// Keys expands the configured order against a request's dimensions into the
// store keys to compose, in order. A kind contributes nothing when any of
// its dimensions has no value; a kind containing group contributes one key
// per group, sorted, all at that entry's position. The result is fully
// determined by (order, dims), so the composed bytes — and the ETag — are
// stable.
func (c *Composition) Keys(dims RequestDims) []string {
	values := map[Dimension][]string{
		DimOS:     valueList(strings.ToLower(dims.OS)),
		DimUser:   valueList(dims.User),
		DimDevice: valueList(NormalizeDevice(dims.Device)),
		DimGroup:  append([]string(nil), dims.Groups...),
	}
	sort.Strings(values[DimGroup])

	var keys []string
	for _, kind := range c.order {
		keys = appendKindKeys(keys, kind, values)
	}
	return keys
}

func valueList(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}

// appendKindKeys appends every key the kind yields for the given dimension
// values: the cross product of each dimension's values, varying the last
// dimension fastest. Only group is multi-valued today, but the expansion is
// written generically. A kind referencing a dimension with no value cannot
// match the request and contributes nothing, regardless of where in the
// kind the empty dimension sits.
func appendKindKeys(keys []string, kind Kind, values map[Dimension][]string) []string {
	if len(kind) == 0 {
		return append(keys, "global")
	}
	for _, d := range kind {
		if len(values[d]) == 0 {
			return keys
		}
	}
	segments := make([]string, 0, len(kind)+1)
	segments = append(segments, kind.String())
	var expand func(i int) // appends one key per combination of values[kind[i:]]
	expand = func(i int) {
		if i == len(kind) {
			keys = append(keys, strings.Join(segments, "/"))
			return
		}
		for _, v := range values[kind[i]] {
			segments = append(segments, v)
			expand(i + 1)
			segments = segments[:len(segments)-1]
		}
	}
	expand(0)
	return keys
}

// SplitLayerKey parses a store key into its kind and dimension values,
// validating the grammar: "global", or kind/value[/value...] with exactly
// one value per dimension, each a valid identity segment.
func SplitLayerKey(key string) (Kind, []string, error) {
	if key == "global" {
		return Kind{}, nil, nil
	}
	parts := strings.Split(key, "/")
	kind, err := ParseKind(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("layer key %q: %w", key, err)
	}
	if len(kind) == 0 {
		return nil, nil, fmt.Errorf("layer key %q: \"global\" takes no value segments", key)
	}
	values := parts[1:]
	if len(values) != len(kind) {
		return nil, nil, fmt.Errorf("layer key %q: kind %q needs %d value segment(s), got %d", key, kind.String(), len(kind), len(values))
	}
	for i, v := range values {
		if !ValidIdentitySegment(v) {
			return nil, nil, fmt.Errorf("layer key %q: %s value %q must be non-empty and free of path separators, \"..\", and control characters", key, kind[i], v)
		}
		if (kind[i] == DimOS || kind[i] == DimDevice) && v != strings.ToLower(v) {
			return nil, nil, fmt.Errorf("layer key %q: the %s segment must be lowercase (composition lowercases the client's value, so %q would never be served)", key, kind[i], v)
		}
		if kind[i] == DimDevice && strings.ContainsRune(v, '.') {
			return nil, nil, fmt.Errorf("layer key %q: device values are keyed on the short hostname — the first DNS label — so %q would never be served (use %q)", key, v, NormalizeDevice(v))
		}
	}
	return kind, values, nil
}

// ValidLayerKey checks that key is a well-formed layer key the composer
// could ever serve (given a composition order that lists its kind).
func ValidLayerKey(key string) error {
	_, _, err := SplitLayerKey(key)
	return err
}
