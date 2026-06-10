package config

// ApplyPartial merges a partial configuration document over a base config:
// rules merge by name (a same-named rule replaces the base rule wholesale,
// keeping the base's position; new names append in document order),
// enrolments merge by map key (an entry replaces the base entry wholesale),
// and a non-empty sync interval overrides. A rule or enrolment is treated as
// an atomic unit — field-level splicing across layers would be unreadable in
// practice.
//
// Merging is additive-only: there are no deletion tombstones. Callers
// recompute base ⊕ overlay from a freshly loaded base on every refresh, so an
// entry removed from the overlay disappears naturally; removing an entry the
// base itself defines requires editing the base.
//
// The base is mutated in place. The overlay is not retained or mutated,
// though map-valued fields (enrolment Settings) are shared rather than
// deep-copied — both sides treat them as immutable after the merge.
func ApplyPartial(base *Config, p *Partial) {
	if base == nil || p == nil {
		return
	}
	if p.Sync != nil && p.Sync.RawInterval != "" {
		base.Sync.RawInterval = p.Sync.RawInterval
	}
	base.Rules = mergeRules(base.Rules, p.Rules)
	if len(p.Enrolments) > 0 {
		if base.Enrolments == nil {
			base.Enrolments = make(map[string]Enrolment, len(p.Enrolments))
		}
		for k, v := range p.Enrolments {
			base.Enrolments[k] = v
		}
	}
}

// MergePartial folds src onto dst with the same semantics as ApplyPartial and
// returns dst (allocating it when nil, so layer composition can fold from a
// nil accumulator). The dotvault-config service composes its layer documents
// with this; keeping it beside ApplyPartial guarantees the service composes
// exactly the way clients merge.
func MergePartial(dst, src *Partial) *Partial {
	if dst == nil {
		dst = &Partial{}
	}
	if src == nil {
		return dst
	}
	if src.Sync != nil && src.Sync.RawInterval != "" {
		if dst.Sync == nil {
			dst.Sync = &SyncConfig{}
		}
		dst.Sync.RawInterval = src.Sync.RawInterval
	}
	dst.Rules = mergeRules(dst.Rules, src.Rules)
	if len(src.Enrolments) > 0 {
		if dst.Enrolments == nil {
			dst.Enrolments = make(map[string]Enrolment, len(src.Enrolments))
		}
		for k, v := range src.Enrolments {
			dst.Enrolments[k] = v
		}
	}
	return dst
}

// mergeRules merges overlay rules into base by rule name. When the overlay
// contributes anything the result is a fresh slice so the overlay's backing
// array is never aliased into the base.
func mergeRules(base, overlay []Rule) []Rule {
	if len(overlay) == 0 {
		return base
	}
	out := append([]Rule(nil), base...)
	index := make(map[string]int, len(out))
	for i, r := range out {
		index[r.Name] = i
	}
	for _, r := range overlay {
		if i, ok := index[r.Name]; ok {
			out[i] = r
		} else {
			index[r.Name] = len(out)
			out = append(out, r)
		}
	}
	return out
}
