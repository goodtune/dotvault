package regfile

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/goodtune/dotvault/internal/config"
)

// Parse reads a Windows Registry Editor Version 5.00 .reg file and
// reconstructs a *config.Config from values under
// HKLM\SOFTWARE\Policies\goodtune\dotvault.
//
// The input may be UTF-16LE with BOM (the canonical regedit.exe format
// produced by Generate) or plain text/UTF-8 (the variant produced by
// GenerateText / --ascii). Other hives are ignored: only values rooted
// at the dotvault policy key are considered.
//
// Parse does NOT validate the produced config; callers that need
// validation should pass the result through (*Config).validate via
// config.Load or the equivalent path. This keeps the parser focused on
// faithful round-trip and lets callers decide how strict to be.
func Parse(data []byte) (*config.Config, error) {
	text, err := decodeRegBytes(data)
	if err != nil {
		return nil, err
	}

	lines, err := splitLogicalLines(text)
	if err != nil {
		return nil, err
	}

	if len(lines) == 0 || !strings.HasPrefix(strings.TrimSpace(lines[0]), "Windows Registry Editor Version 5.00") {
		return nil, fmt.Errorf("not a Windows Registry Editor Version 5.00 file")
	}

	// Walk every (key, name) pair and stash the raw value in a flat map.
	// Building the Config is then a separate pass that doesn't have to
	// care about file-ordering or continuation handling.
	values := map[valueKey]regValue{}
	rules := map[string]bool{}      // set of rule names seen
	enrolments := map[string]bool{} // set of enrolment names seen
	agentKeys := map[string]bool{}  // set of Agent\Keys index subkeys seen

	var currentKey string
	for i := 1; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r\n")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			path := trimmed[1 : len(trimmed)-1]
			if strings.HasPrefix(path, "-") {
				// Deletion stanza — ignore. We're building from a clean slate
				// so deletions have no effect; the recreation key that
				// follows will repopulate the relevant subtree.
				currentKey = ""
				continue
			}
			currentKey = canonicalizeKeyPath(path)
			// Track rule / enrolment subkey names so we can emit them even
			// when they have no values of their own (e.g. a rule whose
			// fields are all empty strings would still produce its parent
			// key line).
			if name, ok := childUnder(currentKey, rootKey+`\Rules`); ok && name != "" {
				rules[name] = true
			}
			if name, ok := childUnder(currentKey, rootKey+`\Enrolments`); ok && name != "" {
				enrolments[name] = true
			}
			if name, ok := childUnder(currentKey, rootKey+`\Agent\Keys`); ok && name != "" {
				agentKeys[name] = true
			}
			continue
		}

		if currentKey == "" {
			continue
		}

		// Only care about values under the dotvault policy root.
		if !pathInScope(currentKey) {
			continue
		}

		name, val, ok, err := parseValueLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if !ok {
			continue
		}
		values[valueKey{key: currentKey, name: name}] = val
	}

	cfg := &config.Config{}
	if err := applyValues(cfg, values, rules, enrolments, agentKeys); err != nil {
		return nil, err
	}
	return cfg, nil
}

// valueKey identifies a single registry value by its containing key path
// and the value name. Package-level so internal helpers can share the type
// without rebuilding the map.
type valueKey struct {
	key, name string
}

// regValue is a parsed value-line on the right-hand side of `=`. Only one
// of the typed fields is populated, indicated by kind.
type regValue struct {
	kind   regValueKind
	str    string
	dword  uint32
	multi  []string
	binary []byte
}

type regValueKind int

const (
	rvSZ regValueKind = iota + 1
	rvDWORD
	rvMultiSZ
	rvBinary
)

// decodeRegBytes detects the UTF-16LE BOM and decodes accordingly. Plain
// text input (no BOM) is treated as UTF-8/ASCII and returned unchanged.
func decodeRegBytes(data []byte) (string, error) {
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		body := data[2:]
		if len(body)%2 != 0 {
			return "", fmt.Errorf("UTF-16LE input has odd byte length")
		}
		runes := make([]uint16, len(body)/2)
		for i := range runes {
			runes[i] = binary.LittleEndian.Uint16(body[2*i:])
		}
		return string(utf16.Decode(runes)), nil
	}
	// Strip a UTF-8 BOM if present so we don't trip up the header check.
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	return string(data), nil
}

// splitLogicalLines splits by line and re-joins continuations. The only
// continuation form this parser recognises is the `,\` tail produced by
// regedit's hex wrapping (e.g. `...,67,00,69,\` followed by indented
// `00,...`), which is the only place a real continuation can appear in
// .reg v5 files emitted by us or regedit.exe. Backslashes inside quoted
// REG_SZ values are escaped as `\\` so they can't form a tail
// continuation; treating any trailing `\` as a continuation would
// misjoin lines like `"path"="C:\\"` followed by another value.
//
// Continuation lines are appended with their leading whitespace stripped,
// matching the way regedit.exe wraps hex output with a two-space indent.
func splitLogicalLines(text string) ([]string, error) {
	rawLines := strings.Split(text, "\n")
	var out []string
	var pending strings.Builder
	for _, raw := range rawLines {
		line := strings.TrimRight(raw, "\r")
		// A line is a continuation only if it ends in `,\` (the regedit
		// hex-wrap form). See the function comment for why we deliberately
		// do not generalise to "any trailing `\`".
		stripped := strings.TrimRight(line, " \t")
		if strings.HasSuffix(stripped, ",\\") {
			body := strings.TrimSuffix(stripped, ",\\")
			if pending.Len() > 0 {
				body = strings.TrimLeft(body, " \t")
			}
			pending.WriteString(body)
			pending.WriteByte(',')
			continue
		}
		if pending.Len() > 0 {
			// An empty/whitespace-only line after a `,\` tail isn't a
			// valid continuation completion — regedit's hex wrap always
			// continues with `<indent>byte,byte,...`. Treat it the same
			// as EOF and fail loudly so a truncated hex blob doesn't
			// silently parse as a too-short value.
			if strings.TrimSpace(line) == "" {
				return nil, fmt.Errorf("unterminated hex continuation followed by blank line")
			}
			pending.WriteString(strings.TrimLeft(line, " \t"))
			out = append(out, pending.String())
			pending.Reset()
			continue
		}
		out = append(out, line)
	}
	// Unterminated `,\` tail at end of input means the file was
	// truncated mid-value. Same rationale as the blank-line case above.
	if pending.Len() > 0 {
		return nil, fmt.Errorf("unterminated hex continuation at end of input")
	}
	return out, nil
}

// parseValueLine parses `"name"=<value>` or `@=<value>`. It returns
// (name, value, true, nil) when a value line was recognized, or
// (..., false, nil) for unrecognized but non-fatal lines.
func parseValueLine(line string) (string, regValue, bool, error) {
	trim := strings.TrimSpace(line)
	if trim == "" {
		return "", regValue{}, false, nil
	}
	var name string
	var rest string
	if strings.HasPrefix(trim, `"`) {
		closeIdx := findClosingQuote(trim, 1)
		if closeIdx < 0 {
			return "", regValue{}, false, fmt.Errorf("unterminated value name")
		}
		name = unescapeREGString(trim[1:closeIdx])
		if closeIdx+1 >= len(trim) || trim[closeIdx+1] != '=' {
			return "", regValue{}, false, fmt.Errorf("expected `=` after value name")
		}
		rest = trim[closeIdx+2:]
	} else if strings.HasPrefix(trim, "@=") {
		// Default value: not used by our exporter, ignore.
		return "", regValue{}, false, nil
	} else {
		return "", regValue{}, false, nil
	}

	// Value-deletion syntax: `"name"=-` is regedit's way of removing a
	// previously-set value. We're rebuilding the config from scratch, so
	// a deletion is a no-op for us — drop the line silently rather than
	// failing parseRHS on an "unrecognized value form". Real-world GPO
	// .reg files routinely include these alongside [-KEY] stanzas.
	if strings.TrimSpace(rest) == "-" {
		return "", regValue{}, false, nil
	}

	val, err := parseRHS(rest)
	if err != nil {
		return "", regValue{}, false, err
	}
	return name, val, true, nil
}

// parseRHS parses the right-hand side of a value line.
func parseRHS(rhs string) (regValue, error) {
	rhs = strings.TrimSpace(rhs)
	if strings.HasPrefix(rhs, `"`) {
		// Quoted REG_SZ.
		if !strings.HasSuffix(rhs, `"`) || len(rhs) < 2 {
			return regValue{}, fmt.Errorf("unterminated quoted REG_SZ value")
		}
		body := rhs[1 : len(rhs)-1]
		return regValue{kind: rvSZ, str: unescapeREGString(body)}, nil
	}
	if strings.HasPrefix(rhs, "dword:") {
		hexs := strings.TrimSpace(strings.TrimPrefix(rhs, "dword:"))
		n, err := strconv.ParseUint(hexs, 16, 32)
		if err != nil {
			return regValue{}, fmt.Errorf("invalid dword value %q: %w", hexs, err)
		}
		return regValue{kind: rvDWORD, dword: uint32(n)}, nil
	}
	if strings.HasPrefix(rhs, "hex(") {
		closeIdx := strings.Index(rhs, "):")
		if closeIdx < 0 {
			return regValue{}, fmt.Errorf("malformed hex(N): value")
		}
		kindStr := rhs[len("hex("):closeIdx]
		kind, err := strconv.ParseInt(kindStr, 16, 32)
		if err != nil {
			return regValue{}, fmt.Errorf("invalid hex kind %q: %w", kindStr, err)
		}
		raw, err := decodeHexBytes(rhs[closeIdx+2:])
		if err != nil {
			return regValue{}, err
		}
		switch kind {
		case 1, 2: // REG_SZ, REG_EXPAND_SZ
			s, err := utf16BytesToString(raw)
			if err != nil {
				return regValue{}, err
			}
			return regValue{kind: rvSZ, str: s}, nil
		case 7: // REG_MULTI_SZ
			vs, err := utf16BytesToMultiString(raw)
			if err != nil {
				return regValue{}, err
			}
			return regValue{kind: rvMultiSZ, multi: vs}, nil
		default:
			return regValue{kind: rvBinary, binary: raw}, nil
		}
	}
	if strings.HasPrefix(rhs, "hex:") {
		raw, err := decodeHexBytes(strings.TrimPrefix(rhs, "hex:"))
		if err != nil {
			return regValue{}, err
		}
		return regValue{kind: rvBinary, binary: raw}, nil
	}
	return regValue{}, fmt.Errorf("unrecognized value form: %q", rhs)
}

// decodeHexBytes decodes a comma-separated hex byte sequence (e.g.
// "67,00,69,00") into raw bytes. Whitespace and stray commas/backslashes
// from line continuations are tolerated.
func decodeHexBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]byte, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.TrimSuffix(p, `\`)
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		b, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid hex byte %q: %w", p, err)
		}
		out = append(out, byte(b))
	}
	return out, nil
}

// utf16BytesToString decodes UTF-16LE bytes (with optional trailing NUL
// terminator) into a Go string. Odd byte counts are an error.
func utf16BytesToString(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("UTF-16LE byte sequence has odd length")
	}
	runes := make([]uint16, len(b)/2)
	for i := range runes {
		runes[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	// Strip a single trailing NUL terminator if present.
	if n := len(runes); n > 0 && runes[n-1] == 0 {
		runes = runes[:n-1]
	}
	return string(utf16.Decode(runes)), nil
}

// utf16BytesToMultiString decodes a REG_MULTI_SZ blob: a series of
// NUL-terminated UTF-16LE strings followed by a final NUL terminator
// representing the empty trailing string. The empty-list encoding is a
// single NUL pair (i.e. 2 bytes of zero).
//
// Splitting strategy: walk every NUL as a string boundary (matching
// what golang.org/x/sys/windows/registry does), then drop the trailing
// empty element which is the list terminator. Treating the FIRST
// consecutive NUL as the terminator would lose middle empty elements
// — `["a", "", "b"]` round-trips through utf16MultiStringBytes as
// `a\0\0b\0\0`, and a Windows-faithful reader must surface all three
// strings rather than truncating at "a".
func utf16BytesToMultiString(b []byte) ([]string, error) {
	if len(b)%2 != 0 {
		return nil, fmt.Errorf("REG_MULTI_SZ byte sequence has odd length")
	}
	runes := make([]uint16, len(b)/2)
	for i := range runes {
		runes[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	if len(runes) == 0 {
		return []string{}, nil
	}
	// REG_MULTI_SZ must end with a NUL terminator. A blob with no
	// trailing NUL (or a non-empty blob with no NUL anywhere) means
	// the data was truncated or corrupted; silently dropping the
	// trailing segment would convert that into an empty list and lose
	// real configuration without warning.
	if runes[len(runes)-1] != 0 {
		return nil, fmt.Errorf("REG_MULTI_SZ byte sequence is missing the trailing NUL terminator")
	}
	// Split on every NUL — middle empties are real list elements.
	var out []string
	start := 0
	for i, r := range runes {
		if r == 0 {
			out = append(out, string(utf16.Decode(runes[start:i])))
			start = i + 1
		}
	}
	// The final empty string is the list terminator, not a real element.
	// If the only element collected is that terminator, the list is empty
	// (matching the empty-MULTI_SZ encoding of a single NUL pair).
	if n := len(out); n > 0 && out[n-1] == "" {
		out = out[:n-1]
	}
	if out == nil {
		// Non-nil empty so callers can distinguish "explicit empty"
		// from "absent" (matches yaml.Unmarshal of `scopes: []`).
		return []string{}, nil
	}
	return out, nil
}

// findClosingQuote returns the index of the unescaped `"` matching the
// opening quote, starting the search at start. Returns -1 if no match.
// Recognises `\\` and `\"` escape sequences inside the quoted span.
func findClosingQuote(s string, start int) int {
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++ // skip the escaped char
		case '"':
			return i
		}
	}
	return -1
}

// unescapeREGString reverses escapeREGString for `\\` -> `\` and `\"` -> `"`.
// Other backslash sequences are passed through unchanged so we don't quietly
// rewrite content the exporter never produces.
func unescapeREGString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\', '"':
				b.WriteByte(s[i+1])
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// canonicalSegments maps lower-cased fixed key segments under the
// dotvault policy root to the case the renderer emits. Windows registry
// paths are case-insensitive, so a hand-written .reg file might
// reasonably use any case for these segments; canonicalizeKeyPath
// folds them to the canonical form so downstream lookups in
// applyValues can do exact-string comparisons.
//
// Only segments at known structural positions are normalised — we do
// NOT touch user-defined names (rule names, enrolment names, or value
// names). A rule named "OAuth" would still survive the round-trip
// because canonicalizeKeyPath only canonicalises positions it expects
// to be a fixed segment.
var canonicalSegments = map[string]string{
	"vault":         "Vault",
	"sync":          "Sync",
	"web":           "Web",
	"observability": "Observability",
	"remoteconfig":  "RemoteConfig",
	"rules":         "Rules",
	"enrolments":    "Enrolments",
	"oauth":         "OAuth",
	"settings":      "Settings",
}

// canonicalizeKeyPath normalises path so that comparisons against
// rootKey (and known fixed sub-segments like Vault, Sync, Rules,
// OAuth, Settings) are case-insensitive even though the rest of the
// parser does exact-string comparison. Paths outside the dotvault
// policy root are returned unchanged so the caller's pathInScope
// check still rejects them.
func canonicalizeKeyPath(path string) string {
	if !(len(path) >= len(rootKey) && strings.EqualFold(path[:len(rootKey)], rootKey)) {
		return path
	}
	// Replace the prefix with canonical case.
	path = rootKey + path[len(rootKey):]

	rootDepth := strings.Count(rootKey, `\`) + 1 // number of segments in rootKey
	parts := strings.Split(path, `\`)

	// Position rootDepth: Vault | Sync | Web | Rules | Enrolments
	if len(parts) > rootDepth {
		if c, ok := canonicalSegments[strings.ToLower(parts[rootDepth])]; ok {
			parts[rootDepth] = c
		}
	}
	// Position rootDepth+2: OAuth (under Rules\<name>) or Settings
	// (under Enrolments\<name>). We deliberately don't touch
	// rootDepth+1 because that's a user-defined name.
	if len(parts) > rootDepth+2 {
		if c, ok := canonicalSegments[strings.ToLower(parts[rootDepth+2])]; ok {
			parts[rootDepth+2] = c
		}
	}
	// Observability\Headers and RemoteConfig\Headers are the fixed segments
	// at rootDepth+1 (a position otherwise reserved for user-defined
	// rule/enrolment names, which we never fold). Canonicalise only when the
	// parent is one of those sections so a hand-authored .reg using
	// `headers` in any case still matches the exact-string lookups in
	// applyValues.
	if len(parts) > rootDepth+1 &&
		(parts[rootDepth] == "Observability" || parts[rootDepth] == "RemoteConfig") &&
		strings.EqualFold(parts[rootDepth+1], "Headers") {
		parts[rootDepth+1] = "Headers"
	}
	return strings.Join(parts, `\`)
}

// pathInScope reports whether path lives under HKLM\SOFTWARE\Policies\goodtune\dotvault.
func pathInScope(path string) bool {
	if path == rootKey {
		return true
	}
	return strings.HasPrefix(path, rootKey+`\`)
}

// childUnder returns the immediate child segment of path under prefix, if any.
func childUnder(path, prefix string) (string, bool) {
	if !strings.HasPrefix(path, prefix+`\`) {
		return "", false
	}
	rest := strings.TrimPrefix(path, prefix+`\`)
	if rest == "" {
		return "", false
	}
	if i := strings.Index(rest, `\`); i >= 0 {
		return rest[:i], true
	}
	return rest, true
}

// applyValues populates cfg from the flat (key, name) -> value map produced
// during parsing. Unknown values are ignored — the renderer is the source
// of truth for the schema, so anything outside it is treated as opaque.
func applyValues(cfg *config.Config, values map[valueKey]regValue, rules map[string]bool, enrolments map[string]bool, agentKeys map[string]bool) error {
	// Typed accessors so a known field with the wrong .reg type is a
	// hard parse error instead of silently decoding to the zero value.
	// We read against the schema produced by regfile.Generate*: every
	// known string is REG_SZ, every bool is REG_DWORD, and the only
	// REG_MULTI_SZ is OAuth Scopes. A value of an unexpected type
	// almost certainly means hand-edited corruption — fail loudly so
	// the daemon doesn't quietly run with misconfigured policy.
	getString := func(keyPath, name string) (string, bool, error) {
		v, ok := values[valueKey{key: keyPath, name: name}]
		if !ok {
			return "", false, nil
		}
		if v.kind != rvSZ {
			return "", false, kindMismatchErr(keyPath, name, "REG_SZ", v.kind)
		}
		return v.str, true, nil
	}
	getDWORD := func(keyPath, name string) (uint32, bool, error) {
		v, ok := values[valueKey{key: keyPath, name: name}]
		if !ok {
			return 0, false, nil
		}
		if v.kind != rvDWORD {
			return 0, false, kindMismatchErr(keyPath, name, "REG_DWORD", v.kind)
		}
		return v.dword, true, nil
	}
	getMultiString := func(keyPath, name string) ([]string, bool, error) {
		v, ok := values[valueKey{key: keyPath, name: name}]
		if !ok {
			return nil, false, nil
		}
		if v.kind != rvMultiSZ {
			return nil, false, kindMismatchErr(keyPath, name, "REG_MULTI_SZ", v.kind)
		}
		return v.multi, true, nil
	}

	apply := func(target *string, keyPath, name string) error {
		v, ok, err := getString(keyPath, name)
		if err != nil {
			return err
		}
		if ok {
			*target = v
		}
		return nil
	}
	applyBool := func(target *bool, keyPath, name string) error {
		v, ok, err := getDWORD(keyPath, name)
		if err != nil {
			return err
		}
		if ok {
			*target = v != 0
		}
		return nil
	}
	// applyBoolPtr is the tri-state variant for `*bool` defaults: an absent
	// value stays nil (the field's documented default) rather than being
	// forced to false.
	applyBoolPtr := func(target **bool, keyPath, name string) error {
		v, ok, err := getDWORD(keyPath, name)
		if err != nil {
			return err
		}
		if ok {
			b := v != 0
			*target = &b
		}
		return nil
	}

	// Top-level values (directly under the policy root key).
	if err := applyBool(&cfg.BypassSystemConfig, rootKey, "BypassSystemConfig"); err != nil {
		return err
	}

	// Vault.
	vaultKey := rootKey + `\Vault`
	for _, fn := range []func() error{
		func() error { return apply(&cfg.Vault.Address, vaultKey, "Address") },
		func() error { return apply(&cfg.Vault.AuthMethod, vaultKey, "AuthMethod") },
		func() error { return apply(&cfg.Vault.AuthMount, vaultKey, "AuthMount") },
		func() error { return apply(&cfg.Vault.AuthRole, vaultKey, "AuthRole") },
		func() error { return apply(&cfg.Vault.CACert, vaultKey, "CACert") },
		func() error { return apply(&cfg.Vault.KVMount, vaultKey, "KVMount") },
		func() error { return apply(&cfg.Vault.UserPrefix, vaultKey, "UserPrefix") },
		func() error { return applyBool(&cfg.Vault.DisableTokenRenewal, vaultKey, "DisableTokenRenewal") },
		func() error { return applyBool(&cfg.Vault.TLSSkipVerify, vaultKey, "TLSSkipVerify") },
	} {
		if err := fn(); err != nil {
			return err
		}
	}

	// Sync.
	if err := apply(&cfg.Sync.RawInterval, rootKey+`\Sync`, "Interval"); err != nil {
		return err
	}

	// Web.
	webKey := rootKey + `\Web`
	if err := applyBool(&cfg.Web.Enabled, webKey, "Enabled"); err != nil {
		return err
	}
	for _, fn := range []func() error{
		func() error { return apply(&cfg.Web.Listen, webKey, "Listen") },
		func() error { return apply(&cfg.Web.LoginText, webKey, "LoginText") },
		func() error { return apply(&cfg.Web.SecretViewText, webKey, "SecretViewText") },
	} {
		if err := fn(); err != nil {
			return err
		}
	}

	// Observability. The scalar fields mirror the renderer; Headers live in
	// a dedicated subkey (see below) because they're a dynamic key/value map.
	obsKey := rootKey + `\Observability`
	if err := applyBool(&cfg.Observability.Enabled, obsKey, "Enabled"); err != nil {
		return err
	}
	if err := applyBool(&cfg.Observability.Insecure, obsKey, "Insecure"); err != nil {
		return err
	}
	for _, fn := range []func() error{
		func() error { return apply(&cfg.Observability.Endpoint, obsKey, "Endpoint") },
		func() error { return apply(&cfg.Observability.Protocol, obsKey, "Protocol") },
		func() error { return apply(&cfg.Observability.RawInterval, obsKey, "ExportInterval") },
	} {
		if err := fn(); err != nil {
			return err
		}
	}
	// Observability headers: every REG_SZ value directly under
	// Observability\Headers. Conversion is lossless in every direction, so the
	// renderer emits these verbatim and an admin may also author them by hand /
	// GPO; either way we read them back. Header names are preserved verbatim —
	// HTTP folds case, but a faithful round-trip keeps the authored form,
	// unlike the lowercased enrolment Settings names.
	headersKey := obsKey + `\Headers`
	headers := map[string]string{}
	for vk, v := range values {
		if vk.key != headersKey {
			continue
		}
		if v.kind != rvSZ {
			return fmt.Errorf("registry value %s\\%s has unsupported type %s for an observability header (only REG_SZ is supported)", headersKey, vk.name, kindName(v.kind))
		}
		headers[vk.name] = v.str
	}
	if len(headers) > 0 {
		cfg.Observability.Headers = headers
	}

	// RemoteConfig. Scalar fields mirror the renderer; Headers live in a
	// dedicated subkey with the same dynamic-map contract as
	// Observability\Headers.
	remoteKey := rootKey + `\RemoteConfig`
	for _, fn := range []func() error{
		func() error { return apply(&cfg.RemoteConfig.URL, remoteKey, "URL") },
		func() error { return apply(&cfg.RemoteConfig.RawRefreshInterval, remoteKey, "RefreshInterval") },
		func() error { return apply(&cfg.RemoteConfig.CACert, remoteKey, "CACert") },
	} {
		if err := fn(); err != nil {
			return err
		}
	}
	remoteHeadersKey := remoteKey + `\Headers`
	remoteHeaders := map[string]string{}
	for vk, v := range values {
		if vk.key != remoteHeadersKey {
			continue
		}
		if v.kind != rvSZ {
			return fmt.Errorf("registry value %s\\%s has unsupported type %s for a remote-config header (only REG_SZ is supported)", remoteHeadersKey, vk.name, kindName(v.kind))
		}
		remoteHeaders[vk.name] = v.str
	}
	if len(remoteHeaders) > 0 {
		cfg.RemoteConfig.Headers = remoteHeaders
	}

	// Agent.
	agentKey := rootKey + `\Agent`
	if err := applyBool(&cfg.Agent.Enabled, agentKey, "Enabled"); err != nil {
		return err
	}
	if err := apply(&cfg.Agent.Unix.Path, agentKey, "UnixPath"); err != nil {
		return err
	}
	if err := apply(&cfg.Agent.Windows.Pipe, agentKey, "WindowsPipe"); err != nil {
		return err
	}
	if err := applyBoolPtr(&cfg.Agent.Windows.Putty, agentKey, "WindowsPutty"); err != nil {
		return err
	}
	// Agent key sources. Each is a subkey under Agent\Keys named after its
	// zero-based list index; sort numerically to recover the original order.
	if len(agentKeys) > 0 {
		ordered, err := sortAgentKeyNames(agentKeys)
		if err != nil {
			return err
		}
		for _, name := range ordered {
			base := rootKey + `\Agent\Keys\` + name
			ks := config.AgentKeySource{}
			for _, fn := range []func() error{
				func() error { return apply(&ks.Source, base, "Source") },
				func() error { return apply(&ks.PathPrefix, base, "PathPrefix") },
				func() error { return apply(&ks.Mount, base, "Mount") },
				func() error { return apply(&ks.Role, base, "Role") },
				func() error { return apply(&ks.TTL, base, "TTL") },
				func() error { return applyBool(&ks.EphemeralKey, base, "EphemeralKey") },
			} {
				if err := fn(); err != nil {
					return err
				}
			}
			if v, ok, err := getMultiString(base, "Principals"); err != nil {
				return err
			} else if ok {
				// utf16BytesToMultiString normalises the empty case to a
				// non-nil []string{}, preserving the `principals: []`
				// round-trip distinction from an absent key.
				ks.Principals = v
			}
			cfg.Agent.Keys = append(cfg.Agent.Keys, ks)
		}
	}

	// Rules.
	for name := range rules {
		rule := config.Rule{Name: name}
		base := rootKey + `\Rules\` + name
		for _, fn := range []func() error{
			func() error { return apply(&rule.Description, base, "Description") },
			func() error { return apply(&rule.VaultKey, base, "VaultKey") },
			func() error { return apply(&rule.Target.Path, base, "TargetPath") },
			func() error { return apply(&rule.Target.Format, base, "TargetFormat") },
			func() error { return apply(&rule.Target.Template, base, "TargetTemplate") },
			func() error { return apply(&rule.Target.Merge, base, "TargetMerge") },
		} {
			if err := fn(); err != nil {
				return err
			}
		}
		// OAuth subkey.
		oauthKey := base + `\OAuth`
		hasOAuth := false
		oauth := &config.OAuthConfig{}
		if v, ok, err := getString(oauthKey, "EnginePath"); err != nil {
			return err
		} else if ok {
			oauth.EnginePath = v
			hasOAuth = true
		}
		if v, ok, err := getString(oauthKey, "Provider"); err != nil {
			return err
		} else if ok {
			oauth.Provider = v
			hasOAuth = true
		}
		if v, ok, err := getMultiString(oauthKey, "Scopes"); err != nil {
			return err
		} else if ok {
			// utf16BytesToMultiString always returns a non-nil slice on
			// success — the empty REG_MULTI_SZ case is normalised to
			// []string{} there — so the assignment is safe to do directly
			// and preserves the `scopes: []` round-trip intent.
			oauth.Scopes = v
			hasOAuth = true
		}
		if hasOAuth {
			rule.OAuth = oauth
		}
		cfg.Rules = append(cfg.Rules, rule)
	}
	// Stable order — the YAML emit otherwise is at the mercy of map iteration.
	sortRulesByName(cfg.Rules)

	// Enrolments.
	if len(enrolments) > 0 {
		cfg.Enrolments = make(map[string]config.Enrolment, len(enrolments))
	}
	for name := range enrolments {
		base := rootKey + `\Enrolments\` + name
		en := config.Enrolment{}
		if v, ok, err := getString(base, "Engine"); err != nil {
			return err
		} else if ok {
			en.Engine = v
		}
		// Settings subkey: collect all values whose key path is exactly
		// base\Settings.
		settingsKey := base + `\Settings`
		settings := map[string]any{}
		for vk, v := range values {
			if vk.key != settingsKey {
				continue
			}
			// Normalize to lowercase: Windows registry value names are
			// case-insensitive and the registry-side loader in
			// internal/config/registry_windows.go applies the same lowering
			// so engine setting keys (`client_id`, `host`, ...) match
			// regardless of how the .reg file capitalises them.
			settingKey := strings.ToLower(vk.name)
			switch v.kind {
			case rvSZ:
				settings[settingKey] = v.str
			case rvMultiSZ:
				// Convert []string to []any so that the YAML round-trip
				// produces the same type as a freshly-loaded YAML config
				// (yaml.Unmarshal turns lists into []any).
				out := make([]any, len(v.multi))
				for i, s := range v.multi {
					out[i] = s
				}
				settings[settingKey] = out
			default:
				// regfile.Generate refuses to emit any other kind for
				// Settings values, so encountering one here means the
				// .reg was hand-edited (or produced by a different
				// tool) and silently dropping it would lose
				// configuration without warning. Fail with the full
				// path and observed kind so the offending line is
				// easy to find.
				return fmt.Errorf("registry value %s\\%s has unsupported type %s for an enrolment setting (only REG_SZ and REG_MULTI_SZ are supported)", settingsKey, vk.name, kindName(v.kind))
			}
		}
		if len(settings) > 0 {
			en.Settings = settings
		}
		cfg.Enrolments[name] = en
	}

	return nil
}

// kindMismatchErr renders a clear "wrong .reg type" error mentioning the
// full key path, value name, expected kind, and actual kind. The path
// is included so a user staring at a 1000-line .reg dump can find the
// offending value with a single grep.
func kindMismatchErr(keyPath, name, want string, got regValueKind) error {
	return fmt.Errorf("registry value %s\\%s has unexpected type (want %s, got %s)", keyPath, name, want, kindName(got))
}

func kindName(k regValueKind) string {
	switch k {
	case rvSZ:
		return "REG_SZ"
	case rvDWORD:
		return "REG_DWORD"
	case rvMultiSZ:
		return "REG_MULTI_SZ"
	case rvBinary:
		return "REG_BINARY"
	default:
		return fmt.Sprintf("kind=%d", k)
	}
}

// sortAgentKeyNames orders the Agent\Keys index subkey names numerically so
// the rebuilt slice matches the YAML list order the exporter encoded. The
// regfile renderer always names these subkeys after their zero-based list
// index, so a non-integer name means the .reg was hand-edited or produced by
// a different tool — fail loudly rather than guess an order or drop the entry.
//
// A twin of this lives in internal/config/registry_windows.go
// (readRegistryAgentKeys, inline): the live registry loader applies the same
// numeric-sort-with-reject discipline. The two can't share code (this package
// is platform-neutral; that one is //go:build windows), and the duplication
// mirrors how rule/enrolment enumeration is already split across the two
// packages. Keep them in lockstep.
func sortAgentKeyNames(names map[string]bool) ([]string, error) {
	type idx struct {
		name string
		n    int
	}
	parsed := make([]idx, 0, len(names))
	for name := range names {
		n, err := strconv.Atoi(name)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("agent key subkey %q under %s\\Agent\\Keys is not a non-negative integer index", name, rootKey)
		}
		parsed = append(parsed, idx{name: name, n: n})
	}
	sort.Slice(parsed, func(i, j int) bool { return parsed[i].n < parsed[j].n })
	out := make([]string, len(parsed))
	for i, p := range parsed {
		out[i] = p.name
	}
	return out, nil
}

func sortRulesByName(rules []config.Rule) {
	for i := 1; i < len(rules); i++ {
		for j := i; j > 0 && rules[j-1].Name > rules[j].Name; j-- {
			rules[j-1], rules[j] = rules[j], rules[j-1]
		}
	}
}
