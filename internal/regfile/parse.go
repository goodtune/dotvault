package regfile

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/goodtune/dotvault/internal/config"
)

// Parse reads a Windows Registry Editor Version 5.00 .reg file and
// reconstructs a *config.Config from values under
// HKLM\SOFTWARE\Policies\dotvault.
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
			currentKey = path
			// Track rule / enrolment subkey names so we can emit them even
			// when they have no values of their own (e.g. a rule whose
			// fields are all empty strings would still produce its parent
			// key line).
			if name, ok := childUnder(path, rootKey+`\Rules`); ok && name != "" {
				rules[name] = true
			}
			if name, ok := childUnder(path, rootKey+`\Enrolments`); ok && name != "" {
				enrolments[name] = true
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
	if err := applyValues(cfg, values, rules, enrolments); err != nil {
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

// splitLogicalLines splits by line and re-joins continuations, where a
// trailing `\` (after stripping CRLF) means the next line is a continuation
// of the current value. Continuation lines are appended verbatim with their
// leading whitespace stripped, matching the way regedit.exe wraps hex
// output with a two-space indent.
func splitLogicalLines(text string) ([]string, error) {
	rawLines := strings.Split(text, "\n")
	var out []string
	var pending strings.Builder
	for _, raw := range rawLines {
		line := strings.TrimRight(raw, "\r")
		// A line is a continuation if its trailing non-whitespace ends in `\`.
		// Note: backslash inside a quoted REG_SZ is escaped as `\\`, so a
		// real continuation only ever appears in hex(...) lines whose tail
		// is `,\`.
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
			pending.WriteString(strings.TrimLeft(line, " \t"))
			out = append(out, pending.String())
			pending.Reset()
			continue
		}
		out = append(out, line)
	}
	if pending.Len() > 0 {
		out = append(out, pending.String())
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
	// The trailing element is always the empty terminator. If the only
	// element is that empty terminator, the list is empty.
	var out []string
	start := 0
	for i, r := range runes {
		if r == 0 {
			if i == start {
				// terminator
				break
			}
			out = append(out, string(utf16.Decode(runes[start:i])))
			start = i + 1
		}
	}
	if out == nil {
		// Differentiate "explicit empty" from "absent": the parser caller
		// uses non-nil-empty to mean an explicit `[]` so the behaviour
		// matches yaml.Unmarshal of `scopes: []`.
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

// pathInScope reports whether path lives under HKLM\SOFTWARE\Policies\dotvault.
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
func applyValues(cfg *config.Config, values map[valueKey]regValue, rules map[string]bool, enrolments map[string]bool) error {
	get := func(keyPath, name string) (regValue, bool) {
		v, ok := values[valueKey{key: keyPath, name: name}]
		return v, ok
	}

	// Vault.
	vaultKey := rootKey + `\Vault`
	if v, ok := get(vaultKey, "Address"); ok {
		cfg.Vault.Address = v.str
	}
	if v, ok := get(vaultKey, "AuthMethod"); ok {
		cfg.Vault.AuthMethod = v.str
	}
	if v, ok := get(vaultKey, "AuthMount"); ok {
		cfg.Vault.AuthMount = v.str
	}
	if v, ok := get(vaultKey, "AuthRole"); ok {
		cfg.Vault.AuthRole = v.str
	}
	if v, ok := get(vaultKey, "CACert"); ok {
		cfg.Vault.CACert = v.str
	}
	if v, ok := get(vaultKey, "KVMount"); ok {
		cfg.Vault.KVMount = v.str
	}
	if v, ok := get(vaultKey, "UserPrefix"); ok {
		cfg.Vault.UserPrefix = v.str
	}
	if v, ok := get(vaultKey, "DisableTokenRenewal"); ok {
		cfg.Vault.DisableTokenRenewal = v.dword != 0
	}
	if v, ok := get(vaultKey, "TLSSkipVerify"); ok {
		cfg.Vault.TLSSkipVerify = v.dword != 0
	}

	// Sync.
	syncKey := rootKey + `\Sync`
	if v, ok := get(syncKey, "Interval"); ok {
		cfg.Sync.RawInterval = v.str
	}

	// Web.
	webKey := rootKey + `\Web`
	if v, ok := get(webKey, "Enabled"); ok {
		cfg.Web.Enabled = v.dword != 0
	}
	if v, ok := get(webKey, "Listen"); ok {
		cfg.Web.Listen = v.str
	}

	// Rules.
	for name := range rules {
		rule := config.Rule{Name: name}
		base := rootKey + `\Rules\` + name
		if v, ok := get(base, "Description"); ok {
			rule.Description = v.str
		}
		if v, ok := get(base, "VaultKey"); ok {
			rule.VaultKey = v.str
		}
		if v, ok := get(base, "TargetPath"); ok {
			rule.Target.Path = v.str
		}
		if v, ok := get(base, "TargetFormat"); ok {
			rule.Target.Format = v.str
		}
		if v, ok := get(base, "TargetTemplate"); ok {
			rule.Target.Template = v.str
		}
		if v, ok := get(base, "TargetMerge"); ok {
			rule.Target.Merge = v.str
		}
		// OAuth subkey.
		oauthKey := base + `\OAuth`
		hasOAuth := false
		oauth := &config.OAuthConfig{}
		if v, ok := get(oauthKey, "EnginePath"); ok {
			oauth.EnginePath = v.str
			hasOAuth = true
		}
		if v, ok := get(oauthKey, "Provider"); ok {
			oauth.Provider = v.str
			hasOAuth = true
		}
		if v, ok := get(oauthKey, "Scopes"); ok {
			// Treat an explicit empty REG_MULTI_SZ as []string{}, matching
			// `scopes: []` in YAML so the round-trip preserves intent.
			if v.multi == nil {
				oauth.Scopes = []string{}
			} else {
				oauth.Scopes = v.multi
			}
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
		if v, ok := get(base, "Engine"); ok {
			en.Engine = v.str
		}
		// Settings subkey: collect all values whose key path is exactly
		// base\Settings.
		settingsKey := base + `\Settings`
		settings := map[string]any{}
		for vk, v := range values {
			if vk.key != settingsKey {
				continue
			}
			switch v.kind {
			case rvSZ:
				settings[vk.name] = v.str
			case rvMultiSZ:
				// Convert []string to []any so that the YAML round-trip
				// produces the same type as a freshly-loaded YAML config
				// (yaml.Unmarshal turns lists into []any).
				out := make([]any, len(v.multi))
				for i, s := range v.multi {
					out[i] = s
				}
				settings[vk.name] = out
			}
		}
		if len(settings) > 0 {
			en.Settings = settings
		}
		cfg.Enrolments[name] = en
	}

	return nil
}

func sortRulesByName(rules []config.Rule) {
	for i := 1; i < len(rules); i++ {
		for j := i; j > 0 && rules[j-1].Name > rules[j].Name; j-- {
			rules[j-1], rules[j] = rules[j], rules[j-1]
		}
	}
}
