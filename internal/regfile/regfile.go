// Package regfile renders a dotvault configuration as a Windows
// Registry (.reg) file targeting HKLM\SOFTWARE\Policies\dotvault.
//
// The output is the canonical "Windows Registry Editor Version 5.00"
// format encoded as UTF-16LE with a BOM, matching what regedit.exe
// produces and what Group Policy tooling expects.
package regfile

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/goodtune/dotvault/internal/config"
)

const (
	rootKey    = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\dotvault`
	header     = "Windows Registry Editor Version 5.00\r\n\r\n"
	maxLineLen = 76
)

// Generate produces .reg file content for cfg encoded as UTF-16LE with BOM.
func Generate(cfg *config.Config) ([]byte, error) {
	text, err := GenerateText(cfg)
	if err != nil {
		return nil, err
	}
	return encodeUTF16LE(text), nil
}

// GenerateText produces .reg file content for cfg as plain text using the
// same Windows Registry Editor Version 5.00 format as Generate, but without
// UTF-16LE encoding. Useful for tests and for callers that want to inspect
// or post-process the output.
func GenerateText(cfg *config.Config) (string, error) {
	e := &emitter{}
	e.WriteString(header)

	e.writeKey(rootKey)
	e.WriteString("\r\n")

	e.writeVault(cfg.Vault)
	e.writeSync(cfg.Sync)
	e.writeWeb(cfg.Web)
	e.writeRules(cfg.Rules)
	e.writeEnrolments(cfg.Enrolments)

	if e.err != nil {
		return "", e.err
	}
	return e.b.String(), nil
}

// emitter is a strings.Builder wrapper that captures the first error
// encountered so the rendering walk can carry on without if/return
// noise at every call site.
type emitter struct {
	b   strings.Builder
	err error
}

func (e *emitter) WriteString(s string) { e.b.WriteString(s) }

func (e *emitter) fail(format string, args ...any) {
	if e.err == nil {
		e.err = fmt.Errorf(format, args...)
	}
}

func (e *emitter) writeKey(path string) {
	fmt.Fprintf(&e.b, "[%s]\r\n", path)
}

// writeKeyDeletion emits a `[-PATH]` stanza which instructs registry
// import to delete the given key (and all subkeys/values). Used to make
// the export idempotent for sections where the set of subkeys is
// determined dynamically by the YAML.
func (e *emitter) writeKeyDeletion(path string) {
	fmt.Fprintf(&e.b, "[-%s]\r\n\r\n", path)
}

func (e *emitter) writeVault(v config.VaultConfig) {
	e.writeKey(rootKey + `\Vault`)
	e.writeString("Address", v.Address)
	e.writeString("AuthMethod", v.AuthMethod)
	e.writeString("AuthMount", v.AuthMount)
	e.writeString("AuthRole", v.AuthRole)
	e.writeString("CACert", v.CACert)
	e.writeString("KVMount", v.KVMount)
	e.writeString("UserPrefix", v.UserPrefix)
	e.writeBool("DisableTokenRenewal", v.DisableTokenRenewal)
	e.writeBool("TLSSkipVerify", v.TLSSkipVerify)
	e.WriteString("\r\n")
}

func (e *emitter) writeSync(s config.SyncConfig) {
	// Emit RawInterval as the user wrote it (or empty if they relied on
	// the daemon's 15m default). Avoid s.Interval.String() because Go's
	// time.Duration formatter produces verbose forms like "15m0s" for
	// what the YAML expressed as "15m"; that round-trip is technically
	// valid but pollutes diffs of exported .reg files.
	e.writeKey(rootKey + `\Sync`)
	e.writeString("Interval", s.RawInterval)
	e.WriteString("\r\n")
}

func (e *emitter) writeWeb(w config.WebConfig) {
	e.writeKey(rootKey + `\Web`)
	e.writeBool("Enabled", w.Enabled)
	e.writeString("Listen", w.Listen)
	e.WriteString("\r\n")
}

func (e *emitter) writeRules(rules []config.Rule) {
	// Delete the whole Rules subtree before re-creating it. Because the
	// registry loader enumerates every subkey under Rules, an additive
	// export would let rules removed from YAML keep syncing secrets on
	// machines where they were previously imported. Pre-deleting makes
	// the .reg file an idempotent statement of intent rather than a
	// merge against existing state.
	e.writeKeyDeletion(rootKey + `\Rules`)
	if len(rules) == 0 {
		// No rules to re-create; the deletion stanza alone wipes the subtree.
		return
	}
	e.writeKey(rootKey + `\Rules`)
	e.WriteString("\r\n")

	sorted := append([]config.Rule(nil), rules...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, r := range sorted {
		e.writeRule(r)
	}
}

func (e *emitter) writeRule(r config.Rule) {
	if err := validateKeyName(r.Name); err != nil {
		e.fail("rule %q: %w", r.Name, err)
		return
	}
	rulePath := rootKey + `\Rules\` + r.Name
	e.writeKey(rulePath)
	e.writeString("Description", r.Description)
	e.writeString("TargetFormat", r.Target.Format)
	e.writeString("TargetMerge", r.Target.Merge)
	e.writeString("TargetPath", r.Target.Path)
	e.writeString("TargetTemplate", r.Target.Template)
	e.writeString("VaultKey", r.VaultKey)
	e.WriteString("\r\n")

	if r.OAuth == nil {
		return
	}
	e.writeKey(rulePath + `\OAuth`)
	e.writeString("EnginePath", r.OAuth.EnginePath)
	e.writeString("Provider", r.OAuth.Provider)
	// Emit Scopes whenever the slice is non-nil so an explicit empty list
	// (`scopes: []` in YAML) round-trips as an empty REG_MULTI_SZ rather
	// than being silently dropped.
	if r.OAuth.Scopes != nil {
		e.writeMultiString("Scopes", r.OAuth.Scopes)
	}
	e.WriteString("\r\n")
}

func (e *emitter) writeEnrolments(enrolments map[string]config.Enrolment) {
	// Same idempotency story as writeRules: wipe the Enrolments subtree
	// first so enrolments (and their Settings) removed from YAML are also
	// removed from the registry on re-import.
	e.writeKeyDeletion(rootKey + `\Enrolments`)
	if len(enrolments) == 0 {
		return
	}
	e.writeKey(rootKey + `\Enrolments`)
	e.WriteString("\r\n")

	names := make([]string, 0, len(enrolments))
	for n := range enrolments {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		e.writeEnrolment(n, enrolments[n])
	}
}

func (e *emitter) writeEnrolment(name string, en config.Enrolment) {
	if err := validateKeyName(name); err != nil {
		e.fail("enrolment %q: %w", name, err)
		return
	}
	enrolPath := rootKey + `\Enrolments\` + name
	e.writeKey(enrolPath)
	e.writeString("Engine", en.Engine)
	e.WriteString("\r\n")

	if len(en.Settings) == 0 {
		return
	}
	e.writeKey(enrolPath + `\Settings`)

	keys := make([]string, 0, len(en.Settings))
	for k := range en.Settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e.writeSetting(name, k, en.Settings[k])
	}
	e.WriteString("\r\n")
}

// writeSetting emits a single enrolment setting. Strings become REG_SZ;
// slices of strings become REG_MULTI_SZ. The registry reader only knows
// how to deserialise these two kinds, so any other value type is treated
// as an error rather than silently dropped: a partial export that
// disagrees with the source YAML is worse than a hard failure.
//
// Empty lists are preserved as empty REG_MULTI_SZ rather than dropped:
// in YAML an explicit `[]` differs from an absent key, and engines that
// override defaults from the presence of a list (e.g. GitHub's `scopes`)
// rely on that distinction.
func (e *emitter) writeSetting(enrolment, name string, value any) {
	switch v := value.(type) {
	case string:
		e.writeString(name, v)
	case []string:
		if v != nil {
			e.writeMultiString(name, v)
		}
	case []any:
		strs := make([]string, 0, len(v))
		for i, item := range v {
			s, ok := item.(string)
			if !ok {
				e.fail("enrolments[%q].settings[%q][%d]: cannot represent %T in registry; only strings are supported", enrolment, name, i, item)
				return
			}
			strs = append(strs, s)
		}
		e.writeMultiString(name, strs)
	default:
		e.fail("enrolments[%q].settings[%q]: cannot represent %T in registry; only strings and string lists are supported", enrolment, name, value)
	}
}

// writeString emits a REG_SZ value. Plain ASCII without control characters
// is emitted in quoted form; anything else falls through to hex(1) so that
// templates with embedded newlines round-trip correctly.
//
// Empty strings are emitted explicitly as `"<Name>"=""` rather than
// omitted, so that re-importing an exported .reg clears any value
// previously configured for the same name. Without this, removing an
// optional field from YAML would leave stale registry data on machines
// where the policy was previously applied.
func (e *emitter) writeString(name, value string) {
	if err := validateValueName(name); err != nil {
		e.fail("%w", err)
		return
	}
	if err := rejectEmbeddedNUL(name, value); err != nil {
		e.fail("%w", err)
		return
	}
	if needsHex(value) {
		e.writeHexValue(name, 1, utf16StringBytes(value))
		return
	}
	fmt.Fprintf(&e.b, "%s=%s\r\n", quoteREGName(name), quoteREGSZ(value))
}

func (e *emitter) writeBool(name string, value bool) {
	if err := validateValueName(name); err != nil {
		e.fail("%w", err)
		return
	}
	v := uint32(0)
	if value {
		v = 1
	}
	fmt.Fprintf(&e.b, "%s=dword:%08x\r\n", quoteREGName(name), v)
}

func (e *emitter) writeMultiString(name string, values []string) {
	if err := validateValueName(name); err != nil {
		e.fail("%w", err)
		return
	}
	// Embedded NUL in a list element would split or truncate the entry on
	// import because REG_MULTI_SZ uses NUL as the element delimiter.
	for i, v := range values {
		if strings.IndexByte(v, 0) >= 0 {
			e.fail("registry value %q list element [%d] contains an embedded NUL byte; REG_MULTI_SZ uses NUL as a delimiter and cannot represent it", name, i)
			return
		}
	}
	e.writeHexValue(name, 7, utf16MultiStringBytes(values))
}

// writeHexValue emits a hex(<kind>):... value, wrapping at maxLineLen
// using the standard backslash continuation that regedit.exe produces.
// Continuation lines are prefixed with two spaces; that indent is included
// in the running length so emitted lines do not exceed maxLineLen.
//
// The first byte is always emitted on the same line as the head so we never
// produce a degenerate first line of just `<head>\` with no payload byte.
// If the head plus first byte cannot fit (excluding any later wrap budget),
// generation fails with an explicit error rather than emitting malformed
// output.
//
// Lengths are measured in runes rather than bytes so Unicode value names
// don't trigger spurious wraps or false "too long" errors. Hex tokens
// (`,XX`) and the indent are pure ASCII, so rune count matches column
// count for everything we append.
func (e *emitter) writeHexValue(name string, kind int, data []byte) {
	head := fmt.Sprintf("%s=hex(%d):", quoteREGName(name), kind)
	headLen := utf8.RuneCountInString(head)
	if len(data) == 0 {
		e.b.WriteString(head + "\r\n")
		return
	}
	firstToken := fmt.Sprintf("%02x", data[0])
	// Reserve two columns for the trailing ",\\" if a continuation is needed.
	if headLen+len(firstToken) > maxLineLen-2 {
		e.fail("registry value name %q is too long to encode as hex(%d) within %d columns", name, kind, maxLineLen)
		return
	}
	cur := head + firstToken
	curLen := headLen + len(firstToken)
	for _, by := range data[1:] {
		token := fmt.Sprintf("%02x", by)
		// Reserve two columns for the trailing ",\\" on a continuation line.
		if curLen+1+len(token) > maxLineLen-2 {
			e.b.WriteString(cur + ",\\\r\n")
			cur = "  " + token
			curLen = 2 + len(token)
			continue
		}
		cur += "," + token
		curLen += 1 + len(token)
	}
	e.b.WriteString(cur + "\r\n")
}

// utf16StringBytes encodes a single string as UTF-16LE bytes terminated
// by a single NUL (0x00 0x00).
func utf16StringBytes(s string) []byte {
	runes := utf16.Encode([]rune(s))
	runes = append(runes, 0)
	return runesToLE(runes)
}

// utf16MultiStringBytes encodes a REG_MULTI_SZ as a contiguous UTF-16LE
// byte sequence: each string NUL-terminated, plus a final NUL terminator
// (the empty trailing string) when the slice is non-empty. An empty slice
// produces a single NUL pair, matching how regedit.exe emits an empty
// REG_MULTI_SZ.
func utf16MultiStringBytes(values []string) []byte {
	var runes []uint16
	for _, s := range values {
		runes = append(runes, utf16.Encode([]rune(s))...)
		runes = append(runes, 0)
	}
	runes = append(runes, 0)
	return runesToLE(runes)
}

func runesToLE(runes []uint16) []byte {
	out := make([]byte, 2*len(runes))
	for i, r := range runes {
		binary.LittleEndian.PutUint16(out[2*i:], r)
	}
	return out
}

// quoteREGSZ wraps s in double quotes and escapes the only two characters
// that have special meaning inside a quoted REG_SZ value.
func quoteREGSZ(s string) string {
	return `"` + escapeREGString(s) + `"`
}

// quoteREGName quotes a value name with the same escape rules as REG_SZ
// values. Value names accepted by Windows are very permissive; the rest
// of the renderer guards against unrepresentable cases via
// validateValueName before calling here.
func quoteREGName(name string) string {
	return `"` + escapeREGString(name) + `"`
}

func escapeREGString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// rejectEmbeddedNUL returns an error if value contains a NUL byte (\x00).
// REG_SZ and REG_MULTI_SZ both use NUL as a terminator, so an embedded NUL
// would be truncated or split when the value is read back on import,
// breaking round-trip. We surface this as a clear error rather than
// silently corrupt the export.
func rejectEmbeddedNUL(name, value string) error {
	if strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("registry value %q contains an embedded NUL byte; REG_SZ cannot represent it", name)
	}
	return nil
}

// validateValueName rejects names that cannot be safely represented inside
// a quoted .reg value name. The .reg format has no escape mechanism for
// control characters or NUL inside quoted strings, so we error out rather
// than silently corrupt the output. Unicode characters are allowed: the
// default UTF-16LE output encodes them faithfully, and the --ascii output
// stays valid UTF-8.
func validateValueName(name string) error {
	if name == "" {
		return fmt.Errorf("registry value name must not be empty")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7F {
			return fmt.Errorf("registry value name %q contains control character U+%04X", name, r)
		}
	}
	return nil
}

// validateKeyName rejects names that cannot appear as a single registry
// key path segment. Key segments may contain Unicode because the default
// .reg output is UTF-16LE and can represent it; however they must not
// contain control characters, `\` (segment separator), or `[`/`]`
// (key-line delimiters) so they cannot break out of the path or
// invalidate the surrounding `.reg` syntax.
func validateKeyName(name string) error {
	if name == "" {
		return fmt.Errorf("registry key name must not be empty")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7F {
			return fmt.Errorf("registry key name %q contains control character U+%04X", name, r)
		}
		switch r {
		case '\\', '[', ']':
			return fmt.Errorf("registry key name %q contains reserved character %q", name, r)
		}
	}
	return nil
}

// needsHex reports whether this renderer should emit s as hex(1) instead
// of a quoted REG_SZ value. Although .reg v5 files can represent Unicode
// in quoted strings when encoded as UTF-16LE, this renderer keeps quoted
// output to printable ASCII so text-oriented output stays plain text;
// anything else (newlines, tabs, non-ASCII) is emitted as hex(1).
func needsHex(s string) bool {
	for _, r := range s {
		if r < 0x20 || r > 0x7E {
			return true
		}
	}
	return false
}

// encodeUTF16LE prepends a UTF-16LE BOM and encodes s as UTF-16 little-endian.
func encodeUTF16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	out := make([]byte, 2+2*len(runes))
	out[0] = 0xFF
	out[1] = 0xFE
	for i, r := range runes {
		binary.LittleEndian.PutUint16(out[2+2*i:], r)
	}
	return out
}
