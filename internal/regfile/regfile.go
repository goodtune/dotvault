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
	interval := s.RawInterval
	if interval == "" && s.Interval > 0 {
		interval = s.Interval.String()
	}
	if interval == "" {
		return
	}
	e.writeKey(rootKey + `\Sync`)
	e.writeString("Interval", interval)
	e.WriteString("\r\n")
}

func (e *emitter) writeWeb(w config.WebConfig) {
	e.writeKey(rootKey + `\Web`)
	e.writeBool("Enabled", w.Enabled)
	e.writeString("Listen", w.Listen)
	e.WriteString("\r\n")
}

func (e *emitter) writeRules(rules []config.Rule) {
	if len(rules) == 0 {
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
	if len(r.OAuth.Scopes) > 0 {
		e.writeMultiString("Scopes", r.OAuth.Scopes)
	}
	e.WriteString("\r\n")
}

func (e *emitter) writeEnrolments(enrolments map[string]config.Enrolment) {
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
func (e *emitter) writeSetting(enrolment, name string, value any) {
	switch v := value.(type) {
	case string:
		e.writeString(name, v)
	case []string:
		if len(v) > 0 {
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
		if len(strs) > 0 {
			e.writeMultiString(name, strs)
		}
	default:
		e.fail("enrolments[%q].settings[%q]: cannot represent %T in registry; only strings and string lists are supported", enrolment, name, value)
	}
}

// writeString emits a REG_SZ value. Plain ASCII without control characters
// is emitted in quoted form; anything else falls through to hex(1) so that
// templates with embedded newlines round-trip correctly.
func (e *emitter) writeString(name, value string) {
	if value == "" {
		return
	}
	if err := validateValueName(name); err != nil {
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
	e.writeHexValue(name, 7, utf16MultiStringBytes(values))
}

// writeHexValue emits a hex(<kind>):... value, wrapping at maxLineLen
// using the standard backslash continuation that regedit.exe produces.
// Continuation lines are prefixed with two spaces; that indent is included
// in the running length so emitted lines do not exceed maxLineLen.
func (e *emitter) writeHexValue(name string, kind int, data []byte) {
	head := fmt.Sprintf("%s=hex(%d):", quoteREGName(name), kind)
	cur := head
	for i, by := range data {
		token := fmt.Sprintf("%02x", by)
		sep := ","
		if i == 0 {
			sep = ""
		}
		// Reserve two columns for the trailing ",\\" on a continuation line.
		if len(cur)+len(sep)+len(token) > maxLineLen-2 {
			e.b.WriteString(cur + sep + "\\\r\n")
			cur = "  " + token
			continue
		}
		cur += sep + token
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

// validateValueName rejects names containing characters that cannot be
// safely represented inside a quoted .reg value name. The .reg format
// has no escape mechanism for control characters or NUL inside quoted
// strings, so we error out rather than silently corrupt the output.
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

// needsHex reports whether s contains characters that cannot appear in a
// quoted REG_SZ value. The .reg quoted form only supports printable ASCII;
// anything else (newlines, tabs, non-ASCII) must use hex(1).
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
