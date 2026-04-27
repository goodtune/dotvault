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
func Generate(cfg *config.Config) []byte {
	return encodeUTF16LE(GenerateText(cfg))
}

// GenerateText produces .reg file content for cfg as plain ASCII text.
// Useful for tests and for callers that want to emit a REGEDIT4-compatible
// file without UTF-16 encoding.
func GenerateText(cfg *config.Config) string {
	var b strings.Builder
	b.WriteString(header)

	writeKey(&b, rootKey)
	b.WriteString("\r\n")

	writeVault(&b, cfg.Vault)
	writeSync(&b, cfg.Sync)
	writeWeb(&b, cfg.Web)
	writeRules(&b, cfg.Rules)
	writeEnrolments(&b, cfg.Enrolments)

	return b.String()
}

func writeVault(b *strings.Builder, v config.VaultConfig) {
	writeKey(b, rootKey+`\Vault`)
	writeString(b, "Address", v.Address)
	writeString(b, "AuthMethod", v.AuthMethod)
	writeString(b, "AuthMount", v.AuthMount)
	writeString(b, "AuthRole", v.AuthRole)
	writeString(b, "CACert", v.CACert)
	writeString(b, "KVMount", v.KVMount)
	writeString(b, "UserPrefix", v.UserPrefix)
	writeBool(b, "DisableTokenRenewal", v.DisableTokenRenewal)
	writeBool(b, "TLSSkipVerify", v.TLSSkipVerify)
	b.WriteString("\r\n")
}

func writeSync(b *strings.Builder, s config.SyncConfig) {
	interval := s.RawInterval
	if interval == "" && s.Interval > 0 {
		interval = s.Interval.String()
	}
	if interval == "" {
		return
	}
	writeKey(b, rootKey+`\Sync`)
	writeString(b, "Interval", interval)
	b.WriteString("\r\n")
}

func writeWeb(b *strings.Builder, w config.WebConfig) {
	writeKey(b, rootKey+`\Web`)
	writeBool(b, "Enabled", w.Enabled)
	writeString(b, "Listen", w.Listen)
	b.WriteString("\r\n")
}

func writeRules(b *strings.Builder, rules []config.Rule) {
	if len(rules) == 0 {
		return
	}
	writeKey(b, rootKey+`\Rules`)
	b.WriteString("\r\n")

	sorted := append([]config.Rule(nil), rules...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, r := range sorted {
		writeRule(b, r)
	}
}

func writeRule(b *strings.Builder, r config.Rule) {
	rulePath := rootKey + `\Rules\` + r.Name
	writeKey(b, rulePath)
	writeString(b, "Description", r.Description)
	writeString(b, "TargetFormat", r.Target.Format)
	writeString(b, "TargetMerge", r.Target.Merge)
	writeString(b, "TargetPath", r.Target.Path)
	writeString(b, "TargetTemplate", r.Target.Template)
	writeString(b, "VaultKey", r.VaultKey)
	b.WriteString("\r\n")

	if r.OAuth == nil {
		return
	}
	writeKey(b, rulePath+`\OAuth`)
	writeString(b, "EnginePath", r.OAuth.EnginePath)
	writeString(b, "Provider", r.OAuth.Provider)
	if len(r.OAuth.Scopes) > 0 {
		writeMultiString(b, "Scopes", r.OAuth.Scopes)
	}
	b.WriteString("\r\n")
}

func writeEnrolments(b *strings.Builder, enrolments map[string]config.Enrolment) {
	if len(enrolments) == 0 {
		return
	}
	writeKey(b, rootKey+`\Enrolments`)
	b.WriteString("\r\n")

	names := make([]string, 0, len(enrolments))
	for n := range enrolments {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		writeEnrolment(b, n, enrolments[n])
	}
}

func writeEnrolment(b *strings.Builder, name string, e config.Enrolment) {
	enrolPath := rootKey + `\Enrolments\` + name
	writeKey(b, enrolPath)
	writeString(b, "Engine", e.Engine)
	b.WriteString("\r\n")

	if len(e.Settings) == 0 {
		return
	}
	writeKey(b, enrolPath+`\Settings`)

	keys := make([]string, 0, len(e.Settings))
	for k := range e.Settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		writeSetting(b, k, e.Settings[k])
	}
	b.WriteString("\r\n")
}

// writeSetting emits a single enrolment setting. Strings become REG_SZ;
// slices of strings become REG_MULTI_SZ. Other types are skipped because
// the registry reader only knows how to deserialise these two kinds.
func writeSetting(b *strings.Builder, name string, value any) {
	switch v := value.(type) {
	case string:
		writeString(b, name, v)
	case []string:
		if len(v) > 0 {
			writeMultiString(b, name, v)
		}
	case []any:
		strs := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return
			}
			strs = append(strs, s)
		}
		if len(strs) > 0 {
			writeMultiString(b, name, strs)
		}
	}
}

func writeKey(b *strings.Builder, path string) {
	fmt.Fprintf(b, "[%s]\r\n", path)
}

// writeString emits a REG_SZ value. Plain ASCII without control characters
// is emitted in quoted form; anything else falls through to hex(1) so that
// templates with embedded newlines round-trip correctly.
func writeString(b *strings.Builder, name, value string) {
	if value == "" {
		return
	}
	if needsHex(value) {
		writeHexValue(b, name, 1, utf16Bytes([]string{value}))
		return
	}
	fmt.Fprintf(b, "\"%s\"=%s\r\n", name, quoteREGSZ(value))
}

func writeBool(b *strings.Builder, name string, value bool) {
	v := uint32(0)
	if value {
		v = 1
	}
	fmt.Fprintf(b, "\"%s\"=dword:%08x\r\n", name, v)
}

func writeMultiString(b *strings.Builder, name string, values []string) {
	writeHexValue(b, name, 7, utf16Bytes(values))
}

// utf16Bytes encodes one or more strings as a contiguous UTF-16LE byte
// sequence terminated as expected by the corresponding registry type:
//
//   - REG_SZ (single string): trailing NUL.
//   - REG_MULTI_SZ (slice of strings): each string NUL-terminated, plus
//     a final NUL terminator on the empty trailing string.
func utf16Bytes(values []string) []byte {
	var runes []uint16
	for _, s := range values {
		runes = append(runes, utf16.Encode([]rune(s))...)
		runes = append(runes, 0)
	}
	if len(values) > 1 {
		runes = append(runes, 0)
	}
	out := make([]byte, 2*len(runes))
	for i, r := range runes {
		binary.LittleEndian.PutUint16(out[2*i:], r)
	}
	return out
}

// writeHexValue emits a hex(<kind>):... value, wrapping at maxLineLen
// using the standard backslash continuation that regedit.exe produces.
func writeHexValue(b *strings.Builder, name string, kind int, data []byte) {
	head := fmt.Sprintf("\"%s\"=hex(%d):", name, kind)
	cur := head
	for i, by := range data {
		token := fmt.Sprintf("%02x", by)
		sep := ","
		if i == 0 {
			sep = ""
		}
		// Reserve one column for the trailing backslash on continuation.
		if len(cur)+len(sep)+len(token) > maxLineLen-1 {
			b.WriteString(cur + sep + "\\\r\n  ")
			cur = token
			continue
		}
		cur += sep + token
	}
	b.WriteString(cur + "\r\n")
}

// quoteREGSZ wraps s in double quotes and escapes the only two characters
// that have special meaning inside a quoted REG_SZ value.
func quoteREGSZ(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
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
