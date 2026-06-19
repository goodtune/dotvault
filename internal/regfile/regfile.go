// Package regfile renders a dotvault configuration as a Windows
// Registry (.reg) file targeting HKLM\SOFTWARE\Policies\goodtune\dotvault.
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
	rootKey    = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault`
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

	e.writeTopLevel(cfg)

	e.writeVault(cfg.Vault)
	e.writeMTLS(cfg.Vault.MTLS)
	e.writeSync(cfg.Sync)
	e.writeWeb(cfg.Web)
	e.writeObservability(cfg.Observability)
	e.writeRemoteConfig(cfg.RemoteConfig)
	e.writeAgent(cfg.Agent)
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

// writeTopLevel emits the root policy key plus the values that live directly
// under it (not inside a named subsection). Currently just BypassSystemConfig,
// which gates whether a --config command-line override is honoured on a
// machine carrying this policy.
func (e *emitter) writeTopLevel(cfg *config.Config) {
	e.writeKey(rootKey)
	e.writeBool("BypassSystemConfig", cfg.BypassSystemConfig)
	e.WriteString("\r\n")
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
	e.writeString("TokenSocket", v.TokenSocket)
	e.writeBool("DisableTokenRenewal", v.DisableTokenRenewal)
	e.writeBool("TLSSkipVerify", v.TLSSkipVerify)
	e.WriteString("\r\n")
}

// writeMTLS emits the cert-auth (mtls / mtls+tpm) settings under a dedicated
// Vault\MTLS subkey, with the bring-your-own paths nested under Vault\MTLS\BYO.
// Scalars are always emitted (empty as "") so a re-import clears stale values,
// matching the Web/Observability idempotency pattern.
func (e *emitter) writeMTLS(m config.MTLSConfig) {
	mtlsKey := rootKey + `\Vault\MTLS`
	e.writeKey(mtlsKey)
	e.writeString("BootstrapMethod", m.BootstrapMethod)
	e.writeString("BootstrapMount", m.BootstrapMount)
	e.writeString("CertMount", m.CertMount)
	e.writeString("CertRole", m.CertRole)
	e.writeString("PKIMount", m.PKIMount)
	e.writeString("PKIRole", m.PKIRole)
	e.writeString("KeyType", m.KeyType)
	e.writeString("CommonName", m.CommonName)
	e.writeString("TTL", m.TTL)
	e.writeString("ReissueBefore", m.ReissueBefore)
	e.writeString("StorageDir", m.StorageDir)
	e.writeBool("SealToPCRs", m.SealToPCRs)
	e.WriteString("\r\n")

	byoKey := mtlsKey + `\BYO`
	e.writeKey(byoKey)
	e.writeString("Cert", m.BYO.Cert)
	e.writeString("Key", m.BYO.Key)
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
	// LoginText / SecretViewText are markdown blobs that may span multiple
	// lines; writeString falls through to hex(1) when it spots a newline or
	// non-ASCII byte, so they round-trip the same way rule templates do.
	e.writeString("LoginText", w.LoginText)
	e.writeString("SecretViewText", w.SecretViewText)
	e.WriteString("\r\n")
}

// writeObservability emits the Observability section: the scalar fields,
// then the Headers map as a dedicated subkey.
//
// Headers routinely carry OTLP bearer tokens, but dotvault treats config
// conversion as lossless in every direction (mirroring
// ObservabilityConfig, which no longer strips them on YAML export), so they
// are emitted verbatim. Each header is a REG_SZ value under
// Observability\Headers named after the header key; header names are case
// preserved (HTTP folds case, but a faithful round-trip keeps the authored
// form). Like Rules / Enrolments / Agent\Keys the dynamic subtree is
// deleted before re-creation so a header removed from the source clears on
// re-import rather than lingering.
func (e *emitter) writeObservability(o config.ObservabilityConfig) {
	e.writeKey(rootKey + `\Observability`)
	e.writeBool("Enabled", o.Enabled)
	e.writeString("Endpoint", o.Endpoint)
	e.writeString("Protocol", o.Protocol)
	e.writeBool("Insecure", o.Insecure)
	// Emit RawInterval as the user wrote it (matching writeSync); the value
	// name mirrors the YAML key (export_interval) capitalised for the registry.
	e.writeString("ExportInterval", o.RawInterval)
	e.WriteString("\r\n")

	// Always pre-delete the Headers subtree so removals round-trip. No-op on
	// a registry that never had it.
	e.writeKeyDeletion(rootKey + `\Observability\Headers`)
	if len(o.Headers) == 0 {
		return
	}
	e.writeKey(rootKey + `\Observability\Headers`)
	names := make([]string, 0, len(o.Headers))
	for n := range o.Headers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		e.writeString(n, o.Headers[n])
	}
	e.WriteString("\r\n")
}

// writeRemoteConfig emits the RemoteConfig section: the scalar fields, then
// the Headers map as a dedicated subkey, following the Observability\Headers
// pattern exactly — the dynamic subtree is deleted before re-creation so a
// header removed from the source clears on re-import. Unlike observability
// headers these values are not credentials (they are client-asserted
// dimension labels like X-Dotvault-Env), but they share the same
// verbatim-name, lossless round-trip contract.
func (e *emitter) writeRemoteConfig(r config.RemoteConfig) {
	e.writeKey(rootKey + `\RemoteConfig`)
	e.writeString("URL", r.URL)
	// Emit RawRefreshInterval as the user wrote it (matching writeSync); the
	// value name mirrors the YAML key (refresh_interval) capitalised for the
	// registry.
	e.writeString("RefreshInterval", r.RawRefreshInterval)
	e.writeString("CACert", r.CACert)
	e.WriteString("\r\n")

	// Always pre-delete the Headers subtree so removals round-trip. No-op on
	// a registry that never had it.
	e.writeKeyDeletion(rootKey + `\RemoteConfig\Headers`)
	if len(r.Headers) == 0 {
		return
	}
	e.writeKey(rootKey + `\RemoteConfig\Headers`)
	names := make([]string, 0, len(r.Headers))
	for n := range r.Headers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		e.writeString(n, r.Headers[n])
	}
	e.WriteString("\r\n")
}

// writeAgent emits the Agent section: the scalar Enabled / Unix / Windows
// transport settings, plus an ordered Keys subtree. The keys list is
// dynamically sized, so — like Rules and Enrolments — the Keys subtree is
// deleted before re-creation so a key removed from YAML doesn't linger in the
// registry on re-import. List order is preserved by naming each key subkey
// after its zero-based index (`Keys\0`, `Keys\1`, …); the parser sorts those
// names numerically to rebuild the slice.
func (e *emitter) writeAgent(a config.AgentConfig) {
	e.writeKey(rootKey + `\Agent`)
	e.writeBool("Enabled", a.Enabled)
	e.writeString("UnixPath", a.Unix.Path)
	e.writeString("WindowsPipe", a.Windows.Pipe)
	// Putty is tri-state (default true): emit the DWORD only when explicitly
	// set so an unset value round-trips as the default rather than being
	// pinned to whatever the export observed.
	if a.Windows.Putty != nil {
		e.writeBool("WindowsPutty", *a.Windows.Putty)
	}
	e.WriteString("\r\n")

	// Always pre-delete the Keys subtree so removals round-trip. This is a
	// no-op on a registry that never had it.
	e.writeKeyDeletion(rootKey + `\Agent\Keys`)
	if len(a.Keys) == 0 {
		return
	}
	e.writeKey(rootKey + `\Agent\Keys`)
	e.WriteString("\r\n")
	for i, k := range a.Keys {
		e.writeAgentKey(i, k)
	}
}

func (e *emitter) writeAgentKey(index int, k config.AgentKeySource) {
	keyPath := fmt.Sprintf(`%s\Agent\Keys\%d`, rootKey, index)
	e.writeKey(keyPath)
	e.writeString("Source", k.Source)
	e.writeString("PathPrefix", k.PathPrefix)
	e.writeString("Mount", k.Mount)
	e.writeString("Role", k.Role)
	e.writeString("TTL", k.TTL)
	e.writeBool("EphemeralKey", k.EphemeralKey)
	// Emit Principals whenever non-nil so an explicit empty list round-trips
	// as an empty REG_MULTI_SZ rather than being silently dropped, matching
	// the OAuth Scopes treatment.
	if k.Principals != nil {
		e.writeMultiString("Principals", k.Principals)
	}
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
	e.writeSettingsBlock(name, enrolPath+`\Settings`, "", en.Settings)
}

// writeSettingsBlock emits a Settings (or nested settings) block as a
// registry key plus its scalar values, then recursively emits any
// nested-map values as further subkeys. settingPath is the dotted-key
// breadcrumb used in error messages so users can locate problematic
// entries in their YAML; the empty string means "top-level".
func (e *emitter) writeSettingsBlock(enrolment, keyPath, settingPath string, m map[string]any) {
	e.writeKey(keyPath)

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Emit scalar (and string-list) values first so the resulting .reg
	// file has a predictable shape: subkeys live at the bottom of each
	// section, matching how the Windows registry editor displays them.
	var nested []string
	for _, k := range keys {
		full := joinSettingPath(settingPath, k)
		switch v := m[k].(type) {
		case map[string]any:
			nested = append(nested, k)
		default:
			e.writeSetting(enrolment, full, k, v)
		}
	}
	e.WriteString("\r\n")

	for _, k := range nested {
		full := joinSettingPath(settingPath, k)
		sub := m[k].(map[string]any)
		if err := validateKeyName(k); err != nil {
			e.fail("enrolments[%q].settings[%q]: %w", enrolment, full, err)
			return
		}
		e.writeSettingsBlock(enrolment, keyPath+`\`+k, full, sub)
	}
}

func joinSettingPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// writeSetting emits a single scalar (or string-list) enrolment setting.
// Strings become REG_SZ; slices of strings become REG_MULTI_SZ. Nested
// maps are handled by writeSettingsBlock (subkey recursion), so they
// never reach this function.
//
// The registry reader only knows how to deserialise REG_SZ / REG_MULTI_SZ
// at any one level, so any other value type is treated as an error
// rather than silently dropped: a partial export that disagrees with
// the source YAML is worse than a hard failure.
//
// Empty lists are preserved as empty REG_MULTI_SZ rather than dropped:
// in YAML an explicit `[]` differs from an absent key, and engines that
// override defaults from the presence of a list (e.g. GitHub's `scopes`)
// rely on that distinction.
func (e *emitter) writeSetting(enrolment, settingPath, name string, value any) {
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
				e.fail("enrolments[%q].settings[%q][%d]: cannot represent %T in registry; only strings are supported", enrolment, settingPath, i, item)
				return
			}
			strs = append(strs, s)
		}
		e.writeMultiString(name, strs)
	default:
		e.fail("enrolments[%q].settings[%q]: cannot represent %T in registry; only strings, string lists, and nested maps are supported", enrolment, settingPath, value)
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
