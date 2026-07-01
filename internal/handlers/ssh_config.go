package handlers

import (
	"fmt"
	"os"
	"strings"
)

// SSHConfigHandler handles OpenSSH client configuration files (typically
// ~/.ssh/config) with a surgical, directive-level merge.
//
// The format is the one documented in ssh_config(5): line-oriented, with
// keywords that are case-insensitive in the keyword position and arguments
// separated from the keyword by whitespace or an optional "=". Directives are
// grouped into sections introduced by a "Host" or "Match" line; directives
// that precede the first such line form an implicit global section that applies
// to every host.
//
// SSHConfigHandler only ever touches the directives named by the incoming
// (template-rendered) document. Comments, blank lines, and every directive or
// Host/Match block the incoming document does not mention are preserved
// verbatim and in place, so a user's hand-maintained config survives a sync
// untouched except for the fields dotvault manages. Because there is no natural
// mapping from raw Vault key/value data to ssh_config directives, this handler
// is template-only: a rule using format "ssh_config" must supply a template.
// Merging anything other than parsed ssh_config content returns a clear error.
type SSHConfigHandler struct{}

// sshConfig is the parsed, mergeable representation of an ssh_config file.
type sshConfig struct {
	blocks []*sshBlock
}

// sshBlock is a Host/Match section, or the implicit global section that holds
// directives appearing before the first Host/Match line (header == nil).
type sshBlock struct {
	header *sshLine   // the "Host ..."/"Match ..." line; nil for the global block
	lines  []*sshLine // directives, comments, and blank lines within the section
}

// sshLine is one physical line. Comment and blank lines keep raw verbatim and
// have an empty keyword. Directive lines parse out keyword/args but also retain
// raw so an untouched line round-trips byte-for-byte; only when dirty is set
// (the merge changed or synthesised the line) is the line re-rendered from its
// fields.
type sshLine struct {
	raw     string // original text without trailing newline; authoritative when !dirty
	indent  string // leading whitespace
	keyword string // "" for comment and blank lines
	args    string // argument text following the keyword, surrounding space trimmed
	dirty   bool   // set when the line was created or updated by Merge
}

// multiValued lists the lowercased keywords that legitimately appear more than
// once within a single section, accumulating rather than overriding. For these
// a directive's identity for merge purposes includes a discriminator derived
// from its arguments (see directiveKey), so distinct entries coexist while a
// repeated sync of the same logical entry updates in place. Every other keyword
// is single-valued: a second occurrence replaces the first.
var multiValued = map[string]bool{
	"identityfile":     true,
	"certificatefile":  true,
	"localforward":     true,
	"remoteforward":    true,
	"dynamicforward":   true,
	"sendenv":          true,
	"setenv":           true,
	"include":          true,
	"permitremoteopen": true,
}

func (h *SSHConfigHandler) Read(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &sshConfig{blocks: []*sshBlock{{}}}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return parseSSHConfig(string(data)), nil
}

func (h *SSHConfigHandler) Parse(content string) (any, error) {
	return parseSSHConfig(content), nil
}

func (h *SSHConfigHandler) Merge(existing any, incoming any) (any, error) {
	dst, ok := existing.(*sshConfig)
	if !ok {
		return nil, fmt.Errorf("existing: expected *sshConfig, got %T", existing)
	}
	src, ok := incoming.(*sshConfig)
	if !ok {
		return nil, fmt.Errorf("incoming: expected *sshConfig, got %T (format \"ssh_config\" requires a template)", incoming)
	}

	for _, srcBlock := range src.blocks {
		dstBlock := dst.findBlock(srcBlock)
		if dstBlock == nil {
			dst.blocks = append(dst.blocks, cloneBlock(srcBlock))
			continue
		}
		mergeDirectives(dstBlock, srcBlock)
	}
	return dst, nil
}

func (h *SSHConfigHandler) Write(path string, data any, perm os.FileMode) error {
	cfg, ok := data.(*sshConfig)
	if !ok {
		return fmt.Errorf("expected *sshConfig, got %T", data)
	}
	return atomicWrite(path, []byte(cfg.render()), perm)
}

// parseSSHConfig splits content into sections. The first section is always the
// implicit global block (header == nil); a Host or Match keyword starts a new
// section. Comments and blank lines attach to the section they appear in so
// they round-trip in place.
func parseSSHConfig(content string) *sshConfig {
	cfg := &sshConfig{}
	current := &sshBlock{} // global section
	cfg.blocks = append(cfg.blocks, current)

	if content == "" {
		return cfg
	}

	// Normalise away a trailing newline so we don't emit a phantom blank line;
	// render re-adds a newline per line.
	body := strings.TrimSuffix(content, "\n")
	body = strings.TrimSuffix(body, "\r")
	for _, raw := range splitLines(body) {
		line := parseLine(raw)
		kw := strings.ToLower(line.keyword)
		if kw == "host" || kw == "match" {
			current = &sshBlock{header: line}
			cfg.blocks = append(cfg.blocks, current)
			continue
		}
		current.lines = append(current.lines, line)
	}
	return cfg
}

// splitLines splits on "\n" and strips a trailing "\r" from each line so CRLF
// files parse cleanly; render always emits "\n".
func splitLines(s string) []string {
	parts := strings.Split(s, "\n")
	for i, p := range parts {
		parts[i] = strings.TrimSuffix(p, "\r")
	}
	return parts
}

// parseLine turns one physical line into an sshLine. Blank lines and comments
// (first non-space rune is '#') keep an empty keyword and are reproduced
// verbatim. Directive lines capture indentation, the keyword, and the argument
// text; the keyword/argument separator may be whitespace, "=", or " = ".
func parseLine(raw string) *sshLine {
	indent := raw[:len(raw)-len(strings.TrimLeft(raw, " \t"))]
	rest := raw[len(indent):]

	if rest == "" || strings.HasPrefix(rest, "#") {
		return &sshLine{raw: raw, indent: indent}
	}

	// Keyword runs until the first whitespace or '='.
	end := strings.IndexAny(rest, " \t=")
	if end == -1 {
		// Bare keyword with no arguments.
		return &sshLine{raw: raw, indent: indent, keyword: rest}
	}
	keyword := rest[:end]
	args := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest[end:]), "="))
	return &sshLine{raw: raw, indent: indent, keyword: keyword, args: args}
}

// render serialises a parsed config back to text, one newline-terminated line
// per node. Untouched lines emit their original raw text; merged lines are
// rebuilt from fields with a single-space separator.
func (c *sshConfig) render() string {
	var b strings.Builder
	for _, blk := range c.blocks {
		if blk.header != nil {
			b.WriteString(blk.header.render())
			b.WriteByte('\n')
		}
		for _, ln := range blk.lines {
			b.WriteString(ln.render())
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func (l *sshLine) render() string {
	if !l.dirty {
		return l.raw
	}
	if l.args == "" {
		return l.indent + l.keyword
	}
	return l.indent + l.keyword + " " + l.args
}

// isDirective reports whether the line carries a keyword (as opposed to a
// comment or blank line).
func (l *sshLine) isDirective() bool { return l.keyword != "" }

// findBlock locates the section in c that has the same identity as want: the
// global block matches the global block, and a Host/Match block matches one
// whose keyword and whitespace-collapsed argument list are identical.
func (c *sshConfig) findBlock(want *sshBlock) *sshBlock {
	for _, b := range c.blocks {
		if blockKey(b) == blockKey(want) {
			return b
		}
	}
	return nil
}

// blockKey is the merge identity of a section. The global block keys on a fixed
// sentinel; a Host/Match block keys on its lowercased keyword plus its
// arguments with internal whitespace collapsed, so "Host  *" and "Host *" merge
// but "Host *" and "Host foo" do not.
func blockKey(b *sshBlock) string {
	if b.header == nil {
		return "\x00global"
	}
	return strings.ToLower(b.header.keyword) + " " + collapseSpaces(b.header.args)
}

func collapseSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// mergeDirectives applies every directive in src onto dst in place. A directive
// already present in dst (matched by directiveKey) has its arguments updated,
// preserving the existing line's indentation; a directive not present is
// inserted after the last existing directive in the section so it groups with
// the section's real content rather than landing past trailing comments.
//
// Only directive lines are applied: comments and blank lines in src are ignored
// when merging into an existing dst section (the existing file's own comments
// are what we preserve). Comments in a section that does not yet exist in dst do
// survive, because such a section is cloned wholesale by cloneBlock rather than
// routed through here.
func mergeDirectives(dst, src *sshBlock) {
	for _, srcLine := range src.lines {
		if !srcLine.isDirective() {
			continue
		}
		key := directiveKey(srcLine)
		if existing := findDirective(dst, key); existing != nil {
			existing.args = srcLine.args
			existing.dirty = true
			continue
		}
		insertDirective(dst, srcLine)
	}
}

// findDirective returns the directive in b whose key matches, or nil.
func findDirective(b *sshBlock, key string) *sshLine {
	for _, l := range b.lines {
		if l.isDirective() && directiveKey(l) == key {
			return l
		}
	}
	return nil
}

// directiveKey is the merge identity of a directive. Single-valued keywords key
// on the keyword alone, so a second occurrence overrides the first. Multi-valued
// keywords append a discriminator drawn from their arguments so independent
// entries coexist while a repeat of the same logical entry updates in place:
//   - setenv keys on the variable name (text before the first '='), so
//     "SetEnv FOO=old" is replaced by "SetEnv FOO=new";
//   - every other multi-valued keyword keys on its first whitespace-delimited
//     argument (a forward's listen spec, an IdentityFile's path, etc.).
//
// Consequence (documented in docs/configuration/sync-rules.md): because the
// discriminator IS the identity, a render that changes the discriminator itself
// (e.g. a RemoteForward whose listen spec moves) is a *new* directive — it is
// appended and the old line is left orphaned, not rewritten. This coexistence
// is intentional (managed and hand-added forwards live side by side); a rewrite
// of the discriminator is not expressible and is a deliberate non-goal. Keep the
// discriminator stable in templates (interpolate the forward target, not its
// listen spec; use the stable {{ username }} for username-bearing paths).
func directiveKey(l *sshLine) string {
	kw := strings.ToLower(l.keyword)
	if !multiValued[kw] {
		return kw
	}
	first := firstField(l.args)
	if kw == "setenv" {
		if i := strings.IndexByte(first, '='); i >= 0 {
			first = first[:i]
		}
	}
	return kw + "\x00" + first
}

func firstField(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// insertDirective places a new directive into b. It is rendered fresh (dirty)
// so its indentation matches the section: existing directives' indentation if
// the section already has any, otherwise the incoming line's own indentation
// (letting a template author control the style of a brand-new section).
//
// Position: if the section already has directives, the new line goes
// immediately after the last of them so it stays grouped with the section body,
// ahead of any trailing comments or blank lines. If the section has no
// directives at all (e.g. a global block holding only a file-header comment),
// it is appended at the end so the directive lands below those comments rather
// than displacing them to the top of the file.
func insertDirective(b *sshBlock, src *sshLine) {
	indent := src.indent
	lastDirective := -1
	for i, l := range b.lines {
		if l.isDirective() {
			indent = l.indent
			lastDirective = i
		}
	}

	newLine := &sshLine{
		indent:  indent,
		keyword: src.keyword,
		args:    src.args,
		dirty:   true,
	}

	pos := len(b.lines)
	if lastDirective >= 0 {
		pos = lastDirective + 1
	}
	b.lines = append(b.lines, nil)
	copy(b.lines[pos+1:], b.lines[pos:])
	b.lines[pos] = newLine
}

// cloneBlock deep-copies a section so appending an incoming block to the
// existing document doesn't alias the incoming parse tree. Lines are marked
// dirty so they render from fields with normalised spacing.
func cloneBlock(src *sshBlock) *sshBlock {
	dst := &sshBlock{}
	if src.header != nil {
		dst.header = cloneLineDirty(src.header)
	}
	for _, l := range src.lines {
		if l.isDirective() {
			dst.lines = append(dst.lines, cloneLineDirty(l))
		} else {
			// Preserve comments/blanks verbatim.
			cp := *l
			dst.lines = append(dst.lines, &cp)
		}
	}
	return dst
}

func cloneLineDirty(src *sshLine) *sshLine {
	return &sshLine{
		indent:  src.indent,
		keyword: src.keyword,
		args:    src.args,
		dirty:   true,
	}
}
