package handlers

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// TOMLHandler handles TOML files with deep merge.
type TOMLHandler struct{}

func (h *TOMLHandler) Read(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		return map[string]any{}, nil
	}

	m, err := parseTOML(string(data))
	if err != nil {
		return nil, fmt.Errorf("parse toml %s: %w", path, err)
	}
	return m, nil
}

func (h *TOMLHandler) Parse(content string) (any, error) {
	if content == "" {
		return map[string]any{}, nil
	}
	m, err := parseTOML(content)
	if err != nil {
		return nil, fmt.Errorf("parse toml content: %w", err)
	}
	return m, nil
}

func (h *TOMLHandler) Merge(existing any, incoming any) (any, error) {
	dst, ok := existing.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("existing: expected map[string]any, got %T", existing)
	}
	src, ok := incoming.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("incoming: expected map[string]any, got %T", incoming)
	}

	return deepMergeTOML(dst, src), nil
}

func (h *TOMLHandler) Write(path string, data any, perm os.FileMode) error {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("expected map[string]any, got %T", data)
	}

	var buf bytes.Buffer
	if err := encodeTOML(&buf, m, ""); err != nil {
		return fmt.Errorf("marshal toml: %w", err)
	}

	return atomicWrite(path, buf.Bytes(), perm)
}

// deepMergeTOML recursively merges src into dst.
func deepMergeTOML(dst, src map[string]any) map[string]any {
	for key, srcVal := range src {
		dstVal, exists := dst[key]
		if !exists {
			dst[key] = srcVal
			continue
		}

		dstMap, dstOk := dstVal.(map[string]any)
		srcMap, srcOk := srcVal.(map[string]any)
		if dstOk && srcOk {
			dst[key] = deepMergeTOML(dstMap, srcMap)
		} else {
			dst[key] = srcVal
		}
	}
	return dst
}

// parseTOML parses a TOML document into map[string]any.
func parseTOML(input string) (map[string]any, error) {
	root := make(map[string]any)
	current := root

	lines := strings.Split(input, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || line[0] == '#' {
			continue
		}

		// Table header [section] or [section.subsection]
		if line[0] == '[' {
			// Array of tables [[...]]
			if strings.HasPrefix(line, "[[") {
				if len(line) < 4 || !strings.HasSuffix(line, "]]") {
					return nil, fmt.Errorf("line %d: unterminated array of tables", i+1)
				}
				name := strings.TrimSpace(line[2 : len(line)-2])
				parts := splitTOMLKey(name)
				parent := root
				for _, p := range parts[:len(parts)-1] {
					parent = ensureTable(parent, p)
				}
				last := parts[len(parts)-1]
				arr, _ := parent[last].([]any)
				newTable := make(map[string]any)
				parent[last] = append(arr, newTable)
				current = newTable
				continue
			}

			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("line %d: unterminated table header", i+1)
			}
			name := strings.TrimSpace(line[1 : len(line)-1])
			parts := splitTOMLKey(name)
			current = root
			for _, p := range parts {
				current = ensureTable(current, p)
			}
			continue
		}

		// Key = Value
		eqIdx := strings.Index(line, "=")
		if eqIdx < 0 {
			return nil, fmt.Errorf("line %d: expected key = value", i+1)
		}

		key := strings.TrimSpace(line[:eqIdx])
		valStr := strings.TrimSpace(line[eqIdx+1:])

		// Handle dotted keys
		parts := splitTOMLKey(key)
		target := current
		for _, p := range parts[:len(parts)-1] {
			target = ensureTable(target, p)
		}

		val, err := parseTOMLValue(valStr)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		target[parts[len(parts)-1]] = val
	}

	return root, nil
}

func ensureTable(m map[string]any, key string) map[string]any {
	if v, ok := m[key]; ok {
		if tbl, ok := v.(map[string]any); ok {
			return tbl
		}
	}
	tbl := make(map[string]any)
	m[key] = tbl
	return tbl
}

func splitTOMLKey(key string) []string {
	// Handle quoted keys and dotted keys
	var parts []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(key); i++ {
		ch := key[i]
		if inQuote {
			if ch == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(ch)
			}
		} else if ch == '"' || ch == '\'' {
			inQuote = true
			quoteChar = ch
		} else if ch == '.' {
			parts = append(parts, strings.TrimSpace(current.String()))
			current.Reset()
		} else {
			current.WriteByte(ch)
		}
	}
	parts = append(parts, strings.TrimSpace(current.String()))
	return parts
}

func parseTOMLValue(s string) (any, error) {
	if s == "" {
		return "", nil
	}

	// Strip inline comment (not inside strings)
	s = stripInlineComment(s)

	// Boolean
	if s == "true" {
		return true, nil
	}
	if s == "false" {
		return false, nil
	}

	// String (basic or literal)
	if strings.HasPrefix(s, `"""`) {
		end := strings.Index(s[3:], `"""`)
		if end < 0 {
			return nil, fmt.Errorf("unterminated multi-line basic string")
		}
		return s[3 : 3+end], nil
	}
	if strings.HasPrefix(s, "'''") {
		end := strings.Index(s[3:], "'''")
		if end < 0 {
			return nil, fmt.Errorf("unterminated multi-line literal string")
		}
		return s[3 : 3+end], nil
	}
	if s[0] == '"' {
		end := strings.LastIndex(s[1:], `"`)
		if end < 0 {
			return nil, fmt.Errorf("unterminated basic string")
		}
		return unescapeTOMLString(s[1 : 1+end]), nil
	}
	if s[0] == '\'' {
		end := strings.LastIndex(s[1:], "'")
		if end < 0 {
			return nil, fmt.Errorf("unterminated literal string")
		}
		return s[1 : 1+end], nil
	}

	// Inline array
	if s[0] == '[' {
		return parseTOMLArray(s)
	}

	// Inline table
	if s[0] == '{' {
		return parseTOMLInlineTable(s)
	}

	// Integer (try before float)
	cleaned := strings.ReplaceAll(s, "_", "")
	if isIntegerStr(s) {
		// Handle hex, octal, binary prefixes
		if strings.HasPrefix(cleaned, "0x") || strings.HasPrefix(cleaned, "0X") ||
			strings.HasPrefix(cleaned, "+0x") || strings.HasPrefix(cleaned, "-0x") {
			n, err := strconv.ParseInt(strings.TrimPrefix(strings.TrimPrefix(cleaned, "+"), "-"), 0, 64)
			if err == nil {
				if strings.HasPrefix(cleaned, "-") {
					return -n, nil
				}
				return n, nil
			}
		} else if strings.HasPrefix(cleaned, "0o") || strings.HasPrefix(cleaned, "0O") {
			n, err := strconv.ParseInt("0"+cleaned[2:], 0, 64)
			if err == nil {
				return n, nil
			}
		} else if strings.HasPrefix(cleaned, "0b") || strings.HasPrefix(cleaned, "0B") {
			n, err := strconv.ParseInt(cleaned, 0, 64)
			if err == nil {
				return n, nil
			}
		} else {
			n, err := strconv.ParseInt(cleaned, 10, 64)
			if err == nil {
				return n, nil
			}
		}
	}

	// Float
	if isFloatStr(s) {
		f, err := strconv.ParseFloat(cleaned, 64)
		if err == nil {
			return f, nil
		}
	}

	// Bare value — treat as string
	return s, nil
}

func stripInlineComment(s string) string {
	inStr := false
	strChar := byte(0)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inStr {
			if ch == '\\' {
				i++ // skip escaped char
				continue
			}
			if ch == strChar {
				inStr = false
			}
		} else {
			if ch == '"' || ch == '\'' {
				inStr = true
				strChar = ch
			} else if ch == '#' {
				return strings.TrimSpace(s[:i])
			}
		}
	}
	return s
}

func unescapeTOMLString(s string) string {
	s = strings.ReplaceAll(s, `\\`, "\x00BACKSLASH\x00")
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, `\t`, "\t")
	s = strings.ReplaceAll(s, `\r`, "\r")
	s = strings.ReplaceAll(s, "\x00BACKSLASH\x00", `\`)
	return s
}

func isIntegerStr(s string) bool {
	if len(s) == 0 {
		return false
	}
	start := 0
	if s[0] == '+' || s[0] == '-' {
		start = 1
	}
	if start >= len(s) {
		return false
	}
	// Hex, octal, binary
	if start+1 < len(s) && s[start] == '0' {
		prefix := s[start : start+2]
		if prefix == "0x" || prefix == "0o" || prefix == "0b" {
			return true
		}
	}
	for i := start; i < len(s); i++ {
		if s[i] == '_' {
			continue
		}
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isFloatStr(s string) bool {
	if s == "inf" || s == "+inf" || s == "-inf" || s == "nan" || s == "+nan" || s == "-nan" {
		return true
	}
	hasDot := false
	hasE := false
	for _, ch := range s {
		if ch == '.' {
			hasDot = true
		}
		if ch == 'e' || ch == 'E' {
			hasE = true
		}
	}
	return hasDot || hasE
}

func parseTOMLArray(s string) ([]any, error) {
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		return nil, fmt.Errorf("invalid array: %s", s)
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	if inner == "" {
		return []any{}, nil
	}

	var result []any
	for _, elem := range splitTOMLElements(inner) {
		elem = strings.TrimSpace(elem)
		if elem == "" {
			continue
		}
		val, err := parseTOMLValue(elem)
		if err != nil {
			return nil, err
		}
		result = append(result, val)
	}
	return result, nil
}

func parseTOMLInlineTable(s string) (map[string]any, error) {
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return nil, fmt.Errorf("invalid inline table: %s", s)
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	if inner == "" {
		return map[string]any{}, nil
	}

	result := make(map[string]any)
	for _, elem := range splitTOMLElements(inner) {
		elem = strings.TrimSpace(elem)
		if elem == "" {
			continue
		}
		eqIdx := strings.Index(elem, "=")
		if eqIdx < 0 {
			return nil, fmt.Errorf("inline table: expected key = value in %q", elem)
		}
		key := strings.TrimSpace(elem[:eqIdx])
		valStr := strings.TrimSpace(elem[eqIdx+1:])
		val, err := parseTOMLValue(valStr)
		if err != nil {
			return nil, err
		}
		result[key] = val
	}
	return result, nil
}

// splitTOMLElements splits comma-separated elements respecting nesting.
func splitTOMLElements(s string) []string {
	var result []string
	depth := 0
	inStr := false
	strChar := byte(0)
	start := 0

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inStr {
			if ch == '\\' {
				i++
				continue
			}
			if ch == strChar {
				inStr = false
			}
		} else {
			switch ch {
			case '"', '\'':
				inStr = true
				strChar = ch
			case '[', '{':
				depth++
			case ']', '}':
				depth--
			case ',':
				if depth == 0 {
					result = append(result, s[start:i])
					start = i + 1
				}
			}
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}

// encodeTOML serialises a map to TOML format.
func encodeTOML(buf *bytes.Buffer, m map[string]any, prefix string) error {
	// Sort keys for deterministic output
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Write scalar values first, then tables
	for _, k := range keys {
		v := m[k]
		switch val := v.(type) {
		case map[string]any:
			// Skip — handled after scalars
		case []any:
			// Check if it's an array of tables
			if isArrayOfTables(val) {
				continue
			}
			encodeTOMLKey(buf, k)
			buf.WriteString(" = ")
			encodeTOMLArrayValue(buf, val)
			buf.WriteByte('\n')
		default:
			encodeTOMLKey(buf, k)
			buf.WriteString(" = ")
			encodeTOMLScalar(buf, v)
			buf.WriteByte('\n')
		}
	}

	// Now write sub-tables
	for _, k := range keys {
		v := m[k]
		switch val := v.(type) {
		case map[string]any:
			fullKey := k
			if prefix != "" {
				fullKey = prefix + "." + k
			}
			buf.WriteByte('\n')
			buf.WriteString("[")
			buf.WriteString(fullKey)
			buf.WriteString("]\n")
			if err := encodeTOML(buf, val, fullKey); err != nil {
				return err
			}
		case []any:
			if isArrayOfTables(val) {
				fullKey := k
				if prefix != "" {
					fullKey = prefix + "." + k
				}
				for _, elem := range val {
					tbl := elem.(map[string]any)
					buf.WriteByte('\n')
					buf.WriteString("[[")
					buf.WriteString(fullKey)
					buf.WriteString("]]\n")
					if err := encodeTOML(buf, tbl, fullKey); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

func isArrayOfTables(arr []any) bool {
	if len(arr) == 0 {
		return false
	}
	for _, elem := range arr {
		if _, ok := elem.(map[string]any); !ok {
			return false
		}
	}
	return true
}

func encodeTOMLKey(buf *bytes.Buffer, key string) {
	// Use bare key if it only contains safe characters
	safe := true
	for _, ch := range key {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
			safe = false
			break
		}
	}
	if safe && len(key) > 0 {
		buf.WriteString(key)
	} else {
		buf.WriteByte('"')
		buf.WriteString(strings.ReplaceAll(key, `"`, `\"`))
		buf.WriteByte('"')
	}
}

func encodeTOMLScalar(buf *bytes.Buffer, v any) {
	switch val := v.(type) {
	case string:
		buf.WriteByte('"')
		s := val
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		s = strings.ReplaceAll(s, "\n", `\n`)
		s = strings.ReplaceAll(s, "\t", `\t`)
		s = strings.ReplaceAll(s, "\r", `\r`)
		buf.WriteString(s)
		buf.WriteByte('"')
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case int64:
		fmt.Fprintf(buf, "%d", val)
	case int:
		fmt.Fprintf(buf, "%d", val)
	case float64:
		fmt.Fprintf(buf, "%g", val)
	default:
		fmt.Fprintf(buf, "%v", val)
	}
}

func encodeTOMLArrayValue(buf *bytes.Buffer, arr []any) {
	buf.WriteByte('[')
	for i, elem := range arr {
		if i > 0 {
			buf.WriteString(", ")
		}
		switch val := elem.(type) {
		case map[string]any:
			buf.WriteByte('{')
			keys := make([]string, 0, len(val))
			for k := range val {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for j, k := range keys {
				if j > 0 {
					buf.WriteString(", ")
				}
				encodeTOMLKey(buf, k)
				buf.WriteString(" = ")
				encodeTOMLScalar(buf, val[k])
			}
			buf.WriteByte('}')
		default:
			encodeTOMLScalar(buf, elem)
		}
	}
	buf.WriteByte(']')
}
