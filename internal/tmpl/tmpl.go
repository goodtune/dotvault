package tmpl

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"text/template"
)

// Render parses and executes a Go template with custom functions.
// The data map is the dot context.
func Render(name, tmplStr string, data map[string]any) (string, error) {
	t, err := template.New(name).Funcs(funcMap).Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("parse template %s: %w", name, err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template %s: %w", name, err)
	}

	return buf.String(), nil
}

var funcMap = template.FuncMap{
	"env":          envFunc,
	"base64encode": base64EncodeFunc,
	"base64decode": base64DecodeFunc,
	"default":      defaultFunc,
	"quote":        quoteFunc,
}

func envFunc(key string) string {
	return os.Getenv(key)
}

func base64EncodeFunc(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func base64DecodeFunc(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("base64decode: %w", err)
	}
	return string(b), nil
}

// defaultFunc follows Sprig convention: fallback first, value second.
// This enables idiomatic piping: {{.port | default "8080"}}
func defaultFunc(fallback string, val any) string {
	if val == nil {
		return fallback
	}
	s := fmt.Sprintf("%v", val)
	if s == "" || s == "<no value>" {
		return fallback
	}
	return s
}

func quoteFunc(s string) string {
	// Shell-safe single quoting: wrap in single quotes,
	// escape embedded single quotes with '"'"'
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
