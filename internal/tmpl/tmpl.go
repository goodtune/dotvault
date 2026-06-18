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
// The data map is the dot context. The {{ username }} function returns the
// empty string; use RenderWithUsername to make a real identity available.
func Render(name, tmplStr string, data map[string]any) (string, error) {
	return render(name, tmplStr, data, "")
}

// RenderWithUsername is Render with the {{ username }} function bound to the
// supplied identity. The sync engine passes the OS account the secrets are
// laid out under (kv/users/<username>/...), so a rule template can build paths
// like /home/{{ username }}/.ssh/dotvault.sock without the username having to be
// a field in the Vault secret.
func RenderWithUsername(name, tmplStr string, data map[string]any, username string) (string, error) {
	return render(name, tmplStr, data, username)
}

func render(name, tmplStr string, data map[string]any, username string) (string, error) {
	funcs := template.FuncMap{
		"env":          envFunc,
		"base64encode": base64EncodeFunc,
		"base64decode": base64DecodeFunc,
		"default":      defaultFunc,
		"quote":        quoteFunc,
		"username":     func() string { return username },
	}

	t, err := template.New(name).Funcs(funcs).Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("parse template %s: %w", name, err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template %s: %w", name, err)
	}

	return buf.String(), nil
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
