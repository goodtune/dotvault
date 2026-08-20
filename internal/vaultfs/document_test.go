package vaultfs

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRenderDocumentIsStableAndNewlineTerminated(t *testing.T) {
	s := &Secret{
		Data:        map[string]any{"z": "last", "a": "first", "m": "middle"},
		Version:     3,
		CreatedTime: time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC),
	}
	first, err := renderDocument(s)
	if err != nil {
		t.Fatalf("renderDocument: %v", err)
	}
	second, err := renderDocument(s)
	if err != nil {
		t.Fatalf("renderDocument: %v", err)
	}
	if string(first.Bytes) != string(second.Bytes) {
		t.Error("rendering the same secret twice produced different bytes")
	}
	if !strings.HasSuffix(string(first.Bytes), "\n") {
		t.Error("rendered document does not end in a newline")
	}
	// Sorted keys are what make the output stable, and what stop anything
	// watching a synced file from seeing spurious changes.
	if a, m := strings.Index(string(first.Bytes), `"a"`), strings.Index(string(first.Bytes), `"m"`); a > m {
		t.Error("keys are not in sorted order")
	}
	if first.Version != 3 {
		t.Errorf("Version = %d, want 3", first.Version)
	}
}

func TestRenderDocumentHandlesNilData(t *testing.T) {
	doc, err := renderDocument(&Secret{})
	if err != nil {
		t.Fatalf("renderDocument: %v", err)
	}
	if got := strings.TrimSpace(string(doc.Bytes)); got != "{}" {
		t.Errorf("rendered nil data as %q, want {}", got)
	}
}

func TestParseDocumentRoundTripsNumbersLosslessly(t *testing.T) {
	// Decoding into float64 would turn these into 1e+06 and an approximation
	// of the large ID, so a read-modify-write through the mount would corrupt
	// values it never touched.
	data, err := parseDocument([]byte(`{"count": 1000000, "id": 9007199254740993}`))
	if err != nil {
		t.Fatalf("parseDocument: %v", err)
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)
	if !strings.Contains(got, "1000000") || !strings.Contains(got, "9007199254740993") {
		t.Errorf("re-marshalled as %s, want the original literals preserved", got)
	}
}

func TestParseDocumentRejections(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"whitespace only", "   \n\t "},
		{"not json", "not json"},
		{"json null", "null"},
		{"json array", `["a","b"]`},
		{"json string", `"just a string"`},
		{"json number", `42`},
		{"empty object", `{}`},
		{"trailing content", `{"a":"b"} {"c":"d"}`},
		{"truncated", `{"a":`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseDocument([]byte(tc.input))
			if !errors.Is(err, ErrInvalidDocument) {
				t.Errorf("parseDocument(%q) error = %v, want ErrInvalidDocument", tc.input, err)
			}
		})
	}
}

// The bytes being rejected are secret material, so the error must not quote
// them — it travels into log lines and into the daemon's diagnostics.
func TestParseDocumentErrorCarriesNoContent(t *testing.T) {
	const secret = "gho_super_secret_value"
	_, err := parseDocument([]byte(`{"token": "` + secret + `"` + "\n"))
	if err == nil {
		t.Fatal("expected an error for a truncated document")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error quotes the rejected content: %v", err)
	}
}

func TestParseDocumentAcceptsAnObject(t *testing.T) {
	data, err := parseDocument([]byte("  {\"a\": \"b\", \"c\": true}\n\n"))
	if err != nil {
		t.Fatalf("parseDocument: %v", err)
	}
	if len(data) != 2 || data["a"] != "b" || data["c"] != true {
		t.Errorf("parsed = %v, want {a: b, c: true}", data)
	}
}
