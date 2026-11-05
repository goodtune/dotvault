package regfile

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/config"
)

// TestClientCertRegRoundTrip covers the client_cert section through the .reg
// render → parse cycle in both encodings, with every field set and with the
// RSA key size present or absent. The registry is the GPO surface for the
// whole configuration, so the section round-trips on every platform.
func TestClientCertRegRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		cc   config.ClientCertConfig
	}{
		{"every field set", config.ClientCertConfig{
			Enabled:    true,
			PKIMount:   "pki-clients",
			PKIRole:    "workstation",
			CommonName: "{{.os_user}}@example.com",
			RawTTL:     "10m",
			KeyType:    "rsa",
			KeyBits:    3072,
		}},
		{"ec with no key bits", config.ClientCertConfig{
			Enabled: true,
			PKIRole: "workstation",
			KeyType: "ec",
		}},
		{"enabled with defaults", config.ClientCertConfig{Enabled: true}},
		{"disabled", config.ClientCertConfig{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := validBaseConfig()
			src.ClientCert = tc.cc

			text, err := GenerateText(src)
			if err != nil {
				t.Fatalf("GenerateText: %v", err)
			}
			got, err := Parse([]byte(text))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(got.ClientCert, src.ClientCert) {
				t.Errorf("ClientCert mismatch:\ngot:  %+v\nwant: %+v", got.ClientCert, src.ClientCert)
			}

			data, err := Generate(src)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			got, err = Parse(data)
			if err != nil {
				t.Fatalf("Parse (utf16): %v", err)
			}
			if !reflect.DeepEqual(got.ClientCert, src.ClientCert) {
				t.Errorf("ClientCert mismatch (utf16):\ngot:  %+v\nwant: %+v", got.ClientCert, src.ClientCert)
			}
		})
	}
}

// TestClientCertRegClearsEmpty confirms optional strings are emitted even
// when empty, so a re-import blanks a value a previous policy set, and that
// the raw TTL string (not the parsed duration) is what is written.
func TestClientCertRegClearsEmpty(t *testing.T) {
	src := validBaseConfig()
	src.ClientCert = config.ClientCertConfig{Enabled: true}

	text, err := GenerateText(src)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	if !strings.Contains(text, `\dotvault\ClientCert]`) {
		t.Fatalf("expected a [ClientCert] key\n%s", text)
	}
	for _, want := range []string{
		`"PKIMount"=""`, `"PKIRole"=""`, `"CommonName"=""`, `"TTL"=""`, `"KeyType"=""`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %s to be emitted so a re-import clears it\n%s", want, text)
		}
	}
	// vault.mtls has its own KeyBits, so look only inside this section.
	section := text[strings.Index(text, `\dotvault\ClientCert]`):]
	if end := strings.Index(section, "\r\n\r\n"); end >= 0 {
		section = section[:end]
	}
	if strings.Contains(section, `"KeyBits"`) {
		t.Errorf("KeyBits must be omitted when zero\n%s", section)
	}
}

// TestClientCertRegDropsStaleKeyBits confirms the key is deleted before it is
// recreated, so omitting KeyBits on re-import removes a value an earlier
// import left behind rather than leaving it in force.
func TestClientCertRegDropsStaleKeyBits(t *testing.T) {
	src := validBaseConfig()
	src.ClientCert = config.ClientCertConfig{Enabled: true}

	text, err := GenerateText(src)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	del := strings.Index(text, `[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\ClientCert]`)
	add := strings.Index(text, `[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\goodtune\dotvault\ClientCert]`)
	if del < 0 || add < 0 || del > add {
		t.Fatalf("expected the ClientCert key to be deleted before it is recreated (del=%d add=%d)\n%s", del, add, text)
	}
}

// TestClientCertYAMLRoundTrip drives the full reg -> YAML -> config.Load path
// the CLI and the web download endpoint use. Comparison is after validation,
// which fills KeyType and the parsed TTL in place.
func TestClientCertYAMLRoundTrip(t *testing.T) {
	src := validBaseConfig()
	src.ClientCert = config.ClientCertConfig{
		Enabled:    true,
		PKIMount:   "pki-clients",
		PKIRole:    "workstation",
		CommonName: "{{.os_user}}",
		RawTTL:     "10m",
		KeyType:    "rsa",
		KeyBits:    4096,
	}

	text, err := GenerateText(src)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	parsed, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	y, err := MarshalYAML(parsed)
	if err != nil {
		t.Fatalf("MarshalYAML: %v", err)
	}
	if !strings.Contains(string(y), "client_cert:") {
		t.Fatalf("expected client_cert in canonical YAML\n%s", y)
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, y, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v\n%s", err, y)
	}
	want := src.ClientCert
	want.TTL = 10 * time.Minute
	if !reflect.DeepEqual(loaded.ClientCert, want) {
		t.Errorf("ClientCert after YAML round trip:\ngot:  %+v\nwant: %+v", loaded.ClientCert, want)
	}
}

// With the section absent, nothing about it appears in the canonical YAML.
func TestClientCertAbsentFromYAMLWhenUnused(t *testing.T) {
	y, err := MarshalYAML(validBaseConfig())
	if err != nil {
		t.Fatalf("MarshalYAML: %v", err)
	}
	if strings.Contains(string(y), "client_cert") {
		t.Errorf("unused client_cert should not appear in YAML\n%s", y)
	}
}
