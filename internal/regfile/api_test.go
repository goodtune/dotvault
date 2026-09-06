package regfile

import (
	"reflect"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// TestAPIRoundTrip covers the local API socket section through the .reg
// render → parse cycle, in both encodings. The section is two scalars, but it
// is the surface a GPO-managed Windows host would configure the borrow
// endpoint through, so it has to survive the trip like every other section.
func TestAPIRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		api  config.APIConfig
	}{
		{"enabled with explicit path", config.APIConfig{
			Enabled: true,
			Unix:    config.APIUnixConfig{Path: "/run/user/1000/dotvault/api.sock"},
		}},
		{"enabled with default path", config.APIConfig{Enabled: true}},
		{"disabled", config.APIConfig{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := validBaseConfig()
			src.API = tc.api

			text, err := GenerateText(src)
			if err != nil {
				t.Fatalf("GenerateText: %v", err)
			}
			got, err := Parse([]byte(text))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(got.API, src.API) {
				t.Errorf("API mismatch:\ngot:  %+v\nwant: %+v", got.API, src.API)
			}

			// UTF-16 form too — the canonical encoding regedit produces.
			data, err := Generate(src)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			got, err = Parse(data)
			if err != nil {
				t.Fatalf("Parse (utf16): %v", err)
			}
			if !reflect.DeepEqual(got.API, src.API) {
				t.Errorf("API mismatch (utf16):\ngot:  %+v\nwant: %+v", got.API, src.API)
			}
		})
	}
}

// TestAPIClearedPathRoundTrips is the reason UnixPath is emitted even when
// empty: re-importing an export must be able to blank a path a previous
// policy set, rather than leaving the stale value in the registry.
func TestAPIClearedPathRoundTrips(t *testing.T) {
	src := validBaseConfig()
	src.API = config.APIConfig{Enabled: true}

	text, err := GenerateText(src)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	if !strings.Contains(text, `\dotvault\API]`) {
		t.Fatalf("expected an [API] key\n%s", text)
	}
	if !strings.Contains(text, `"UnixPath"=""`) {
		t.Errorf("expected UnixPath to be emitted as an empty string so a re-import clears it\n%s", text)
	}
}
