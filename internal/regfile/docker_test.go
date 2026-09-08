package regfile

import (
	"reflect"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// TestDockerRoundTrip covers the volume plugin section through the .reg
// render → parse cycle in both encodings. Like FUSE, it configures a surface
// Windows cannot serve and round-trips there all the same, because the
// registry is the GPO surface for the whole configuration.
func TestDockerRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		docker config.DockerConfig
	}{
		{"enabled with explicit paths", config.DockerConfig{
			Enabled:     true,
			Socket:      "/run/user/1000/dotvault/docker.sock",
			VolumeDir:   "~/.cache/dotvault/volumes",
			RawCacheTTL: "2m",
		}},
		{"enabled with defaults", config.DockerConfig{Enabled: true}},
		{"disabled", config.DockerConfig{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := validBaseConfig()
			src.Docker = tc.docker

			text, err := GenerateText(src)
			if err != nil {
				t.Fatalf("GenerateText: %v", err)
			}
			got, err := Parse([]byte(text))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(got.Docker, src.Docker) {
				t.Errorf("Docker mismatch:\ngot:  %+v\nwant: %+v", got.Docker, src.Docker)
			}

			data, err := Generate(src)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			got, err = Parse(data)
			if err != nil {
				t.Fatalf("Parse (utf16): %v", err)
			}
			if !reflect.DeepEqual(got.Docker, src.Docker) {
				t.Errorf("Docker mismatch (utf16):\ngot:  %+v\nwant: %+v", got.Docker, src.Docker)
			}
		})
	}
}

// Optional strings are emitted even when empty so a re-import clears a value
// a previous policy set, and the raw duration string is what round-trips.
func TestDockerClearedValuesRoundTrip(t *testing.T) {
	src := validBaseConfig()
	src.Docker = config.DockerConfig{Enabled: true}

	text, err := GenerateText(src)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	if !strings.Contains(text, `\dotvault\Docker]`) {
		t.Fatalf("expected a [Docker] key\n%s", text)
	}
	for _, want := range []string{`"Socket"=""`, `"VolumeDir"=""`, `"CacheTTL"=""`} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %s to be emitted so a re-import clears it\n%s", want, text)
		}
	}
}
