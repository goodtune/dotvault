package regfile

import (
	"reflect"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// TestFUSERoundTrip covers the filesystem section through the .reg render →
// parse cycle in both encodings.
//
// The section configures a surface Windows cannot mount, and it round-trips
// there all the same: the registry is the GPO deployment surface for the whole
// configuration, so an admin managing a mixed fleet from one policy has to be
// able to set it for the Linux and macOS machines that policy also covers.
func TestFUSERoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		fuse config.FUSEConfig
	}{
		{"enabled with explicit mountpoint", config.FUSEConfig{
			Enabled:     true,
			Mountpoint:  "/home/gary/secrets",
			RawCacheTTL: "1m",
		}},
		{"enabled read-write", config.FUSEConfig{
			Enabled:     true,
			Mountpoint:  "~/.dotvault",
			ReadWrite:   true,
			RawCacheTTL: "5s",
		}},
		{"enabled with defaults", config.FUSEConfig{Enabled: true}},
		{"caching disabled", config.FUSEConfig{Enabled: true, RawCacheTTL: "0"}},
		{"disabled", config.FUSEConfig{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := validBaseConfig()
			src.FUSE = tc.fuse

			text, err := GenerateText(src)
			if err != nil {
				t.Fatalf("GenerateText: %v", err)
			}
			got, err := Parse([]byte(text))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(got.FUSE, src.FUSE) {
				t.Errorf("FUSE mismatch:\ngot:  %+v\nwant: %+v", got.FUSE, src.FUSE)
			}

			data, err := Generate(src)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			got, err = Parse(data)
			if err != nil {
				t.Fatalf("Parse (utf16): %v", err)
			}
			if !reflect.DeepEqual(got.FUSE, src.FUSE) {
				t.Errorf("FUSE mismatch (utf16):\ngot:  %+v\nwant: %+v", got.FUSE, src.FUSE)
			}
		})
	}
}

// The raw duration string is what round-trips, not the parsed value: an
// operator who wrote "1m" must get "1m" back rather than "1m0s", and an unset
// cache_ttl must stay unset rather than being frozen at whatever the default
// happened to be when the config was loaded.
func TestFUSECacheTTLRoundTripsAsWritten(t *testing.T) {
	src := validBaseConfig()
	src.FUSE = config.FUSEConfig{Enabled: true, RawCacheTTL: "1m"}
	if err := src.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	text, err := GenerateText(src)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	if !strings.Contains(text, `"CacheTTL"="1m"`) {
		t.Errorf("expected the literal cache_ttl to be emitted\n%s", text)
	}

	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.FUSE.RawCacheTTL != "1m" {
		t.Errorf("RawCacheTTL = %q, want 1m", got.FUSE.RawCacheTTL)
	}
}

// Mountpoint is emitted even when empty for the same reason as the API
// socket's UnixPath: re-importing an export must be able to blank a value a
// previous policy set, rather than leaving the stale one in the registry.
func TestFUSEClearedMountpointRoundTrips(t *testing.T) {
	src := validBaseConfig()
	src.FUSE = config.FUSEConfig{Enabled: true}

	text, err := GenerateText(src)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	if !strings.Contains(text, `\dotvault\FUSE]`) {
		t.Fatalf("expected a [FUSE] key\n%s", text)
	}
	if !strings.Contains(text, `"Mountpoint"=""`) {
		t.Errorf("expected Mountpoint to be emitted as an empty string so a re-import clears it\n%s", text)
	}
	if !strings.Contains(text, `"CacheTTL"=""`) {
		t.Errorf("expected CacheTTL to be emitted as an empty string so a re-import clears it\n%s", text)
	}
}
