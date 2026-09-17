package config

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func dockerBaseConfig() *Config {
	return &Config{
		Vault: VaultConfig{Address: "https://vault.example.com"},
		Rules: []Rule{{
			Name:     "gh",
			VaultKey: "gh",
			Target:   Target{Path: "~/.netrc", Format: "netrc"},
		}},
	}
}

func TestDockerDefaultsCacheTTL(t *testing.T) {
	cfg := dockerBaseConfig()
	cfg.Docker = DockerConfig{Enabled: true}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.Docker.CacheTTL != DefaultDockerCacheTTL {
		t.Errorf("CacheTTL = %s, want the default %s", cfg.Docker.CacheTTL, DefaultDockerCacheTTL)
	}
	// The literal value stays empty so an export round-trips "unset" rather
	// than baking in the default.
	if cfg.Docker.RawCacheTTL != "" {
		t.Errorf("RawCacheTTL = %q, want it left empty", cfg.Docker.RawCacheTTL)
	}
}

func TestDockerCacheTTLParsing(t *testing.T) {
	tests := []struct {
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{"", DefaultDockerCacheTTL, false},
		{"5s", 5 * time.Second, false},
		{"2m", 2 * time.Minute, false},
		{"10m", MaxDockerCacheTTL, false}, // the ceiling itself is allowed
		{"0", 0, true},                    // no ask-on-every-read mode for plain files
		{"-1s", 0, true},
		{"soon", 0, true},
		{"11m", 0, true}, // past the ceiling
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			cfg := dockerBaseConfig()
			cfg.Docker = DockerConfig{Enabled: true, RawCacheTTL: tc.raw}
			err := cfg.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Validate() = nil, want an error for %q", tc.raw)
				}
				if !strings.Contains(err.Error(), "docker.cache_ttl") {
					t.Errorf("error = %v, want it to name docker.cache_ttl", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if cfg.Docker.CacheTTL != tc.want {
				t.Errorf("CacheTTL = %s, want %s", cfg.Docker.CacheTTL, tc.want)
			}
		})
	}
}

// Path shape is validated whether or not the section is enabled, so a
// mistake is named at load time rather than when someone flips enabled on.
func TestDockerPathsMustBeAbsolute(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  DockerConfig
		want string
	}{
		{"relative socket", DockerConfig{Socket: "docker.sock"}, "docker.socket"},
		{"relative volume dir", DockerConfig{VolumeDir: "volumes"}, "docker.volume_dir"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dockerBaseConfig()
			cfg.Docker = tc.cfg
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate accepted a relative path")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to name %s", err, tc.want)
			}
		})
	}
	for _, bare := range []DockerConfig{{Socket: "~"}, {VolumeDir: "~"}} {
		cfg := dockerBaseConfig()
		cfg.Docker = bare
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate accepted %+v: the driver prunes and chmods the volume dir as its own", bare)
		}
	}
	for _, p := range []string{"/run/x.sock", "~/x.sock"} {
		cfg := dockerBaseConfig()
		cfg.Docker = DockerConfig{Socket: p, VolumeDir: p}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate rejected %q: %v", p, err)
		}
	}
}

func TestDockerSocketPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the plugin is served on linux only")
	}
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1234")

	t.Run("disabled yields no path", func(t *testing.T) {
		c := &Config{Docker: DockerConfig{Socket: "/tmp/docker.sock"}}
		got, err := c.DockerSocketPath()
		if err != nil {
			t.Fatalf("DockerSocketPath: %v", err)
		}
		if got != "" {
			t.Errorf("path = %q, want empty when docker.enabled is false", got)
		}
		dir, err := c.DockerVolumeDir()
		if err != nil {
			t.Fatalf("DockerVolumeDir: %v", err)
		}
		if dir != "" {
			t.Errorf("volume dir = %q, want empty when docker.enabled is false", dir)
		}
	})

	t.Run("enabled without paths uses the runtime defaults", func(t *testing.T) {
		c := &Config{Docker: DockerConfig{Enabled: true}}
		got, err := c.DockerSocketPath()
		if err != nil {
			t.Fatalf("DockerSocketPath: %v", err)
		}
		if want := "/run/user/1234/dotvault/docker.sock"; got != want {
			t.Errorf("socket = %q, want %q", got, want)
		}
		dir, err := c.DockerVolumeDir()
		if err != nil {
			t.Fatalf("DockerVolumeDir: %v", err)
		}
		if want := "/run/user/1234/dotvault/volumes"; dir != want {
			t.Errorf("volume dir = %q, want %q", dir, want)
		}
	})

	t.Run("explicit paths win", func(t *testing.T) {
		c := &Config{Docker: DockerConfig{Enabled: true, Socket: "/tmp/custom.sock", VolumeDir: "/tmp/vols"}}
		got, err := c.DockerSocketPath()
		if err != nil {
			t.Fatalf("DockerSocketPath: %v", err)
		}
		if got != "/tmp/custom.sock" {
			t.Errorf("socket = %q, want the explicit path", got)
		}
		dir, err := c.DockerVolumeDir()
		if err != nil {
			t.Fatalf("DockerVolumeDir: %v", err)
		}
		if dir != "/tmp/vols" {
			t.Errorf("volume dir = %q, want the explicit path", dir)
		}
	})
}

// The whole section is inert off Linux: no socket, no volume dir, so no
// consumer ever carries a permanently dead path.
func TestDockerInertOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("gate only applies off linux")
	}
	c := &Config{Docker: DockerConfig{Enabled: true, Socket: "/tmp/custom.sock"}}
	if got, _ := c.DockerSocketPath(); got != "" {
		t.Errorf("socket = %q, want empty on %s", got, runtime.GOOS)
	}
	if got, _ := c.DockerVolumeDir(); got != "" {
		t.Errorf("volume dir = %q, want empty on %s", got, runtime.GOOS)
	}
}

func TestDockerSectionRoundTripsThroughYAML(t *testing.T) {
	src := dockerBaseConfig()
	src.Docker = DockerConfig{Enabled: true, Socket: "~/docker.sock", VolumeDir: "/tmp/vols", RawCacheTTL: "2m"}
	out, err := yaml.Marshal(src)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Config
	if err := yaml.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Docker != src.Docker {
		t.Errorf("docker section mismatch:\ngot:  %+v\nwant: %+v", got.Docker, src.Docker)
	}
}

func TestValidateDockerTTL(t *testing.T) {
	if err := ValidateDockerTTL(0); err == nil {
		t.Error("accepted 0")
	}
	if err := ValidateDockerTTL(MaxDockerCacheTTL + time.Second); err == nil {
		t.Error("accepted a value past the ceiling")
	}
	if err := ValidateDockerTTL(30 * time.Second); err != nil {
		t.Errorf("rejected 30s: %v", err)
	}
}

// A remote document must not be able to open a socket on the machine.
func TestPartialRejectsDockerSection(t *testing.T) {
	_, err := ParsePartial([]byte("docker:\n  enabled: true\n"))
	if err == nil {
		t.Fatal("ParsePartial accepted a docker section")
	}
	if !strings.Contains(err.Error(), "docker") {
		t.Errorf("error = %v, want it to name the section", err)
	}
}
