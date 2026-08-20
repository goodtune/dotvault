package config

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

func fuseBaseConfig() *Config {
	return &Config{
		Vault: VaultConfig{Address: "https://vault.example.com"},
		Rules: []Rule{{
			Name:     "gh",
			VaultKey: "gh",
			Target:   Target{Path: "~/.netrc", Format: "netrc"},
		}},
	}
}

func TestFUSEDefaultsCacheTTL(t *testing.T) {
	cfg := fuseBaseConfig()
	cfg.FUSE = FUSEConfig{Enabled: true}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.FUSE.CacheTTL != DefaultFUSECacheTTL {
		t.Errorf("CacheTTL = %s, want the default %s", cfg.FUSE.CacheTTL, DefaultFUSECacheTTL)
	}
	// The literal value stays empty so an export round-trips "unset" rather
	// than baking in the default.
	if cfg.FUSE.RawCacheTTL != "" {
		t.Errorf("RawCacheTTL = %q, want it left empty", cfg.FUSE.RawCacheTTL)
	}
}

func TestFUSECacheTTLParsing(t *testing.T) {
	tests := []struct {
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{"", DefaultFUSECacheTTL, false},
		{"5s", 5 * time.Second, false},
		{"2m", 2 * time.Minute, false},
		{"0", 0, false},                 // explicitly disables caching
		{"10m", MaxFUSECacheTTL, false}, // the ceiling itself is allowed
		{"-1s", 0, true},
		{"soon", 0, true},
		{"11m", 0, true}, // past the ceiling
		{"1d", 0, true},  // the day shorthand parses, then trips the ceiling
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			cfg := fuseBaseConfig()
			cfg.FUSE = FUSEConfig{Enabled: true, RawCacheTTL: tc.raw}
			err := cfg.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Validate() = nil, want an error for %q", tc.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if cfg.FUSE.CacheTTL != tc.want {
				t.Errorf("CacheTTL = %s, want %s", cfg.FUSE.CacheTTL, tc.want)
			}
		})
	}
}

// A relative mountpoint resolves against the daemon's working directory, so
// the daemon and anyone reading the config would disagree about where the
// secrets appeared. Named at load time rather than at mount time.
func TestFUSERelativeMountpointRejected(t *testing.T) {
	cfg := fuseBaseConfig()
	cfg.FUSE = FUSEConfig{Enabled: true, Mountpoint: "secrets"}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want an error for a relative mountpoint")
	}
	if !strings.Contains(err.Error(), "fuse.mountpoint") {
		t.Errorf("error = %v, want it to name fuse.mountpoint", err)
	}
}

// Validation is unconditional: a mistake is worth naming whether or not the
// section is currently switched on, so flipping enabled later cannot surface
// an error the operator has long since forgotten writing.
func TestFUSEValidatedWhenDisabled(t *testing.T) {
	cfg := fuseBaseConfig()
	cfg.FUSE = FUSEConfig{Mountpoint: "relative/path"}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() = nil, want the relative mountpoint rejected even while disabled")
	}
}

func TestFUSEMountpointResolution(t *testing.T) {
	cfg := fuseBaseConfig()

	// Disabled means no mountpoint at all, so callers can treat "no path"
	// and "not enabled" identically.
	if p, err := cfg.FUSEMountpoint(); err != nil || p != "" {
		t.Errorf("FUSEMountpoint() = %q, %v; want empty when disabled", p, err)
	}

	cfg.FUSE = FUSEConfig{Enabled: true, Mountpoint: "/srv/secrets"}
	p, err := cfg.FUSEMountpoint()
	if err != nil {
		t.Fatalf("FUSEMountpoint: %v", err)
	}
	if runtime.GOOS == "windows" {
		// Windows has no FUSE, and the gate lives in the config so every
		// consumer agrees rather than each one re-deciding.
		if p != "" {
			t.Errorf("FUSEMountpoint() = %q on Windows, want empty", p)
		}
		return
	}
	if p != "/srv/secrets" {
		t.Errorf("FUSEMountpoint() = %q, want /srv/secrets", p)
	}

	// An unset mountpoint resolves to the default, expanded.
	cfg.FUSE.Mountpoint = ""
	p, err = cfg.FUSEMountpoint()
	if err != nil {
		t.Fatalf("FUSEMountpoint: %v", err)
	}
	if p == "" || strings.HasPrefix(p, "~") {
		t.Errorf("FUSEMountpoint() = %q, want the default expanded to an absolute path", p)
	}
	if !strings.HasSuffix(p, ".dotvault") {
		t.Errorf("FUSEMountpoint() = %q, want it to end in .dotvault", p)
	}
}

// filepath.IsAbs is host-relative, so a Unix mountpoint written for the Linux
// machines in a fleet must not read as "relative" to a Windows binary — that
// would make config.Load fail and the daemon exit, which is exactly what the
// warn-and-mount-nothing gate exists to prevent.
func TestFUSEUnixMountpointAcceptedOnEveryPlatform(t *testing.T) {
	for _, p := range []string{"/home/gary/.dotvault", "/srv/secrets", "~/.dotvault", "~/secrets"} {
		cfg := fuseBaseConfig()
		cfg.FUSE = FUSEConfig{Enabled: true, Mountpoint: p}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() rejected mountpoint %q: %v", p, err)
		}
	}
}
