package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func userBaseConfig(fuse FUSEConfig) *Config {
	return &Config{
		Vault: VaultConfig{Address: "https://vault.example.com"},
		FUSE:  fuse,
		Rules: []Rule{{
			Name:     "gh",
			VaultKey: "gh",
			Target:   Target{Path: "~/.netrc", Format: "netrc"},
		}},
	}
}

// The ratchet on `enabled`: a user may turn the filesystem on, never off.
func TestApplyUserEnabledRatchet(t *testing.T) {
	tests := []struct {
		name        string
		systemOn    bool
		userPref    *bool
		want        bool
		description string
	}{
		{"user enables what the system left off", false, boolPtr(true), true,
			"the system's off is a default, so the user may opt in"},
		{"user cannot disable what the system turned on", true, boolPtr(false), true,
			"the system's on is policy, so the user may not opt out"},
		{"user agrees with the system", true, boolPtr(true), true, ""},
		{"user disables what was already off", false, boolPtr(false), false, ""},
		{"user expresses no preference", true, nil, true,
			"an absent key must not read as an explicit false"},
		{"no preference leaves off alone", false, nil, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := userBaseConfig(FUSEConfig{Enabled: tc.systemOn})
			uc := &UserConfig{FUSE: &UserFUSEConfig{Enabled: tc.userPref}}
			if err := cfg.ApplyUser(uc); err != nil {
				t.Fatalf("ApplyUser: %v", err)
			}
			if cfg.FUSE.Enabled != tc.want {
				t.Errorf("Enabled = %v, want %v (%s)", cfg.FUSE.Enabled, tc.want, tc.description)
			}
		})
	}
}

// read_write ratchets the other way: a user may always be more careful than
// policy requires, never less.
func TestApplyUserReadWriteRatchet(t *testing.T) {
	tests := []struct {
		name     string
		systemRW bool
		userPref *bool
		want     bool
	}{
		{"user turns writes off", true, boolPtr(false), false},
		{"user cannot turn writes on", false, boolPtr(true), false},
		{"user agrees writes are on", true, boolPtr(true), true},
		{"user agrees writes are off", false, boolPtr(false), false},
		{"no preference keeps writes on", true, nil, true},
		{"no preference keeps writes off", false, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := userBaseConfig(FUSEConfig{Enabled: true, ReadWrite: tc.systemRW})
			uc := &UserConfig{FUSE: &UserFUSEConfig{ReadWrite: tc.userPref}}
			if err := cfg.ApplyUser(uc); err != nil {
				t.Fatalf("ApplyUser: %v", err)
			}
			if cfg.FUSE.ReadWrite != tc.want {
				t.Errorf("ReadWrite = %v, want %v", cfg.FUSE.ReadWrite, tc.want)
			}
		})
	}
}

// Mountpoint and cache_ttl carry no policy weight, so the user's value wins.
func TestApplyUserPreferencesWin(t *testing.T) {
	cfg := userBaseConfig(FUSEConfig{Enabled: true, Mountpoint: "/srv/policy", RawCacheTTL: "5m"})
	uc := &UserConfig{FUSE: &UserFUSEConfig{Mountpoint: "~/secrets", CacheTTL: "2s"}}
	if err := cfg.ApplyUser(uc); err != nil {
		t.Fatalf("ApplyUser: %v", err)
	}
	if cfg.FUSE.Mountpoint != "~/secrets" {
		t.Errorf("Mountpoint = %q, want ~/secrets", cfg.FUSE.Mountpoint)
	}
	if cfg.FUSE.RawCacheTTL != "2s" {
		t.Errorf("RawCacheTTL = %q, want 2s", cfg.FUSE.RawCacheTTL)
	}
	// The merged section is re-validated, so the parsed duration tracks the
	// user's value rather than the policy one it replaced.
	if cfg.FUSE.CacheTTL != 2*time.Second {
		t.Errorf("CacheTTL = %s, want 2s", cfg.FUSE.CacheTTL)
	}
}

// An unset preference must leave the policy value alone.
func TestApplyUserEmptyOverlayChangesNothing(t *testing.T) {
	want := FUSEConfig{Enabled: true, Mountpoint: "/srv/policy", ReadWrite: true, RawCacheTTL: "5m"}
	cfg := userBaseConfig(want)
	if err := cfg.ApplyUser(&UserConfig{FUSE: &UserFUSEConfig{}}); err != nil {
		t.Fatalf("ApplyUser: %v", err)
	}
	if cfg.FUSE.Enabled != want.Enabled || cfg.FUSE.ReadWrite != want.ReadWrite ||
		cfg.FUSE.Mountpoint != want.Mountpoint || cfg.FUSE.RawCacheTTL != want.RawCacheTTL {
		t.Errorf("FUSE = %+v, want the policy values %+v untouched", cfg.FUSE, want)
	}
}

func TestApplyUserNilIsNoop(t *testing.T) {
	cfg := userBaseConfig(FUSEConfig{Enabled: true})
	if err := cfg.ApplyUser(nil); err != nil {
		t.Fatalf("ApplyUser(nil): %v", err)
	}
	if !cfg.FUSE.Enabled {
		t.Error("a nil overlay changed the config")
	}
}

// The merged section is validated, so a bad value in the user's file is a
// startup error naming that file rather than a silent fallback to the default.
func TestApplyUserValidatesTheMergedSection(t *testing.T) {
	for _, tc := range []struct{ name, mountpoint, ttl string }{
		{"unparseable cache_ttl", "", "soon"},
		{"negative cache_ttl", "", "-5s"},
		{"relative mountpoint", "somewhere/relative", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := userBaseConfig(FUSEConfig{Enabled: true})
			uc := &UserConfig{FUSE: &UserFUSEConfig{Mountpoint: tc.mountpoint, CacheTTL: tc.ttl}}
			err := cfg.ApplyUser(uc)
			if err == nil {
				t.Fatal("ApplyUser accepted an invalid value")
			}
			if !strings.Contains(err.Error(), "user config") {
				t.Errorf("error = %v, want it to name the user config", err)
			}
		})
	}
}

// A section the user may not set is a hard error naming it. Silently dropping
// a `vault:` block would let someone believe they had re-pointed their daemon.
func TestParseUserConfigRejectsPolicySections(t *testing.T) {
	for _, section := range []string{"vault", "web", "agent", "api", "observability", "rules", "enrolments", "remote_config", "ssh", "bypass_system_config"} {
		t.Run(section, func(t *testing.T) {
			_, err := ParseUserConfig([]byte(section + ":\n  enabled: true\n"))
			if err == nil {
				t.Fatalf("ParseUserConfig accepted a %q section", section)
			}
			if !strings.Contains(err.Error(), section) {
				t.Errorf("error = %v, want it to name %q", err, section)
			}
			if !strings.Contains(err.Error(), "fuse") {
				t.Errorf("error = %v, want it to name what the file may set", err)
			}
		})
	}
}

// Case matters: a mis-cased known section would be dropped by the typed
// decode and take effect as nothing at all, and a mis-cased policy section
// must not slip past the rejection as merely unknown.
func TestParseUserConfigRejectsMisCasedSections(t *testing.T) {
	if _, err := ParseUserConfig([]byte("FUSE:\n  enabled: true\n")); err == nil {
		t.Error("ParseUserConfig accepted a mis-cased fuse section")
	}
	if _, err := ParseUserConfig([]byte("Vault:\n  address: https://evil.example.com\n")); err == nil {
		t.Error("ParseUserConfig accepted a mis-cased vault section")
	}
}

// A key this build does not know is ignored with a warning: a newer dotvault
// may understand it, and a stale binary should not refuse to start over one.
func TestParseUserConfigIgnoresUnknownSections(t *testing.T) {
	uc, err := ParseUserConfig([]byte("future_section:\n  x: 1\nfuse:\n  enabled: true\n"))
	if err != nil {
		t.Fatalf("ParseUserConfig: %v", err)
	}
	if uc.FUSE == nil || uc.FUSE.Enabled == nil || !*uc.FUSE.Enabled {
		t.Error("the known section was not parsed alongside the unknown one")
	}
}

func TestParseUserConfigDistinguishesAbsentFromFalse(t *testing.T) {
	absent, err := ParseUserConfig([]byte("fuse:\n  mountpoint: ~/x\n"))
	if err != nil {
		t.Fatalf("ParseUserConfig: %v", err)
	}
	if absent.FUSE.Enabled != nil {
		t.Error("an absent enabled key decoded as a preference; it must stay nil")
	}

	explicit, err := ParseUserConfig([]byte("fuse:\n  enabled: false\n"))
	if err != nil {
		t.Fatalf("ParseUserConfig: %v", err)
	}
	if explicit.FUSE.Enabled == nil || *explicit.FUSE.Enabled {
		t.Error("an explicit `enabled: false` did not decode as a false preference")
	}
}

func TestLoadUserConfigMissingFileIsNotAnError(t *testing.T) {
	uc, err := LoadUserConfig(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("LoadUserConfig: %v", err)
	}
	if uc != nil {
		t.Errorf("uc = %v, want nil for a missing file", uc)
	}
}

func TestLoadUserConfigReadsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("fuse:\n  enabled: true\n  cache_ttl: 5s\n"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	uc, err := LoadUserConfig(path)
	if err != nil {
		t.Fatalf("LoadUserConfig: %v", err)
	}
	if uc == nil || uc.FUSE == nil || uc.FUSE.Enabled == nil || !*uc.FUSE.Enabled {
		t.Fatalf("uc = %+v, want fuse.enabled true", uc)
	}
	if uc.FUSE.CacheTTL != "5s" {
		t.Errorf("CacheTTL = %q, want 5s", uc.FUSE.CacheTTL)
	}
}

// The end-to-end shape a user actually writes: a machine whose system config
// does not mention the filesystem, and a user who wants it.
func TestUserEnablesOnAnUnconfiguredMachine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("fuse:\n  enabled: true\n  mountpoint: ~/vault\n"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	uc, err := LoadUserConfig(path)
	if err != nil {
		t.Fatalf("LoadUserConfig: %v", err)
	}

	cfg := userBaseConfig(FUSEConfig{})
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := cfg.ApplyUser(uc); err != nil {
		t.Fatalf("ApplyUser: %v", err)
	}
	if !cfg.FUSE.Enabled {
		t.Error("the user could not enable the filesystem on a machine that left it off")
	}
	if cfg.FUSE.Mountpoint != "~/vault" {
		t.Errorf("Mountpoint = %q, want ~/vault", cfg.FUSE.Mountpoint)
	}
	if cfg.FUSE.ReadWrite {
		t.Error("enabling the mount must not also grant writes")
	}
}
