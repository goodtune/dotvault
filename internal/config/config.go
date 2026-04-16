package config

import (
	"fmt"
	"log/slog"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/perms"
	"gopkg.in/yaml.v3"
)

// ParseDuration extends time.ParseDuration with a standalone "Nd" suffix
// representing whole days (N × 24h). It is a thin wrapper: anything other
// than a bare Nd is delegated to the stdlib parser, so "6h", "30m",
// "1h30m" etc. continue to work as normal.
//
// Accepts:
//   - bare "Nd" where N is a non-negative integer ("60d" → 1440h, "1d" → 24h)
//   - anything time.ParseDuration accepts ("6h", "30m", "1h30m", "45s")
//
// Rejects:
//   - empty string
//   - negative bare "Nd" (e.g. "-5d"): kept out as a guard-rail for
//     settings like token_ttl where negative values never make sense.
//     Note that stdlib forms like "-5m" are still parseable by
//     time.ParseDuration and pass through unchanged — callers that need a
//     "must be positive" invariant should enforce it at the validation
//     site (e.g. the 10-min floor check for token_ttl)
//   - mixed forms combining days with other units ("1d12h" is rejected
//     because "d" is not understood by time.ParseDuration; if this ever
//     becomes load-bearing we can extend the parser)
//   - non-integer days ("1.5d") and unsupported suffixes ("w", "y")
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	// Bare Nd: digits followed by 'd' with nothing after. A minus sign is
	// allowed through strconv.Atoi but rejected explicitly below so the
	// error is clearer than stdlib's "unknown unit" for the common mistake.
	if strings.HasSuffix(s, "d") {
		num := s[:len(s)-1]
		days, err := strconv.Atoi(num)
		if err != nil {
			// Not a bare Nd (e.g. "1.5d", "1dd", "1d12h") — fall through to
			// stdlib, which will produce the standard "unknown unit" error.
			return time.ParseDuration(s)
		}
		if days < 0 {
			return 0, fmt.Errorf("negative duration: %q", s)
		}
		// Guard against int64 overflow. time.Duration is nanoseconds in an
		// int64, so max representable days ≈ MaxInt64 / (24*time.Hour in ns).
		// Anything above that silently wraps to a negative/garbage value.
		const maxDays = int(int64(math.MaxInt64) / int64(24*time.Hour))
		if days > maxDays {
			return 0, fmt.Errorf("duration %q exceeds time.Duration range (max %dd)", s, maxDays)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// Config is the top-level system configuration.
type Config struct {
	Vault      VaultConfig          `yaml:"vault"`
	Sync       SyncConfig           `yaml:"sync"`
	Web        WebConfig            `yaml:"web"`
	Rules      []Rule               `yaml:"rules"`
	Enrolments map[string]Enrolment `yaml:"enrolments"`
}

// Enrolment declares a credential acquisition flow for a Vault KV key.
type Enrolment struct {
	Engine   string         `yaml:"engine"`
	Settings map[string]any `yaml:"settings"`
}

// VaultConfig holds Vault connection settings.
type VaultConfig struct {
	Address       string `yaml:"address"`
	CACert        string `yaml:"ca_cert"`
	TLSSkipVerify bool   `yaml:"tls_skip_verify"`
	KVMount       string `yaml:"kv_mount"`
	UserPrefix    string `yaml:"user_prefix"`
	AuthMethod    string `yaml:"auth_method"`
	AuthRole      string `yaml:"auth_role"`
	AuthMount     string `yaml:"auth_mount"`
}

// SyncConfig holds sync settings.
type SyncConfig struct {
	Interval    time.Duration `yaml:"-"`
	RawInterval string        `yaml:"interval"`
}

// WebConfig holds optional web UI settings.
type WebConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Listen         string `yaml:"listen"`
	LoginText      string `yaml:"login_text"`
	SecretViewText string `yaml:"secret_view_text"`
}

// Rule defines a single sync rule.
type Rule struct {
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	VaultKey    string       `yaml:"vault_key"`
	OAuth       *OAuthConfig `yaml:"oauth"`
	Target      Target       `yaml:"target"`
}

// OAuthConfig holds optional OAuth2 settings for a rule.
type OAuthConfig struct {
	EnginePath string   `yaml:"engine_path"`
	Provider   string   `yaml:"provider"`
	Scopes     []string `yaml:"scopes"`
}

// Target defines where and how a secret is written.
type Target struct {
	Path     string `yaml:"path"`
	Format   string `yaml:"format"`
	Template string `yaml:"template"`
	Merge    string `yaml:"merge"`
}

var validFormats = map[string]bool{
	"yaml":  true,
	"json":  true,
	"ini":   true,
	"toml":  true,
	"text":  true,
	"netrc": true,
}

// LoadSystem loads configuration using the platform-appropriate source.
// On Windows, if Group Policy registry keys exist under
// HKLM\SOFTWARE\Policies\dotvault, configuration is loaded from the
// registry and the file-based config at path is ignored. Only
// machine-level (HKLM) policy is read; HKCU is intentionally skipped
// because it is user-writable and cannot be treated as a trusted policy
// boundary on unmanaged machines.
// On non-Windows platforms this falls back to Load(path).
func LoadSystem(path string) (*Config, error) {
	cfg, managed, err := loadFromRegistry()
	if err != nil {
		return nil, fmt.Errorf("read registry config: %w", err)
	}
	if managed {
		slog.Info("configuration loaded from Windows Registry (Group Policy); file-based config is ignored",
			"path", path)
		if err := cfg.validate(); err != nil {
			return nil, fmt.Errorf("validate registry config: %w", err)
		}
		return cfg, nil
	}
	return Load(path)
}

// Load reads and validates a config file at the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Warn if the config file is group or world writable.
	if insecure, checkErr := perms.IsGroupWorldWritable(path); checkErr == nil && insecure {
		slog.Warn("config file is group or world writable", "path", path)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	// Vault address required
	if c.Vault.Address == "" {
		return fmt.Errorf("vault.address is required")
	}

	// Default KV mount
	if c.Vault.KVMount == "" {
		c.Vault.KVMount = "kv"
	}

	// Default user prefix; ensure exactly one trailing slash so all
	// consumers (sync engine, enrolment manager) build consistent paths.
	if c.Vault.UserPrefix == "" {
		c.Vault.UserPrefix = "users/"
	} else {
		c.Vault.UserPrefix = strings.TrimRight(c.Vault.UserPrefix, "/") + "/"
	}

	// Parse sync interval
	if c.Sync.RawInterval == "" {
		c.Sync.Interval = 15 * time.Minute // default fallback interval
	} else {
		d, err := time.ParseDuration(c.Sync.RawInterval)
		if err != nil {
			return fmt.Errorf("sync.interval %q: %w", c.Sync.RawInterval, err)
		}
		c.Sync.Interval = d
	}

	// Web UI validation
	if c.Web.Enabled {
		if c.Web.Listen == "" {
			c.Web.Listen = "127.0.0.1:8200"
		}
		if err := paths.ValidateLoopback(c.Web.Listen); err != nil {
			return fmt.Errorf("web.listen: %w", err)
		}
	}

	// Rules validation
	if len(c.Rules) == 0 {
		return fmt.Errorf("at least one rule is required")
	}

	seen := make(map[string]bool)
	for i, r := range c.Rules {
		if r.Name == "" {
			return fmt.Errorf("rules[%d].name is required", i)
		}
		if seen[r.Name] {
			return fmt.Errorf("duplicate rule name %q", r.Name)
		}
		seen[r.Name] = true

		if r.VaultKey == "" {
			return fmt.Errorf("rules[%d] (%s): vault_key is required", i, r.Name)
		}
		if r.Target.Path == "" {
			return fmt.Errorf("rules[%d] (%s): target.path is required", i, r.Name)
		}
		if !validFormats[r.Target.Format] {
			return fmt.Errorf("rules[%d] (%s): invalid format %q (must be yaml, json, ini, toml, text, or netrc)", i, r.Name, r.Target.Format)
		}
	}

	// Enrolments validation
	for key, e := range c.Enrolments {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("enrolment key must not be empty or whitespace")
		}
		if e.Engine == "" {
			return fmt.Errorf("enrolments[%q].engine is required", key)
		}

		// Engine-agnostic validation of token_ttl if present: must parse
		// as a duration and be no smaller than the 10-minute floor so
		// engines that refresh don't thrash the upstream API.
		if raw, ok := e.Settings["token_ttl"]; ok {
			s, ok := raw.(string)
			if !ok {
				return fmt.Errorf("enrolments[%q].settings.token_ttl must be a string, got %T", key, raw)
			}
			d, err := ParseDuration(s)
			if err != nil {
				return fmt.Errorf("enrolments[%q].settings.token_ttl %q: %w", key, s, err)
			}
			if d < 10*time.Minute {
				return fmt.Errorf("enrolments[%q].settings.token_ttl %q is below the 10m minimum", key, s)
			}
		}
	}

	return nil
}

