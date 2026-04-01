package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/perms"
	"gopkg.in/yaml.v3"
)

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
	}

	return nil
}

