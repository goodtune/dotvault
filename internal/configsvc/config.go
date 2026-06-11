package configsvc

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/configsvc/groups"
	"github.com/goodtune/dotvault/internal/configsvc/store"
)

// Config is the dotvault-config service's own configuration file. It is
// deliberately a different shape from the daemon's config — the service is a
// deployable network component whose only concerns are a listener, a storage
// backend, and a group resolver.
type Config struct {
	// Listen is the address the HTTP server binds. Unlike the daemon's web
	// UI there is no loopback invariant — this is a network service.
	// Default "127.0.0.1:9100".
	Listen string `yaml:"listen"`
	// TLS optionally terminates TLS on the service's own listener. Leave
	// unset when the operator's ingress terminates instead.
	TLS    TLSConfig    `yaml:"tls"`
	Store  StoreConfig  `yaml:"store"`
	Groups GroupsConfig `yaml:"groups"`
}

// TLSConfig is the optional listener certificate pair.
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Enabled reports whether the listener should terminate TLS itself.
func (t TLSConfig) Enabled() bool {
	return t.CertFile != "" || t.KeyFile != ""
}

// StoreConfig selects and configures the storage backend.
type StoreConfig struct {
	// Driver is "sqlite" (development/tests) or "vault" (production).
	Driver string `yaml:"driver"`
	// DSN is the sqlite database path (":memory:" for ephemeral).
	DSN string `yaml:"dsn"`
	// Vault configures the vault driver.
	Vault VaultStoreConfig `yaml:"vault"`
}

// VaultStoreConfig is the YAML projection of store.VaultStoreConfig.
type VaultStoreConfig struct {
	Address    string         `yaml:"address"`
	Mount      string         `yaml:"mount"`
	Path       string         `yaml:"path"`
	Auth       string         `yaml:"auth"`
	Token      string         `yaml:"token"`
	CACert     string         `yaml:"ca_cert"`
	Kubernetes KubernetesAuth `yaml:"kubernetes"`
}

// KubernetesAuth configures the kubernetes auth method of the vault driver.
type KubernetesAuth struct {
	Mount   string `yaml:"mount"`
	Role    string `yaml:"role"`
	JWTPath string `yaml:"jwt_path"`
}

// GroupsConfig selects and configures the group resolver.
type GroupsConfig struct {
	// Source is "static" (membership maps in the store) or "ldap".
	// Default "static".
	Source string `yaml:"source"`
	// RawTTL is the resolver cache TTL as a duration string ("Nd" day
	// shorthand accepted). Default "1m"; "0" disables caching.
	RawTTL string        `yaml:"ttl"`
	TTL    time.Duration `yaml:"-"`
	// LDAP configures the ldap source.
	LDAP groups.LDAPConfig `yaml:"ldap"`
}

// LoadConfig reads and validates the service config. Unknown YAML keys are a
// hard error — this file is authored by an operator, and a typo'd key
// silently doing nothing is worse than a load failure.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:9100"
	}
	if c.TLS.Enabled() && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		return fmt.Errorf("tls requires both cert_file and key_file")
	}

	switch c.Store.Driver {
	case "sqlite":
		if c.Store.DSN == "" {
			return fmt.Errorf("store.dsn is required for the sqlite driver")
		}
	case "vault":
		v := &c.Store.Vault
		if v.Address == "" {
			return fmt.Errorf("store.vault.address is required")
		}
		if _, err := url.Parse(v.Address); err != nil {
			return fmt.Errorf("store.vault.address: %w", err)
		}
		switch v.Auth {
		case "", "token":
			// Token may come from VAULT_TOKEN at open time.
		case "kubernetes":
			if v.Kubernetes.Role == "" {
				return fmt.Errorf("store.vault.kubernetes.role is required for kubernetes auth")
			}
		default:
			return fmt.Errorf("store.vault.auth must be token or kubernetes, got %q", v.Auth)
		}
	case "":
		return fmt.Errorf("store.driver is required (sqlite or vault)")
	default:
		return fmt.Errorf("store.driver must be sqlite or vault, got %q", c.Store.Driver)
	}

	switch c.Groups.Source {
	case "", "static":
		c.Groups.Source = "static"
	case "ldap":
		// Full validation (URL shape, filter placeholder, CA readability)
		// happens in groups.NewLDAP at open time; the cheap structural
		// checks run here so `compose`-style offline use fails early too.
		if c.Groups.LDAP.URL == "" {
			return fmt.Errorf("groups.ldap.url is required for the ldap source")
		}
		if !strings.Contains(c.Groups.LDAP.Filter, "%s") {
			return fmt.Errorf("groups.ldap.filter must contain a %%s username placeholder")
		}
	default:
		return fmt.Errorf("groups.source must be static or ldap, got %q", c.Groups.Source)
	}

	if c.Groups.RawTTL == "" {
		c.Groups.TTL = time.Minute
	} else {
		ttl, err := config.ParseDuration(c.Groups.RawTTL)
		if err != nil {
			return fmt.Errorf("groups.ttl %q: %w", c.Groups.RawTTL, err)
		}
		if ttl < 0 {
			return fmt.Errorf("groups.ttl must not be negative")
		}
		c.Groups.TTL = ttl
	}
	return nil
}

// OpenStore opens the configured storage backend.
func (c *Config) OpenStore(ctx context.Context) (store.Store, error) {
	switch c.Store.Driver {
	case "vault":
		v := c.Store.Vault
		return store.OpenVault(ctx, store.VaultStoreConfig{
			Address:    v.Address,
			Mount:      v.Mount,
			Path:       v.Path,
			Auth:       v.Auth,
			Token:      v.Token,
			CACert:     v.CACert,
			K8sMount:   v.Kubernetes.Mount,
			K8sRole:    v.Kubernetes.Role,
			K8sJWTPath: v.Kubernetes.JWTPath,
		})
	default:
		return store.Open(ctx, c.Store.Driver, c.Store.DSN)
	}
}

// OpenResolver builds the configured group resolver, wrapped in the TTL
// cache. The static source reads membership from st.
func (c *Config) OpenResolver(st store.Store) (groups.Resolver, error) {
	var inner groups.Resolver
	switch c.Groups.Source {
	case "ldap":
		r, err := groups.NewLDAP(c.Groups.LDAP)
		if err != nil {
			return nil, err
		}
		inner = r
	default:
		inner = groups.NewStatic(st)
	}
	return groups.NewCached(inner, c.Groups.TTL), nil
}
