package client

import (
	"strings"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/paths"
)

// Config is the connectivity-and-auth view of dotvault's system config. It is
// a deliberately narrow projection of the full dotvault configuration: only
// the fields needed to talk to Vault, authenticate, and locate a user's
// secrets are exposed. Sync rules, enrolment definitions, web UI, and
// observability settings stay internal to dotvault and are not part of this
// surface.
//
// A Config can be produced two ways:
//
//   - LoadConfig parses dotvault's on-disk system config (the same file the
//     daemon reads), so a consumer inherits the operator's connectivity and
//     auth settings verbatim. This is the recommended path — it keeps
//     dotvault the single source of truth.
//   - Constructed directly by a caller that already knows its connectivity
//     (useful for tests, or callers wiring values from another source). New
//     applies the same defaults LoadConfig would (KVMount "kv", UserPrefix
//     "users/", TokenFile ~/.vault-token).
type Config struct {
	Vault VaultConfig

	// TokenFile is the path to the Vault token file consulted after
	// VAULT_TOKEN. Empty means dotvault's platform default
	// (~/.vault-token, %USERPROFILE%\.vault-token on Windows). dotvault
	// does not expose this in its YAML today; it is here as a programmatic
	// override point and defaults to the canonical location.
	TokenFile string
}

// VaultConfig mirrors the connectivity + auth fields of dotvault's vault:
// config stanza.
//
// Vault namespaces are not a dotvault YAML field; the underlying Vault client
// honours the VAULT_NAMESPACE environment variable, so namespaced
// deployments work without an explicit field here.
type VaultConfig struct {
	// Address is the Vault server URL (e.g. https://vault.example.com:8200).
	// Required.
	Address string

	// CACert is the path to a PEM CA bundle for verifying the Vault server.
	CACert string

	// TLSSkipVerify disables TLS verification. Insecure; for dev only.
	TLSSkipVerify bool

	// KVMount is the KV v2 mount that holds user secrets. Defaults to "kv".
	KVMount string

	// UserPrefix is the path prefix under which per-user secrets live.
	// Defaults to "users/" and is normalised to carry exactly one trailing
	// slash, so the full layout is {KVMount}/{UserPrefix}{identity}/{service}.
	UserPrefix string

	// AuthMethod is the fresh-auth method dotvault uses when no cached token
	// is usable: "oidc", "ldap", or "token".
	AuthMethod string

	// AuthMount is the auth backend mount path (defaults per method: "oidc"
	// or "ldap").
	AuthMount string

	// AuthRole is an optional Vault role passed to the auth method.
	AuthRole string
}

// DefaultConfigPath returns the platform-appropriate path to dotvault's
// system config file — the same file the daemon loads. On Linux this is
// /etc/xdg/dotvault/config.yaml (honouring XDG_CONFIG_DIRS).
func DefaultConfigPath() string {
	return paths.SystemConfigPath()
}

// DefaultTokenFile returns the platform-appropriate path to the Vault token
// file dotvault reads and writes (~/.vault-token).
func DefaultTokenFile() string {
	return paths.VaultTokenPath()
}

// LoadConfig parses dotvault's system config at path and projects it onto the
// connectivity-and-auth Config. Pass DefaultConfigPath() for the canonical
// location. The file is parsed and validated by dotvault's own loader, so a
// malformed or incomplete config (missing vault.address, etc.) surfaces the
// same error the daemon would report.
//
// On Windows, if Group Policy registry keys are present, dotvault loads its
// config from the registry and ignores the file; LoadConfig follows that same
// precedence via the shared loader.
func LoadConfig(path string) (*Config, error) {
	cfg, err := config.LoadSystem(path)
	if err != nil {
		return nil, err
	}
	return fromInternal(cfg), nil
}

// fromInternal projects the full internal config onto the public surface.
// The internal loader has already applied defaults and normalisation
// (KVMount, UserPrefix trailing slash), so this is a straight copy.
func fromInternal(cfg *config.Config) *Config {
	return &Config{
		Vault: VaultConfig{
			Address:       cfg.Vault.Address,
			CACert:        cfg.Vault.CACert,
			TLSSkipVerify: cfg.Vault.TLSSkipVerify,
			KVMount:       cfg.Vault.KVMount,
			UserPrefix:    cfg.Vault.UserPrefix,
			AuthMethod:    cfg.Vault.AuthMethod,
			AuthMount:     cfg.Vault.AuthMount,
			AuthRole:      cfg.Vault.AuthRole,
		},
	}
}

// withDefaults returns a copy of cfg with empty fields filled in to match the
// defaults LoadConfig would have applied. Used by New so a directly
// constructed Config behaves identically to a loaded one.
//
// The default values come from the shared config.DefaultKVMount /
// config.DefaultUserPrefix constants, so the defaults themselves can't drift
// from internal/config.(*Config).validate. (The trailing-slash normalisation
// is trivially duplicated; the logic is small and stable.) For the LoadConfig
// path the internal validator has already applied these, so this is inert
// there; it matters only for a Config a caller builds by hand.
func (c *Config) withDefaults() Config {
	out := *c
	if out.Vault.KVMount == "" {
		out.Vault.KVMount = config.DefaultKVMount
	}
	if out.Vault.UserPrefix == "" {
		out.Vault.UserPrefix = config.DefaultUserPrefix
	} else {
		out.Vault.UserPrefix = strings.TrimRight(out.Vault.UserPrefix, "/") + "/"
	}
	if out.TokenFile == "" {
		out.TokenFile = DefaultTokenFile()
	}
	return out
}
