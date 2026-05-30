//go:build windows

package config

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	// registryPolicyPath is the GPO-managed registry path. Policies are read
	// from HKLM\SOFTWARE\Policies\goodtune\dotvault only. HKCU is intentionally
	// not used as a trusted policy source because it is normally user-writable.
	registryPolicyPath = `SOFTWARE\Policies\goodtune\dotvault`
)

// loadFromRegistry attempts to load configuration from Windows Registry
// Group Policy keys. It reads machine-level values from
// HKLM\SOFTWARE\Policies\goodtune\dotvault. HKCU is not consulted because it
// is user-writable and cannot be treated as a trusted policy boundary.
//
// Returns (nil, false, nil) if no GPO registry keys are found.
func loadFromRegistry() (*Config, bool, error) {
	machine, machineFound, err := readRegistryLayer(registry.LOCAL_MACHINE)
	if err != nil {
		return nil, false, fmt.Errorf("read HKLM registry layer: %w", err)
	}

	if !machineFound {
		return nil, false, nil
	}

	cfg := &Config{}

	slog.Debug("loading machine-level registry configuration",
		"key", `HKLM\`+registryPolicyPath)
	applyRegistryLayer(cfg, machine)

	// Read rules from the machine-level policy key.
	rules, err := readRegistryRules(registry.LOCAL_MACHINE)
	if err != nil {
		return nil, true, fmt.Errorf("read registry rules: %w", err)
	}
	cfg.Rules = rules

	// Read enrolments from the machine-level policy key.
	enrolments, err := readRegistryEnrolments(registry.LOCAL_MACHINE, registryPolicyPath)
	if err != nil {
		return nil, true, fmt.Errorf("read registry enrolments: %w", err)
	}
	cfg.Enrolments = enrolments

	return cfg, true, nil
}

// registryLayer holds the flat values read from a single registry hive.
type registryLayer struct {
	// Vault
	VaultAddress            string
	VaultCACert             string
	VaultTLSSkipVerify      *uint32
	VaultKVMount            string
	VaultUserPrefix         string
	VaultAuthMethod         string
	VaultAuthRole           string
	VaultAuthMount          string
	VaultDisableTokenRenewal *uint32

	// Sync
	SyncInterval string

	// Web
	WebEnabled *uint32
	WebListen  string

	// Observability. Headers are intentionally not modelled here —
	// they carry OTLP bearer tokens (Datadog / Grafana Cloud / etc.)
	// and live in the per-user EnvironmentFile per the credential
	// rule documented in CLAUDE.md. The SDK reads them from
	// OTEL_EXPORTER_OTLP_HEADERS regardless of how the rest of this
	// block is sourced.
	ObservabilityEnabled        *uint32
	ObservabilityEndpoint       string
	ObservabilityProtocol       string
	ObservabilityInsecure       *uint32
	ObservabilityExportInterval string
}

// readRegistryLayer reads dotvault policy values from the given root key.
// Returns the layer, whether the key exists, and any unexpected error.
// A missing key (ErrNotExist) is not an error — it means no policy is set.
func readRegistryLayer(root registry.Key) (registryLayer, bool, error) {
	var layer registryLayer

	key, err := registry.OpenKey(root, registryPolicyPath, registry.READ)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return layer, false, nil
		}
		return layer, false, err
	}
	defer key.Close()

	// Read Vault subkey.
	vk, err := registry.OpenKey(root, registryPolicyPath+`\Vault`, registry.READ)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return layer, false, fmt.Errorf("open Vault policy key: %w", err)
	}
	if err == nil {
		defer vk.Close()
		layer.VaultAddress, _ = readRegString(vk, "Address")
		layer.VaultCACert, _ = readRegString(vk, "CACert")
		layer.VaultTLSSkipVerify = readRegDWORD(vk, "TLSSkipVerify")
		layer.VaultKVMount, _ = readRegString(vk, "KVMount")
		layer.VaultUserPrefix, _ = readRegString(vk, "UserPrefix")
		layer.VaultAuthMethod, _ = readRegString(vk, "AuthMethod")
		layer.VaultAuthRole, _ = readRegString(vk, "AuthRole")
		layer.VaultAuthMount, _ = readRegString(vk, "AuthMount")
		layer.VaultDisableTokenRenewal = readRegDWORD(vk, "DisableTokenRenewal")
	}

	// Read Sync subkey.
	sk, err := registry.OpenKey(root, registryPolicyPath+`\Sync`, registry.READ)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return layer, false, fmt.Errorf("open Sync policy key: %w", err)
	}
	if err == nil {
		defer sk.Close()
		layer.SyncInterval, _ = readRegString(sk, "Interval")
	}

	// Read Web subkey.
	wk, err := registry.OpenKey(root, registryPolicyPath+`\Web`, registry.READ)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return layer, false, fmt.Errorf("open Web policy key: %w", err)
	}
	if err == nil {
		defer wk.Close()
		layer.WebEnabled = readRegDWORD(wk, "Enabled")
		layer.WebListen, _ = readRegString(wk, "Listen")
	}

	// Read Observability subkey. Without this, a GPO-managed daemon
	// has Observability.Enabled=false (zero value), Init short-circuits
	// to an inactive Provider, and the WARN record from
	// LogRegistryConfigManaged vanishes into the no-op global logger —
	// silently dropping the very notification this PR set out to make
	// reachable.
	ok, err := registry.OpenKey(root, registryPolicyPath+`\Observability`, registry.READ)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return layer, false, fmt.Errorf("open Observability policy key: %w", err)
	}
	if err == nil {
		defer ok.Close()
		layer.ObservabilityEnabled = readRegDWORD(ok, "Enabled")
		layer.ObservabilityEndpoint, _ = readRegString(ok, "Endpoint")
		layer.ObservabilityProtocol, _ = readRegString(ok, "Protocol")
		layer.ObservabilityInsecure = readRegDWORD(ok, "Insecure")
		layer.ObservabilityExportInterval, _ = readRegString(ok, "ExportInterval")
	}

	return layer, true, nil
}

// applyRegistryLayer merges a registry layer into the config. Only non-zero
// values are applied, allowing higher-priority layers to override selectively.
func applyRegistryLayer(cfg *Config, layer registryLayer) {
	if layer.VaultAddress != "" {
		cfg.Vault.Address = layer.VaultAddress
	}
	if layer.VaultCACert != "" {
		cfg.Vault.CACert = layer.VaultCACert
	}
	if layer.VaultTLSSkipVerify != nil {
		cfg.Vault.TLSSkipVerify = *layer.VaultTLSSkipVerify != 0
	}
	if layer.VaultKVMount != "" {
		cfg.Vault.KVMount = layer.VaultKVMount
	}
	if layer.VaultUserPrefix != "" {
		cfg.Vault.UserPrefix = layer.VaultUserPrefix
	}
	if layer.VaultAuthMethod != "" {
		cfg.Vault.AuthMethod = layer.VaultAuthMethod
	}
	if layer.VaultAuthRole != "" {
		cfg.Vault.AuthRole = layer.VaultAuthRole
	}
	if layer.VaultAuthMount != "" {
		cfg.Vault.AuthMount = layer.VaultAuthMount
	}
	if layer.VaultDisableTokenRenewal != nil {
		cfg.Vault.DisableTokenRenewal = *layer.VaultDisableTokenRenewal != 0
	}
	if layer.SyncInterval != "" {
		cfg.Sync.RawInterval = layer.SyncInterval
	}
	if layer.WebEnabled != nil {
		cfg.Web.Enabled = *layer.WebEnabled != 0
	}
	if layer.WebListen != "" {
		cfg.Web.Listen = layer.WebListen
	}
	if layer.ObservabilityEnabled != nil {
		cfg.Observability.Enabled = *layer.ObservabilityEnabled != 0
	}
	if layer.ObservabilityEndpoint != "" {
		cfg.Observability.Endpoint = layer.ObservabilityEndpoint
	}
	if layer.ObservabilityProtocol != "" {
		cfg.Observability.Protocol = layer.ObservabilityProtocol
	}
	if layer.ObservabilityInsecure != nil {
		cfg.Observability.Insecure = *layer.ObservabilityInsecure != 0
	}
	if layer.ObservabilityExportInterval != "" {
		cfg.Observability.RawInterval = layer.ObservabilityExportInterval
	}
}

// readRegistryRules reads rules from the Rules subkey under the given root
// (HKLM). Each rule is a subkey named after the rule, containing values for
// VaultKey, TargetPath, TargetFormat, etc.
func readRegistryRules(root registry.Key) ([]Rule, error) {
	names, err := readRuleNames(root)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			// Rules subkey absent means no rules are configured via registry.
			return nil, nil
		}
		return nil, fmt.Errorf("enumerate rules at HKLM\\%s\\Rules: %w", registryPolicyPath, err)
	}

	rules := make([]Rule, 0, len(names))
	for _, name := range names {
		rule, err := readSingleRule(root, name)
		if err != nil {
			return nil, fmt.Errorf("read rule %q from HKLM\\%s\\Rules: %w", name, registryPolicyPath, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// readRuleNames returns the names of rule subkeys under the Rules key.
func readRuleNames(root registry.Key) ([]string, error) {
	key, err := registry.OpenKey(root, registryPolicyPath+`\Rules`, registry.READ)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	info, err := key.Stat()
	if err != nil {
		return nil, err
	}

	names, err := key.ReadSubKeyNames(int(info.SubKeyCount))
	if err != nil {
		return nil, err
	}
	return names, nil
}

// readSingleRule reads a single rule from the registry.
func readSingleRule(root registry.Key, name string) (Rule, error) {
	path := registryPolicyPath + `\Rules\` + name
	key, err := registry.OpenKey(root, path, registry.READ)
	if err != nil {
		return Rule{}, err
	}
	defer key.Close()

	rule := Rule{Name: name}
	rule.Description, _ = readRegString(key, "Description")
	rule.VaultKey, _ = readRegString(key, "VaultKey")
	rule.Target.Path, _ = readRegString(key, "TargetPath")
	rule.Target.Format, _ = readRegString(key, "TargetFormat")
	rule.Target.Template, _ = readRegString(key, "TargetTemplate")
	rule.Target.Merge, _ = readRegString(key, "TargetMerge")

	// Read optional OAuth settings.
	oauthPath := path + `\OAuth`
	ok, oerr := registry.OpenKey(root, oauthPath, registry.READ)
	if oerr != nil && !errors.Is(oerr, registry.ErrNotExist) {
		return Rule{}, fmt.Errorf("open OAuth key at %s: %w", oauthPath, oerr)
	}
	if oerr == nil {
		defer ok.Close()
		oauth := &OAuthConfig{}
		oauth.EnginePath, _ = readRegString(ok, "EnginePath")
		oauth.Provider, _ = readRegString(ok, "Provider")
		oauth.Scopes = readRegMultiString(ok, "Scopes")
		if oauth.EnginePath != "" || oauth.Provider != "" || len(oauth.Scopes) > 0 {
			rule.OAuth = oauth
		}
	}

	return rule, nil
}

// readRegString reads a REG_SZ value, returning ("", false) if not found.
// Unexpected errors (e.g. type mismatch) are logged to aid GPO debugging.
func readRegString(key registry.Key, name string) (string, bool) {
	val, _, err := key.GetStringValue(name)
	if err != nil {
		if !errors.Is(err, registry.ErrNotExist) {
			slog.Warn("unexpected error reading REG_SZ", "name", name, "error", err)
		}
		return "", false
	}
	return val, true
}

// readRegDWORD reads a REG_DWORD value, returning nil if not found.
// Unexpected errors (e.g. type mismatch) are logged to aid GPO debugging.
func readRegDWORD(key registry.Key, name string) *uint32 {
	val, _, err := key.GetIntegerValue(name)
	if err != nil {
		if !errors.Is(err, registry.ErrNotExist) {
			slog.Warn("unexpected error reading REG_DWORD", "name", name, "error", err)
		}
		return nil
	}
	v := uint32(val)
	return &v
}

// readRegMultiString reads a REG_MULTI_SZ value, returning nil if not found.
// Unexpected errors (e.g. type mismatch) are logged to aid GPO debugging.
func readRegMultiString(key registry.Key, name string) []string {
	val, _, err := key.GetStringsValue(name)
	if err != nil {
		if !errors.Is(err, registry.ErrNotExist) {
			slog.Warn("unexpected error reading REG_MULTI_SZ", "name", name, "error", err)
		}
		return nil
	}
	return val
}

// readRegistryEnrolments reads enrolments from the Enrolments subkey under
// the given basePath. Each enrolment is a named subkey containing an Engine
// value and optional Settings subkey.
// Returns (nil, nil) if the Enrolments key does not exist.
func readRegistryEnrolments(root registry.Key, basePath string) (map[string]Enrolment, error) {
	enrolPath := basePath + `\Enrolments`
	key, err := registry.OpenKey(root, enrolPath, registry.READ)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open Enrolments key at %s: %w", enrolPath, err)
	}
	defer key.Close()

	info, err := key.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat Enrolments key: %w", err)
	}

	names, err := key.ReadSubKeyNames(int(info.SubKeyCount))
	if err != nil {
		return nil, fmt.Errorf("enumerate enrolment subkeys: %w", err)
	}

	enrolments := make(map[string]Enrolment, len(names))
	for _, name := range names {
		enrolment, err := readSingleEnrolment(root, basePath, name)
		if err != nil {
			return nil, fmt.Errorf("read enrolment %q: %w", name, err)
		}
		enrolments[name] = enrolment
	}
	return enrolments, nil
}

// readSingleEnrolment reads a single enrolment from the registry.
// The basePath parameter is the registry path containing the Enrolments
// subkey (e.g. registryPolicyPath). The name is the enrolment subkey name.
func readSingleEnrolment(root registry.Key, basePath, name string) (Enrolment, error) {
	path := basePath + `\Enrolments\` + name
	key, err := registry.OpenKey(root, path, registry.READ)
	if err != nil {
		return Enrolment{}, err
	}
	defer key.Close()

	enrolment := Enrolment{}
	enrolment.Engine, _ = readRegString(key, "Engine")

	// Read optional Settings subkey, recursing into any nested subkeys
	// so engines like "copy" with structured settings (e.g. settings.from
	// → mount/path) round-trip cleanly through reg-export → reg-import.
	settingsPath := path + `\Settings`
	settings, err := readRegistrySettingsBlock(root, settingsPath)
	if err != nil {
		return Enrolment{}, err
	}
	if len(settings) > 0 {
		enrolment.Settings = settings
	}

	return enrolment, nil
}

// readRegistrySettingsBlock reads scalar values directly under keyPath
// and recursively reads any subkeys as nested map[string]any entries.
// Returns nil (no error) when the key does not exist; returns an empty
// map when the key exists but contains no values or subkeys.
func readRegistrySettingsBlock(root registry.Key, keyPath string) (map[string]any, error) {
	sk, err := registry.OpenKey(root, keyPath, registry.READ)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open settings key at %s: %w", keyPath, err)
	}
	defer sk.Close()

	info, err := sk.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat settings key: %w", err)
	}

	out := make(map[string]any)

	if info.ValueCount > 0 {
		names, err := sk.ReadValueNames(int(info.ValueCount))
		if err != nil {
			return nil, fmt.Errorf("read settings value names: %w", err)
		}
		for _, vname := range names {
			// Registry value names are case-insensitive on Windows;
			// engines compare keys lowercase (e.g. "client_id"), so
			// normalize before storing.
			settingKey := strings.ToLower(vname)
			_, valtype, _ := sk.GetValue(vname, nil)
			switch valtype {
			case registry.SZ, registry.EXPAND_SZ:
				if s, ok := readRegString(sk, vname); ok {
					out[settingKey] = s
				}
			case registry.MULTI_SZ:
				if ms := readRegMultiString(sk, vname); ms != nil {
					vals := make([]any, len(ms))
					for i, v := range ms {
						vals[i] = v
					}
					out[settingKey] = vals
				}
			}
		}
	}

	if info.SubKeyCount > 0 {
		subnames, err := sk.ReadSubKeyNames(int(info.SubKeyCount))
		if err != nil {
			return nil, fmt.Errorf("read settings subkey names: %w", err)
		}
		for _, sub := range subnames {
			nested, err := readRegistrySettingsBlock(root, keyPath+`\`+sub)
			if err != nil {
				return nil, err
			}
			out[strings.ToLower(sub)] = nested
		}
	}

	return out, nil
}
