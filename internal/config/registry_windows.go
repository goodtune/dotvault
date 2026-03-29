//go:build windows

package config

import (
	"fmt"
	"log/slog"

	"golang.org/x/sys/windows/registry"
)

const (
	// registryPolicyPath is the GPO-managed registry path. Both HKLM and HKCU
	// keys under SOFTWARE\Policies are administrator-controlled — users cannot
	// modify HKCU\SOFTWARE\Policies without elevated privileges.
	registryPolicyPath = `SOFTWARE\Policies\dotvault`
)

// loadFromRegistry attempts to load configuration from Windows Registry
// Group Policy keys. It reads machine-level values from HKLM and user-level
// values from HKCU (both under SOFTWARE\Policies\dotvault), merging them
// with user values taking precedence over machine values.
//
// Returns (nil, false, nil) if no GPO registry keys are found.
func loadFromRegistry() (*Config, bool, error) {
	machine, machineFound := readRegistryLayer(registry.LOCAL_MACHINE)
	user, userFound := readRegistryLayer(registry.CURRENT_USER)

	if !machineFound && !userFound {
		return nil, false, nil
	}

	cfg := &Config{}

	// Apply machine-level values first.
	if machineFound {
		slog.Debug("loading machine-level registry configuration",
			"key", `HKLM\`+registryPolicyPath)
		applyRegistryLayer(cfg, machine)
	}

	// Apply user-level values on top (user overrides machine).
	if userFound {
		slog.Debug("loading user-level registry configuration",
			"key", `HKCU\`+registryPolicyPath)
		applyRegistryLayer(cfg, user)
	}

	// Read rules from both layers, with user rules taking precedence by name.
	rules, err := readRegistryRules(registry.LOCAL_MACHINE, registry.CURRENT_USER)
	if err != nil {
		return nil, true, fmt.Errorf("read registry rules: %w", err)
	}
	cfg.Rules = rules

	return cfg, true, nil
}

// registryLayer holds the flat values read from a single registry hive.
type registryLayer struct {
	// Vault
	VaultAddress       string
	VaultCACert        string
	VaultTLSSkipVerify *uint32
	VaultKVMount       string
	VaultUserPrefix    string
	VaultAuthMethod    string
	VaultAuthRole      string
	VaultAuthMount     string

	// Sync
	SyncInterval string

	// Web
	WebEnabled *uint32
	WebListen  string
}

// readRegistryLayer reads dotvault policy values from the given root key.
// Returns the layer and whether the key exists.
func readRegistryLayer(root registry.Key) (registryLayer, bool) {
	var layer registryLayer

	key, err := registry.OpenKey(root, registryPolicyPath, registry.READ)
	if err != nil {
		return layer, false
	}
	defer key.Close()

	// Read Vault subkey.
	if vk, err := registry.OpenKey(root, registryPolicyPath+`\Vault`, registry.READ); err == nil {
		defer vk.Close()
		layer.VaultAddress, _ = readRegString(vk, "Address")
		layer.VaultCACert, _ = readRegString(vk, "CACert")
		layer.VaultTLSSkipVerify = readRegDWORD(vk, "TLSSkipVerify")
		layer.VaultKVMount, _ = readRegString(vk, "KVMount")
		layer.VaultUserPrefix, _ = readRegString(vk, "UserPrefix")
		layer.VaultAuthMethod, _ = readRegString(vk, "AuthMethod")
		layer.VaultAuthRole, _ = readRegString(vk, "AuthRole")
		layer.VaultAuthMount, _ = readRegString(vk, "AuthMount")
	}

	// Read Sync subkey.
	if sk, err := registry.OpenKey(root, registryPolicyPath+`\Sync`, registry.READ); err == nil {
		defer sk.Close()
		layer.SyncInterval, _ = readRegString(sk, "Interval")
	}

	// Read Web subkey.
	if wk, err := registry.OpenKey(root, registryPolicyPath+`\Web`, registry.READ); err == nil {
		defer wk.Close()
		layer.WebEnabled = readRegDWORD(wk, "Enabled")
		layer.WebListen, _ = readRegString(wk, "Listen")
	}

	return layer, true
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
	if layer.SyncInterval != "" {
		cfg.Sync.RawInterval = layer.SyncInterval
	}
	if layer.WebEnabled != nil {
		cfg.Web.Enabled = *layer.WebEnabled != 0
	}
	if layer.WebListen != "" {
		cfg.Web.Listen = layer.WebListen
	}
}

// readRegistryRules reads rules from the Rules subkey under both HKLM and
// HKCU policy paths. Each rule is a subkey named after the rule, containing
// values for VaultKey, TargetPath, TargetFormat, etc. User-level rules
// override machine-level rules with the same name.
func readRegistryRules(machineRoot, userRoot registry.Key) ([]Rule, error) {
	ruleMap := make(map[string]Rule)
	var order []string

	// Read machine-level rules first.
	if names, err := readRuleNames(machineRoot); err == nil {
		for _, name := range names {
			if rule, err := readSingleRule(machineRoot, name); err == nil {
				ruleMap[name] = rule
				order = append(order, name)
			}
		}
	}

	// Read user-level rules, overriding machine-level by name.
	if names, err := readRuleNames(userRoot); err == nil {
		for _, name := range names {
			if rule, err := readSingleRule(userRoot, name); err == nil {
				if _, exists := ruleMap[name]; !exists {
					order = append(order, name)
				}
				ruleMap[name] = rule
			}
		}
	}

	rules := make([]Rule, 0, len(order))
	for _, name := range order {
		rules = append(rules, ruleMap[name])
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
	if ok, oerr := registry.OpenKey(root, oauthPath, registry.READ); oerr == nil {
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
func readRegString(key registry.Key, name string) (string, bool) {
	val, _, err := key.GetStringValue(name)
	if err != nil {
		return "", false
	}
	return val, true
}

// readRegDWORD reads a REG_DWORD value, returning nil if not found.
func readRegDWORD(key registry.Key, name string) *uint32 {
	val, _, err := key.GetIntegerValue(name)
	if err != nil {
		return nil
	}
	v := uint32(val)
	return &v
}

// readRegMultiString reads a REG_MULTI_SZ value, returning nil if not found.
func readRegMultiString(key registry.Key, name string) []string {
	val, _, err := key.GetStringsValue(name)
	if err != nil {
		return nil
	}
	return val
}
