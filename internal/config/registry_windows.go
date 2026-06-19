//go:build windows

package config

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
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

	// Read the ordered agent key sources from the machine-level policy key.
	agentKeys, err := readRegistryAgentKeys(registry.LOCAL_MACHINE, registryPolicyPath)
	if err != nil {
		return nil, true, fmt.Errorf("read registry agent keys: %w", err)
	}
	cfg.Agent.Keys = agentKeys

	// Read observability headers (a dynamic key/value map) from the
	// machine-level policy key. The scalar observability fields are handled
	// by applyRegistryLayer above; headers live under their own subkey.
	headers, err := readRegistryObservabilityHeaders(registry.LOCAL_MACHINE, registryPolicyPath)
	if err != nil {
		return nil, true, fmt.Errorf("read registry observability headers: %w", err)
	}
	if len(headers) > 0 {
		cfg.Observability.Headers = headers
	}

	// Read remote-config dimension headers (same dynamic key/value map
	// shape as observability headers, under RemoteConfig\Headers).
	remoteHeaders, err := readRegistryRemoteConfigHeaders(registry.LOCAL_MACHINE, registryPolicyPath)
	if err != nil {
		return nil, true, fmt.Errorf("read registry remote-config headers: %w", err)
	}
	if len(remoteHeaders) > 0 {
		cfg.RemoteConfig.Headers = remoteHeaders
	}

	return cfg, true, nil
}

// readRegistryObservabilityHeaders reads the OTLP header map from
// Observability\Headers under the given basePath. Each header is a REG_SZ
// value whose name is the header key. Returns (nil, nil) when the key does
// not exist. Header names are preserved verbatim (not lowercased like
// enrolment Settings): HTTP folds header case, but a faithful round-trip
// keeps whatever the admin authored.
//
// These values are credentials (OTLP bearer tokens). Config conversion is
// lossless in every direction, so the regfile renderer does emit them and
// this loader reads them back; an admin can also author them directly via
// Group Policy.
func readRegistryObservabilityHeaders(root registry.Key, basePath string) (map[string]string, error) {
	return readRegistryHeaderMap(root, basePath+`\Observability\Headers`)
}

// readRegistryRemoteConfigHeaders reads the remote-config dimension header
// map from RemoteConfig\Headers under the given basePath. Unlike
// observability headers these are not credentials — they are client-asserted
// dimension labels (e.g. X-Dotvault-Env) — but they follow the same
// verbatim-name, lossless round-trip contract.
func readRegistryRemoteConfigHeaders(root registry.Key, basePath string) (map[string]string, error) {
	return readRegistryHeaderMap(root, basePath+`\RemoteConfig\Headers`)
}

// readRegistryHeaderMap reads a dynamic header map: every REG_SZ value
// directly under headersPath, keyed by value name. Returns (nil, nil) when
// the key does not exist or holds no values.
func readRegistryHeaderMap(root registry.Key, headersPath string) (map[string]string, error) {
	key, err := registry.OpenKey(root, headersPath, registry.READ)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open headers key at %s: %w", headersPath, err)
	}
	defer key.Close()

	info, err := key.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat headers key %s: %w", headersPath, err)
	}
	if info.ValueCount == 0 {
		return nil, nil
	}

	names, err := key.ReadValueNames(int(info.ValueCount))
	if err != nil {
		return nil, fmt.Errorf("read header value names at %s: %w", headersPath, err)
	}

	headers := make(map[string]string, len(names))
	for _, name := range names {
		if v, ok := readRegString(key, name); ok {
			headers[name] = v
		}
	}
	return headers, nil
}

// registryLayer holds the flat values read from a single registry hive.
type registryLayer struct {
	// Top-level (values directly under the policy root key).
	BypassSystemConfig *uint32

	// Vault
	VaultAddress             string
	VaultCACert              string
	VaultTLSSkipVerify       *uint32
	VaultKVMount             string
	VaultUserPrefix          string
	VaultAuthMethod          string
	VaultAuthRole            string
	VaultAuthMount           string
	VaultDisableTokenRenewal *uint32
	VaultTokenSocket         string

	// Vault\MTLS (cert auth), with BYO under Vault\MTLS\BYO.
	MTLSBootstrapMethod string
	MTLSBootstrapMount  string
	MTLSCertMount       string
	MTLSCertRole        string
	MTLSPKIMount        string
	MTLSPKIRole         string
	MTLSKeyType         string
	MTLSCommonName      string
	MTLSTTL             string
	MTLSReissueBefore   string
	MTLSStorageDir      string
	MTLSSealToPCRs      *uint32
	MTLSBYOCert         string
	MTLSBYOKey          string

	// Sync
	SyncInterval string

	// Web
	WebEnabled        *uint32
	WebListen         string
	WebLoginText      string
	WebSecretViewText string

	// Observability (scalar fields; the Headers map is read separately by
	// readRegistryObservabilityHeaders).
	ObservabilityEnabled  *uint32
	ObservabilityEndpoint string
	ObservabilityProtocol string
	ObservabilityInsecure *uint32
	ObservabilityInterval string

	// Agent (scalar transport settings; the ordered Keys list is read
	// separately by readRegistryAgentKeys).
	AgentEnabled      *uint32
	AgentUnixPath     string
	AgentWindowsPipe  string
	AgentWindowsPutty *uint32

	// RemoteConfig (scalar fields; the Headers map is read separately by
	// readRegistryRemoteConfigHeaders).
	RemoteConfigURL             string
	RemoteConfigRefreshInterval string
	RemoteConfigCACert          string
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

	// Top-level values live directly under the policy root key (no subkey).
	layer.BypassSystemConfig = readRegDWORD(key, "BypassSystemConfig")

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
		layer.VaultTokenSocket, _ = readRegString(vk, "TokenSocket")
	}

	// Read Vault\MTLS subkey (cert auth) and its nested BYO subkey.
	mk, err := registry.OpenKey(root, registryPolicyPath+`\Vault\MTLS`, registry.READ)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return layer, false, fmt.Errorf("open Vault\\MTLS policy key: %w", err)
	}
	if err == nil {
		defer mk.Close()
		layer.MTLSBootstrapMethod, _ = readRegString(mk, "BootstrapMethod")
		layer.MTLSBootstrapMount, _ = readRegString(mk, "BootstrapMount")
		layer.MTLSCertMount, _ = readRegString(mk, "CertMount")
		layer.MTLSCertRole, _ = readRegString(mk, "CertRole")
		layer.MTLSPKIMount, _ = readRegString(mk, "PKIMount")
		layer.MTLSPKIRole, _ = readRegString(mk, "PKIRole")
		layer.MTLSKeyType, _ = readRegString(mk, "KeyType")
		layer.MTLSCommonName, _ = readRegString(mk, "CommonName")
		layer.MTLSTTL, _ = readRegString(mk, "TTL")
		layer.MTLSReissueBefore, _ = readRegString(mk, "ReissueBefore")
		layer.MTLSStorageDir, _ = readRegString(mk, "StorageDir")
		layer.MTLSSealToPCRs = readRegDWORD(mk, "SealToPCRs")
	}
	bk, err := registry.OpenKey(root, registryPolicyPath+`\Vault\MTLS\BYO`, registry.READ)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return layer, false, fmt.Errorf("open Vault\\MTLS\\BYO policy key: %w", err)
	}
	if err == nil {
		defer bk.Close()
		layer.MTLSBYOCert, _ = readRegString(bk, "Cert")
		layer.MTLSBYOKey, _ = readRegString(bk, "Key")
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
		layer.WebLoginText, _ = readRegString(wk, "LoginText")
		layer.WebSecretViewText, _ = readRegString(wk, "SecretViewText")
	}

	// Read Observability subkey (scalar fields only; Headers is a nested
	// key/value map read separately by readRegistryObservabilityHeaders).
	// Without this a GPO-managed daemon would have Observability.Enabled
	// false, Init would short-circuit to an inactive Provider, and the WARN
	// record from LogRegistryConfigManaged would vanish into the no-op
	// global logger — silently dropping the registry-config notification.
	obk, err := registry.OpenKey(root, registryPolicyPath+`\Observability`, registry.READ)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return layer, false, fmt.Errorf("open Observability policy key: %w", err)
	}
	if err == nil {
		defer obk.Close()
		layer.ObservabilityEnabled = readRegDWORD(obk, "Enabled")
		layer.ObservabilityEndpoint, _ = readRegString(obk, "Endpoint")
		layer.ObservabilityProtocol, _ = readRegString(obk, "Protocol")
		layer.ObservabilityInsecure = readRegDWORD(obk, "Insecure")
		layer.ObservabilityInterval, _ = readRegString(obk, "ExportInterval")
	}

	// Read Agent subkey (scalar transport settings only).
	ak, err := registry.OpenKey(root, registryPolicyPath+`\Agent`, registry.READ)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return layer, false, fmt.Errorf("open Agent policy key: %w", err)
	}
	if err == nil {
		defer ak.Close()
		layer.AgentEnabled = readRegDWORD(ak, "Enabled")
		layer.AgentUnixPath, _ = readRegString(ak, "UnixPath")
		layer.AgentWindowsPipe, _ = readRegString(ak, "WindowsPipe")
		layer.AgentWindowsPutty = readRegDWORD(ak, "WindowsPutty")
	}

	// Read RemoteConfig subkey (scalar fields only; Headers is a nested
	// key/value map read separately by readRegistryRemoteConfigHeaders).
	rk, err := registry.OpenKey(root, registryPolicyPath+`\RemoteConfig`, registry.READ)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return layer, false, fmt.Errorf("open RemoteConfig policy key: %w", err)
	}
	if err == nil {
		defer rk.Close()
		layer.RemoteConfigURL, _ = readRegString(rk, "URL")
		layer.RemoteConfigRefreshInterval, _ = readRegString(rk, "RefreshInterval")
		layer.RemoteConfigCACert, _ = readRegString(rk, "CACert")
	}

	return layer, true, nil
}

// applyRegistryLayer merges a registry layer into the config. Only values that
// are *present* in the layer are applied — non-empty strings and non-nil DWORD
// pointers — so a higher-priority layer overrides selectively. Presence, not
// non-zero-ness, gates the merge: a present boolean DWORD of 0 is applied and
// forces the field false (e.g. an explicit BypassSystemConfig=0 clears it).
func applyRegistryLayer(cfg *Config, layer registryLayer) {
	if layer.BypassSystemConfig != nil {
		cfg.BypassSystemConfig = *layer.BypassSystemConfig != 0
	}
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
	if layer.VaultTokenSocket != "" {
		cfg.Vault.TokenSocket = layer.VaultTokenSocket
	}
	if layer.MTLSBootstrapMethod != "" {
		cfg.Vault.MTLS.BootstrapMethod = layer.MTLSBootstrapMethod
	}
	if layer.MTLSBootstrapMount != "" {
		cfg.Vault.MTLS.BootstrapMount = layer.MTLSBootstrapMount
	}
	if layer.MTLSCertMount != "" {
		cfg.Vault.MTLS.CertMount = layer.MTLSCertMount
	}
	if layer.MTLSCertRole != "" {
		cfg.Vault.MTLS.CertRole = layer.MTLSCertRole
	}
	if layer.MTLSPKIMount != "" {
		cfg.Vault.MTLS.PKIMount = layer.MTLSPKIMount
	}
	if layer.MTLSPKIRole != "" {
		cfg.Vault.MTLS.PKIRole = layer.MTLSPKIRole
	}
	if layer.MTLSKeyType != "" {
		cfg.Vault.MTLS.KeyType = layer.MTLSKeyType
	}
	if layer.MTLSCommonName != "" {
		cfg.Vault.MTLS.CommonName = layer.MTLSCommonName
	}
	if layer.MTLSTTL != "" {
		cfg.Vault.MTLS.TTL = layer.MTLSTTL
	}
	if layer.MTLSReissueBefore != "" {
		cfg.Vault.MTLS.ReissueBefore = layer.MTLSReissueBefore
	}
	if layer.MTLSStorageDir != "" {
		cfg.Vault.MTLS.StorageDir = layer.MTLSStorageDir
	}
	if layer.MTLSSealToPCRs != nil {
		cfg.Vault.MTLS.SealToPCRs = *layer.MTLSSealToPCRs != 0
	}
	if layer.MTLSBYOCert != "" {
		cfg.Vault.MTLS.BYO.Cert = layer.MTLSBYOCert
	}
	if layer.MTLSBYOKey != "" {
		cfg.Vault.MTLS.BYO.Key = layer.MTLSBYOKey
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
	if layer.WebLoginText != "" {
		cfg.Web.LoginText = layer.WebLoginText
	}
	if layer.WebSecretViewText != "" {
		cfg.Web.SecretViewText = layer.WebSecretViewText
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
	if layer.ObservabilityInterval != "" {
		cfg.Observability.RawInterval = layer.ObservabilityInterval
	}
	if layer.AgentEnabled != nil {
		cfg.Agent.Enabled = *layer.AgentEnabled != 0
	}
	if layer.AgentUnixPath != "" {
		cfg.Agent.Unix.Path = layer.AgentUnixPath
	}
	if layer.AgentWindowsPipe != "" {
		cfg.Agent.Windows.Pipe = layer.AgentWindowsPipe
	}
	if layer.AgentWindowsPutty != nil {
		b := *layer.AgentWindowsPutty != 0
		cfg.Agent.Windows.Putty = &b
	}
	if layer.RemoteConfigURL != "" {
		cfg.RemoteConfig.URL = layer.RemoteConfigURL
	}
	if layer.RemoteConfigRefreshInterval != "" {
		cfg.RemoteConfig.RawRefreshInterval = layer.RemoteConfigRefreshInterval
	}
	if layer.RemoteConfigCACert != "" {
		cfg.RemoteConfig.CACert = layer.RemoteConfigCACert
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

// readRegistryAgentKeys reads the ordered SSH-agent key sources from
// Agent\Keys under the given root. Each source is a subkey named after its
// zero-based list index; the names are sorted numerically so the slice is
// rebuilt in the order the YAML/.reg encoded it. A non-integer subkey name is
// a hard error — the renderer only ever emits numeric indices, so anything
// else means hand-edited or foreign input and silently reordering (or
// dropping) it would change which key the agent presents.
// Returns (nil, nil) when the Agent\Keys key does not exist. basePath is the
// registry path containing the Agent subkey (registryPolicyPath in production;
// a temporary path under HKCU in tests).
//
// The numeric-sort-with-reject logic here is a twin of
// regfile.sortAgentKeyNames (internal/regfile/parse.go). They can't share code
// — this file is //go:build windows, regfile is platform-neutral — so keep the
// two in lockstep when the ordering contract changes.
func readRegistryAgentKeys(root registry.Key, basePath string) ([]AgentKeySource, error) {
	keysPath := basePath + `\Agent\Keys`
	key, err := registry.OpenKey(root, keysPath, registry.READ)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open Agent\\Keys key at %s: %w", keysPath, err)
	}
	defer key.Close()

	info, err := key.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat Agent\\Keys key: %w", err)
	}

	names, err := key.ReadSubKeyNames(int(info.SubKeyCount))
	if err != nil {
		return nil, fmt.Errorf("enumerate agent key subkeys: %w", err)
	}

	type idx struct {
		name string
		n    int
	}
	parsed := make([]idx, 0, len(names))
	for _, name := range names {
		n, err := strconv.Atoi(name)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("agent key subkey %q under HKLM\\%s is not a non-negative integer index", name, keysPath)
		}
		parsed = append(parsed, idx{name: name, n: n})
	}
	sort.Slice(parsed, func(i, j int) bool { return parsed[i].n < parsed[j].n })

	sources := make([]AgentKeySource, 0, len(parsed))
	for _, p := range parsed {
		src, err := readSingleAgentKey(root, keysPath+`\`+p.name)
		if err != nil {
			return nil, fmt.Errorf("read agent key %q: %w", p.name, err)
		}
		sources = append(sources, src)
	}
	return sources, nil
}

// readSingleAgentKey reads one AgentKeySource from its registry subkey.
func readSingleAgentKey(root registry.Key, path string) (AgentKeySource, error) {
	key, err := registry.OpenKey(root, path, registry.READ)
	if err != nil {
		return AgentKeySource{}, err
	}
	defer key.Close()

	src := AgentKeySource{}
	src.Source, _ = readRegString(key, "Source")
	src.PathPrefix, _ = readRegString(key, "PathPrefix")
	src.Mount, _ = readRegString(key, "Mount")
	src.Role, _ = readRegString(key, "Role")
	src.TTL, _ = readRegString(key, "TTL")
	if v := readRegDWORD(key, "EphemeralKey"); v != nil {
		src.EphemeralKey = *v != 0
	}
	// readRegMultiString returns nil for both an absent and an empty
	// REG_MULTI_SZ. Unlike the regfile parser (which preserves the
	// `principals: []` vs absent distinction for .reg round-trip fidelity),
	// the live loader doesn't need it: nil and []string{} both mean "no
	// principals" to the agent, which substitutes the role's defaults. This
	// matches how the existing OAuth Scopes registry read already behaves.
	src.Principals = readRegMultiString(key, "Principals")
	return src, nil
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
