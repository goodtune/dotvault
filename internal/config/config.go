package config

import (
	"errors"
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
	// Bare Nd: digits followed by 'd' with nothing after. Use ParseInt
	// rather than Atoi so that very-large-day values that overflow int are
	// caught here (Atoi returns "value out of range", which would otherwise
	// fall through to time.ParseDuration and produce a confusing "unknown
	// unit d" error). A minus sign is allowed through ParseInt but rejected
	// explicitly below so the error message is clear.
	if strings.HasSuffix(s, "d") {
		num := s[:len(s)-1]
		days, err := strconv.ParseInt(num, 10, 64)
		if err != nil {
			// Is the parse failure because the numeral is out of int64 range?
			// That's a clear "too big" case — surface it directly instead of
			// handing the string to time.ParseDuration where "d" is an
			// unknown unit and the error would be confusing.
			if numErr, ok := err.(*strconv.NumError); ok && numErr.Err == strconv.ErrRange {
				return 0, fmt.Errorf("duration %q exceeds representable range", s)
			}
			// Not a bare Nd (e.g. "1.5d", "1dd", "1d12h") — fall through to
			// stdlib, which will produce the standard "unknown unit" error.
			return time.ParseDuration(s)
		}
		if days < 0 {
			return 0, fmt.Errorf("negative duration: %q", s)
		}
		// Guard against int64 overflow when converting to nanoseconds.
		// time.Duration is nanoseconds in an int64 so max representable
		// days ≈ MaxInt64 / (24 * time.Hour in ns).
		const maxDays = int64(math.MaxInt64 / int64(24*time.Hour))
		if days > maxDays {
			return 0, fmt.Errorf("duration %q exceeds time.Duration range (max %dd)", s, maxDays)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// Default connectivity values applied by validate(). Exported so the public
// client facade (client/config.go) can apply the same defaults to a
// hand-constructed config without re-typing the literals — keeping the two
// from silently drifting.
const (
	DefaultKVMount    = "kv"
	DefaultUserPrefix = "users/"

	// mTLS / cert-auth defaults applied by validate() when auth_method is
	// "mtls", "mtls+tpm", or "mtls+os".
	DefaultCertMount      = "cert"
	DefaultPKIMount       = "pki"
	DefaultMTLSKeyType    = "ec"
	DefaultMTLSCommonName = "{{.user}}"
	DefaultReissueBefore  = 168 * time.Hour // 7d
	// DefaultMTLSOSTTL is the certificate TTL requested by mtls+os when ttl is
	// unset. The OS-store credential is a general-purpose user identity (used by
	// browsers, not just dotvault), so it defaults to a longer 30d lifetime than
	// the unset "let the PKI role decide" behaviour of plain mtls/mtls+tpm. The
	// Vault PKI role's max_ttl remains the authoritative cap.
	DefaultMTLSOSTTL = "720h" // 30d

	// DefaultAgentPipe is the Windows named pipe the SSH agent listens on
	// when agent.windows.pipe is unset. dotvault claims its own pipe rather
	// than the well-known \\.\pipe\openssh-ssh-agent so it never contends
	// with the built-in ssh-agent service.
	DefaultAgentPipe = `\\.\pipe\dotvault-agent`
)

// Config is the top-level system configuration.
type Config struct {
	Vault         VaultConfig          `yaml:"vault"`
	Sync          SyncConfig           `yaml:"sync"`
	Web           WebConfig            `yaml:"web"`
	Observability ObservabilityConfig  `yaml:"observability,omitempty"`
	Agent         AgentConfig          `yaml:"agent,omitempty"`
	API           APIConfig            `yaml:"api,omitempty"`
	SSH           SSHConfig            `yaml:"ssh,omitempty"`
	RemoteConfig  RemoteConfig         `yaml:"remote_config,omitempty"`
	Rules         []Rule               `yaml:"rules"`
	Enrolments    map[string]Enrolment `yaml:"enrolments"`

	// BypassSystemConfig, when set in the system-wide configuration (the
	// YAML at paths.SystemConfigPath(), or the Windows Group Policy
	// registry), permits this machine to honour a --config command-line
	// override instead of the system config. Default false: with a
	// system-wide config present and this flag unset, --config is refused.
	// The intent is that an admin normally pins the system config but can
	// flip this flag to trial a hand-edited config without un-deploying the
	// policy. Enforcement lives in cmd/dotvault (resolveConfigSource +
	// SystemConfigBypass); the value itself is just data and behaves the
	// same on every platform.
	BypassSystemConfig bool `yaml:"bypass_system_config"`

	// Managed is set by LoadSystem when the config originated from the
	// Windows Registry (Group Policy) rather than the YAML file. The
	// daemon uses it to emit a one-shot WARN OTel log record after
	// observability.Init runs; deliberately not serialised so an
	// exported YAML/.reg artefact never carries the flag back in.
	Managed bool `yaml:"-"`
}

// ObservabilityConfig configures the OpenTelemetry metric and log
// exporters. Each signal is configured in its nested Metrics/Logs block, so
// the two can go to separate backends or one can be switched off. The
// top-level Endpoint / Protocol / Insecure / Headers fields are shared
// defaults the signal blocks layer onto — still functional, but DEPRECATED
// (staged removal, tracking issue #140): using them draws a startup WARN
// plus a dotvault.config.deprecated increment per field (see
// DeprecatedSharedFields), and 1.0 removes them in favour of per-signal-only
// configuration with the OTEL_* env vars as the cross-signal sharing
// mechanism. Disabled by default — set Enabled and a signal's Endpoint (or
// the standard OTEL_* env vars) to point the daemon at an OTel collector.
//
// The layering deliberately mirrors the OTel SDK's own environment-variable
// convention (generic OTEL_EXPORTER_OTLP_* plus signal-specific
// OTEL_EXPORTER_OTLP_METRICS_* / _LOGS_* overrides), so an operator who
// knows one model knows both. Resolution lives in ResolveSignal.
//
// The inner fields deliberately do NOT carry `omitempty`. The
// project's YAML/regfile round-trip contract (see
// internal/regfile/yaml.go) emits empty optional fields explicitly
// so a re-import can clear previously-set values; omitempty here
// would let a cleared endpoint or protocol silently persist its
// previous value across an export → re-import cycle. The
// top-level Observability field on Config keeps `omitempty` so
// operators who don't use observability at all don't see a noisy
// empty block in their downloads.
//
// Headers (which may hold OTLP bearer tokens) are emitted verbatim on
// export. dotvault treats config conversion as lossless in every
// direction — YAML <-> in-memory <-> .reg/registry — so no serialiser
// strips them. The trade-off is deliberate: an exported config artefact
// (the web download endpoint, a reg-export, a YAML round-trip) carries
// the live header values. Operators who want to keep tokens out of
// checked-in config should set them via OTEL_EXPORTER_OTLP_HEADERS in the
// per-user EnvironmentFile and leave Headers empty; the SDK falls through
// to those env vars when the field is unset.
type ObservabilityConfig struct {
	Enabled        bool              `yaml:"enabled"`
	Endpoint       string            `yaml:"endpoint"`
	Protocol       string            `yaml:"protocol"`
	Insecure       bool              `yaml:"insecure"`
	Headers        map[string]string `yaml:"headers"`
	RawInterval    string            `yaml:"export_interval"`
	ExportInterval time.Duration     `yaml:"-"`

	// Metrics and Logs override the shared fields above per signal. The
	// zero value inherits everything, so existing configs behave exactly
	// as before.
	Metrics ObservabilitySignalConfig `yaml:"metrics"`
	Logs    ObservabilitySignalConfig `yaml:"logs"`
}

// ObservabilitySignalConfig is one signal's overrides of the shared
// observability fields. Empty/nil fields inherit; see ResolveSignal for the
// exact semantics of each.
//
// Enabled and Insecure are pointers for the same tri-state reason as
// AgentWindowsConfig.Putty: an unset value must stay distinguishable from
// an explicit false (unset inherits, explicit false overrides), and a nil
// pointer is the default rather than a "cleared" value that must be
// re-emitted, so `omitempty` is correct on exactly those two fields. The
// string and map fields follow the section's round-trip contract and are
// always emitted.
type ObservabilitySignalConfig struct {
	// Enabled switches this signal on or off. Unset (nil) means enabled
	// whenever the top-level observability.enabled is — the top-level flag
	// remains the master switch, and a per-signal true can only select,
	// never resurrect a disabled subsystem.
	Enabled *bool `yaml:"enabled,omitempty"`
	// Endpoint, when non-empty, replaces the shared endpoint for this
	// signal — the "separate backends" field. A full URL is the
	// recommended form: the scheme carries the TLS intent and an explicit
	// path is used verbatim (no assumed mount path); see
	// observability.Signal.Endpoint for the complete value contract.
	Endpoint string `yaml:"endpoint"`
	// Protocol, when non-empty, replaces the shared protocol ("grpc" or
	// "http/protobuf") for this signal.
	Protocol string `yaml:"protocol"`
	// Insecure, when set, replaces the shared insecure flag for this
	// signal.
	Insecure *bool `yaml:"insecure,omitempty"`
	// Headers, when non-nil, REPLACES the shared headers map for this
	// signal — no merging, matching the OTel env-var convention where a
	// signal-specific OTEL_EXPORTER_OTLP_LOGS_HEADERS supersedes the
	// generic value wholesale. Merging credential maps invites sending one
	// backend's bearer token to the other. An explicitly empty map
	// (`headers: {}`) therefore means "this signal sends no headers" even
	// when the shared map is populated.
	//
	// nil-vs-empty is semantic (inherit vs suppress), and no struct tag can
	// express it: `omitempty` collapses both to absent, and no tag emits
	// `{}` for empty while omitting nil. The custom MarshalYAML below is
	// what preserves the distinction on emission; without it a single
	// export→import cycle through the config-download or reg-export YAML
	// would turn "inherit the shared credentials" into "send none",
	// silently detaching auth from both signals.
	Headers map[string]string `yaml:"headers"`
	// Temporality is the metric temporality preference — "cumulative",
	// "delta", or "lowmemory", the exact vocabulary of
	// OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE (which an empty
	// value falls through to). Meaningful on the metrics block only:
	// temporality is a metric concept with no log analogue, so validation
	// rejects it on `logs` rather than silently ignoring a setting the
	// operator believed took effect. It lives on the per-signal struct
	// (not the deprecated shared layer) because new exporter knobs go
	// where the config is headed, not where it is leaving.
	Temporality string `yaml:"temporality"`
}

// MarshalYAML preserves the Headers nil-vs-empty distinction on the YAML
// emission path (config download, reg-export): a nil map omits the
// `headers:` key entirely (inherit), while a non-nil map — including an
// empty one — emits it (`headers: {}` = this signal sends no headers). The
// scalar fields keep the section's always-emit round-trip contract, and the
// tri-state pointers keep their omit-when-unset behaviour.
func (s ObservabilitySignalConfig) MarshalYAML() (any, error) {
	// Keep this scalar mirror in lockstep with ObservabilitySignalConfig:
	// a field added there and forgotten here is silently DROPPED from
	// every YAML export (config download, reg-export) — the regfile
	// round-trip tests are what catch the drift.
	type scalars struct {
		Enabled     *bool  `yaml:"enabled,omitempty"`
		Endpoint    string `yaml:"endpoint"`
		Protocol    string `yaml:"protocol"`
		Insecure    *bool  `yaml:"insecure,omitempty"`
		Temporality string `yaml:"temporality"`
	}
	base := scalars{
		Enabled:     s.Enabled,
		Endpoint:    s.Endpoint,
		Protocol:    s.Protocol,
		Insecure:    s.Insecure,
		Temporality: s.Temporality,
	}
	if s.Headers == nil {
		return base, nil
	}
	return struct {
		scalars `yaml:",inline"`
		Headers map[string]string `yaml:"headers"`
	}{base, s.Headers}, nil
}

// ResolvedSignal is one signal's effective exporter settings after
// layering its overrides onto the shared observability fields.
//
// Keep in lockstep with observability.Signal and the field-by-field copy in
// cmd/dotvault's initObservability: the two structs are deliberately
// separate (the observability package must not import this one), so a field
// added here and forgotten there compiles silently and drops.
type ResolvedSignal struct {
	Enabled     bool
	Endpoint    string
	Protocol    string
	Insecure    bool
	Headers     map[string]string
	Temporality string
}

// ResolveSignal layers a signal's overrides onto the shared fields.
// Semantics per field: Enabled is the top-level master switch AND-ed with
// the signal's own flag (unset = true); Endpoint and Protocol override when
// non-empty; Insecure overrides when set; Headers replace wholesale when
// non-nil. An empty resolved Endpoint still works — the OTel exporters fall
// through to the standard OTEL_EXPORTER_OTLP_* (and signal-specific)
// environment variables exactly as before.
func (o ObservabilityConfig) ResolveSignal(sig ObservabilitySignalConfig) ResolvedSignal {
	r := ResolvedSignal{
		Enabled:  o.Enabled && (sig.Enabled == nil || *sig.Enabled),
		Endpoint: o.Endpoint,
		Protocol: o.Protocol,
		Insecure: o.Insecure,
		Headers:  o.Headers,
		// Temporality has no shared-layer default to inherit — it is
		// per-signal-only by design (see the field's godoc), so the
		// signal's own value passes straight through.
		Temporality: sig.Temporality,
	}
	if sig.Endpoint != "" {
		r.Endpoint = sig.Endpoint
	}
	if sig.Protocol != "" {
		r.Protocol = sig.Protocol
	}
	if sig.Insecure != nil {
		r.Insecure = *sig.Insecure
	}
	if sig.Headers != nil {
		r.Headers = sig.Headers
	}
	return r
}

// MetricsSignal and LogsSignal are the two concrete resolutions; every
// consumer (the daemon's exporter wiring, the docs' description of what a
// config means) goes through these so the layering is defined in exactly
// one place.
func (o ObservabilityConfig) MetricsSignal() ResolvedSignal { return o.ResolveSignal(o.Metrics) }
func (o ObservabilityConfig) LogsSignal() ResolvedSignal    { return o.ResolveSignal(o.Logs) }

// DeprecatedSharedFields reports which of the deprecated shared exporter
// fields are in use, as dotted YAML paths ("observability.endpoint", …).
// The shared endpoint/protocol/insecure/headers layer is being retired in
// stages in favour of the per-signal metrics:/logs: blocks: this release
// warns and meters the usage, a later release makes the warning louder, and
// 1.0 removes the fields. Enabled (the master switch) and export_interval
// (which has no per-signal home yet) are not part of the deprecation.
//
// Detection is presence-based, matching what the fields can express:
// endpoint/protocol when non-empty, insecure only when true (the shared
// field is a plain bool, so an explicit false is indistinguishable from
// unset), headers when non-empty (for the shared map, nil and {} mean the
// same thing — only the per-signal maps carry the presence distinction).
// The caller decides how to surface the result; this stays a pure query so
// the config package does not log or meter.
func (o ObservabilityConfig) DeprecatedSharedFields() []string {
	var fields []string
	if o.Endpoint != "" {
		fields = append(fields, "observability.endpoint")
	}
	if o.Protocol != "" {
		fields = append(fields, "observability.protocol")
	}
	if o.Insecure {
		fields = append(fields, "observability.insecure")
	}
	if len(o.Headers) > 0 {
		fields = append(fields, "observability.headers")
	}
	return fields
}

// validateOTLPProtocol accepts the OTel canonical names from the
// OTEL_EXPORTER_OTLP_PROTOCOL spec, or empty (inherit / SDK default). One
// helper for the shared field and both per-signal overrides so the accepted
// set cannot drift between them.
func validateOTLPProtocol(field, protocol string) error {
	switch strings.ToLower(protocol) {
	case "", "grpc", "http/protobuf":
		return nil
	default:
		return fmt.Errorf("%s %q: must be grpc or http/protobuf", field, protocol)
	}
}

// validateOTLPTemporality accepts the vocabulary of
// OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE, or empty (fall through
// to that env var / the SDK's cumulative default). Kept in lockstep with
// observability.temporalitySelector, which maps the same names onto the SDK
// selectors.
func validateOTLPTemporality(field, temporality string) error {
	// Identical normalization to observability.temporalitySelector —
	// lockstep means a value that validates here must resolve there.
	switch strings.ToLower(strings.TrimSpace(temporality)) {
	case "", "cumulative", "delta", "lowmemory":
		return nil
	default:
		return fmt.Errorf("%s %q: must be cumulative, delta, or lowmemory", field, temporality)
	}
}

// Enrolment declares a credential acquisition flow for a Vault KV key.
type Enrolment struct {
	Engine   string         `yaml:"engine"`
	Settings map[string]any `yaml:"settings"`
	// HelpText is optional admin-authored markdown, rendered to HTML and
	// shown alongside this enrolment in the web UI to explain what the
	// engine does for the user before they run it.
	HelpText string `yaml:"help_text,omitempty"`
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
	// OIDCCallbackPort is the fixed local TCP port the "oidc"/"oidc+tpm" CLI
	// flow (dotvault login, and the mtls bootstrap sub-login) binds for the
	// OAuth redirect_uri, so operators can register one predictable
	// http://127.0.0.1:<port>/oidc/callback URI with both the Vault auth
	// role's allowed_redirect_uris and the identity provider, instead of
	// depending on RFC 8252 loopback (port-agnostic) redirect matching that
	// not every IdP implements. Zero (the default) resolves to 8250, the
	// same default the `vault` CLI itself uses, so a role/IdP already
	// configured for `vault login -method=oidc` typically works for
	// dotvault without any change. If the configured (or default) port is
	// already in use, dotvault falls back to an OS-assigned random port and
	// logs why. Not consulted by the daemon's web UI flow, which always
	// binds web.listen. See docs/authentication/oidc.md.
	OIDCCallbackPort int `yaml:"oidc_callback_port"`
	// Policies is the least-privilege set of Vault policies the working token
	// should carry. When non-empty, dotvault does not run with the token its
	// auth role grants directly; instead it exchanges that login token for a
	// child token restricted to exactly these policies (Vault enforces that the
	// requested set is a subset of the login token's own policies). Empty — the
	// default — keeps today's behaviour: the token carries every policy the
	// auth role granted, which over-provisions a credential that could leak.
	//
	// This is a per-deployment concern; dotvault ships no default policy list
	// because the right set is specific to each operator's Vault policy layout.
	// See docs/configuration/config-reference.md for the staged rollout — a
	// future release defaults NoDefaultPolicy to true, and 1.0 will make it
	// impossible to run a token carrying the implicit `default` policy.
	Policies []string `yaml:"policies"`
	// NoDefaultPolicy, when true, strips the implicit `default` policy from the
	// working token (it sets no_default_policy on the downscoped child token).
	// Default false today for backwards compatibility; a future release flips
	// the default to true and 1.0 removes the ability to set it false. Combine
	// with Policies to pin a token to exactly the capabilities dotvault needs.
	NoDefaultPolicy     bool `yaml:"no_default_policy"`
	DisableTokenRenewal bool `yaml:"disable_token_renewal"`
	// TokenSocket is an optional path to a Unix-domain socket served by a
	// peer dotvault daemon's web API. When set, dotvault tries to borrow a
	// live Vault token from the peer via `GET http://localhost/api/v1/token`
	// over this socket — the equivalent of
	// `curl --unix-socket <path> http://localhost/api/v1/token` — before
	// falling back to its own authentication. The borrow runs where dotvault
	// would otherwise authenticate interactively: on a fresh login (Manager
	// .Login, after Authenticate finds no usable cached token) and on the
	// lifecycle recovery path after a cached token goes invalid; a healthy
	// RenewSelf renewal does not borrow. This is the dotvault-to-dotvault
	// token-sharing seam: a machine with no interactive login facility (no
	// browser, no TTY) borrows the token from a peer that has one, reached
	// over an SSH RemoteForward'd socket. A leading ~ is expanded to the
	// user's home. A missing or stale socket is ignored — the normal auth
	// flow proceeds — so the field is purely additive and needs no validation.
	TokenSocket string `yaml:"token_socket"`
	// MTLS configures the cert auth methods. It is consulted only when
	// AuthMethod drives the cert-auth flow ("mtls", "mtls+tpm", "mtls+os").
	MTLS MTLSConfig `yaml:"mtls"`
}

// MTLSConfig configures certificate-based Vault authentication (the "mtls",
// "mtls+tpm", and "mtls+os" auth methods). A TLS client certificate
// authenticates instead of a human credential; LDAP/OIDC is demoted to a
// one-time bootstrap that mints the first certificate via the Vault PKI engine.
// The key is held on disk ("mtls"), TPM-sealed ("mtls+tpm"), or in the
// OS-native certificate store where browsers can present it ("mtls+os").
type MTLSConfig struct {
	// BootstrapMethod is the human-credential method used only to mint the
	// first certificate ("ldap" or "oidc"). Default "oidc".
	BootstrapMethod string `yaml:"bootstrap_method"`
	// BootstrapMount overrides the auth mount for the bootstrap login.
	// Default: the method name (the same default the bootstrap flow applies).
	BootstrapMount string `yaml:"bootstrap_mount"`
	// CertMount is the Vault cert auth mount. Default "cert".
	CertMount string `yaml:"cert_mount"`
	// CertRole is the cert auth role name presented at login. Required.
	CertRole string `yaml:"cert_role"`
	// PKIMount is the PKI secrets engine used to issue/sign. Default "pki".
	PKIMount string `yaml:"pki_mount"`
	// PKIRole is the PKI role. Required when issuance is possible (no BYO).
	PKIRole string `yaml:"pki_role"`
	// KeyType is "ec" (P-256) or "rsa" (2048). Default "ec". The mtls+tpm
	// backend supports "ec" only; mtls/mtls+os accept both.
	KeyType string `yaml:"key_type"`
	// CommonName is a Go template (over {{.user}}) for the certificate CN.
	// Default "{{.user}}".
	CommonName string `yaml:"common_name"`
	// TTL is an optional client-side TTL hint passed to issue/sign; the PKI
	// role's TTL remains authoritative.
	TTL string `yaml:"ttl"`
	// ReissueBefore is how long before expiry to rotate the certificate.
	// Default 168h (7d).
	ReissueBefore    string        `yaml:"reissue_before"`
	ReissueBeforeDur time.Duration `yaml:"-"`
	// SealToPCRs binds the TPM unseal to the current boot (PCR) state.
	// mtls+tpm only.
	SealToPCRs bool `yaml:"seal_to_pcrs"`
	// StorageDir holds the credential envelope. Default {cache_dir}/mtls.
	StorageDir string `yaml:"storage_dir"`
	// BYO supplies an existing certificate, skipping bootstrap.
	BYO MTLSBYO `yaml:"byo"`
}

// MTLSBYO points at an existing certificate and key on disk (the bring-your-own
// seeding path). Both must be set together, or neither.
type MTLSBYO struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
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

// AgentConfig configures the SSH agent surface. Disabled by default; when
// enabled the daemon serves an agent.ExtendedAgent over a Unix domain socket
// (Linux/macOS) or a named pipe (Windows), backed by the live Vault token.
//
// The inner fields deliberately omit `omitempty` for the same round-trip
// reason as ObservabilityConfig: an exported config must re-emit cleared
// optional values so a re-import can blank a previously-set path or pipe. The
// top-level Agent field keeps `omitempty` so operators who don't use the agent
// see no empty block in downloads.
type AgentConfig struct {
	Enabled bool               `yaml:"enabled"`
	Unix    AgentUnixConfig    `yaml:"unix"`
	Windows AgentWindowsConfig `yaml:"windows"`
	Keys    []AgentKeySource   `yaml:"keys"`
}

// APIConfig configures the local API socket: the daemon's web API served over
// a per-user Unix domain socket in addition to (or instead of) the loopback
// TCP listener that web.enabled controls.
//
// It exists for the dotvault-to-dotvault token borrow. A workstation forwards
// its web API to a remote host over an SSH RemoteForward, and processes on
// that host borrow the live token via vault.token_socket — but the forwarded
// socket dies with the SSH session, so a long-running process (a tmux job
// that outlives the connection) loses its only source of tokens. Enabling
// this makes the long-lived per-user daemon serve the same borrow endpoint
// from a stable path that no disconnect can take away: the daemon keeps its
// own token alive (re-borrowing across the forwarded socket when the SSH
// session returns) and local clients borrow from it instead.
//
// Deliberately separate from web.enabled. The two surfaces have different
// audiences and different exposure: the TCP listener is a browser UI
// reachable by every uid on the box, while this socket is owner-only (0600 in
// a 0700 directory) and carries no SPA. An operator who wants the borrow
// endpoint on a headless host should not have to stand up a web UI to get it,
// and enabling it does not widen what web.enabled already exposes.
//
// Unix only for now. Windows has no equivalent surface yet — the analogue
// would be a named pipe with a protected DACL, mirroring the SSH agent's
// listener — so enabling this on Windows logs a warning and serves nothing.
// The nested `unix:` block (rather than a flat `path:`) is what leaves room
// for a sibling `windows:` block to be added without reshaping the section
// across YAML, the registry, and .reg.
//
// The inner fields deliberately omit `omitempty` for the same round-trip
// reason as AgentConfig: an exported config must re-emit cleared optional
// values so a re-import can blank a previously-set path. The top-level API
// field keeps `omitempty` so operators who don't use the socket see no empty
// block in downloads.
type APIConfig struct {
	Enabled bool          `yaml:"enabled"`
	Unix    APIUnixConfig `yaml:"unix"`
}

// APIUnixConfig holds the Unix-domain-socket transport settings for the local
// API surface.
type APIUnixConfig struct {
	// Path is the socket path. Empty resolves to the per-user runtime path
	// at daemon-start time (see paths.DefaultAPISocket). A leading ~ is
	// expanded, as it is for vault.token_socket.
	Path string `yaml:"path"`
}

// SSHConfig holds the admin-owned trust material for daemon-managed SSH
// forwards. The remotes themselves are deliberately *not* here: they live in
// the user-level ssh.yaml (see paths.SSHConfigPath), which has no registry
// surface because it is user-writable and must never act as policy.
//
// The inner fields omit `omitempty` for the same round-trip reason as
// AgentConfig: an exported config must re-emit cleared optional values so a
// re-import can blank a previously-set list. The top-level SSH field keeps
// `omitempty` so operators who do not use managed forwards see no empty block.
//
// The daemon applies a config-refresh-loop change to this section without a
// restart (see cmd/dotvault's updateSSHPolicyConfig), but only on a remote's
// *next* connection attempt: an already-established forward keeps using the
// HostKeyPolicy it dialled with. Removing a CA, or turning
// InsecureIgnoreHostKey back off, does not retroactively drop or re-verify a
// forward that is already connected — it only takes effect on the next
// reconnect.
type SSHConfig struct {
	// CertificateAuthorities lists trusted SSH host CAs in known_hosts
	// @cert-authority form. A host whose certificate one of these signed
	// needs no per-host pin in ssh.yaml.
	CertificateAuthorities []string `yaml:"certificate_authorities"`

	// InsecureIgnoreHostKey disables host-key verification entirely.
	//
	// It lives in the system config rather than the user's ssh.yaml because
	// it is a security downgrade; on a personal machine the user is the admin
	// anyway. Every connection attempt made under it logs a WARN naming the
	// host, so it cannot be set once and forgotten silently.
	InsecureIgnoreHostKey bool `yaml:"insecure_ignore_host_key"`
}

// AgentUnixConfig holds the Unix-domain-socket transport settings.
type AgentUnixConfig struct {
	// Path is the socket path. Empty resolves to the per-user runtime path
	// at agent-construction time (see paths.DefaultAgentSocket).
	Path string `yaml:"path"`
}

// AgentWindowsConfig holds the named-pipe transport settings.
type AgentWindowsConfig struct {
	// Pipe is the pipe name. Empty resolves to DefaultAgentPipe.
	Pipe string `yaml:"pipe"`

	// Putty controls whether a second named pipe following the PuTTY/Pageant
	// naming convention (\\.\pipe\pageant.<user>.<hash>) is served alongside
	// Pipe, so PuTTY-family clients (PuTTY, WinSCP, FileZilla, …) that speak
	// the Pageant protocol over a named pipe find the agent without any
	// client-side configuration. A Windows named pipe carries exactly one
	// name, so this is an additional parallel listener, not an alias of Pipe.
	// Defaults to true; only takes effect when the agent is enabled and only
	// on Windows.
	//
	// A pointer (unlike the surrounding fields) so an unset value defaults to
	// true while an explicit `putty: false` stays distinguishable and
	// round-trips. `omitempty` is therefore correct here — a nil pointer is
	// the default, not a "cleared" value that must be re-emitted, so it does
	// not share the round-trip rationale documented on AgentConfig for the
	// string fields.
	Putty *bool `yaml:"putty,omitempty"`
}

// PuttyEnabled reports whether the Pageant-compatible named pipe should be
// served. An unset value (nil) defaults to true.
func (w AgentWindowsConfig) PuttyEnabled() bool {
	return w.Putty == nil || *w.Putty
}

// AgentKeySource is one ordered origin of signing identities: either raw keys
// discovered under a KV path prefix, or short-lived certificates minted by a
// Vault SSH CA.
type AgentKeySource struct {
	// Source selects the engine: "kv" or "vault-ca".
	Source string `yaml:"source"`

	// PathPrefix (kv) is resolved under kv/data/{user_prefix}{you}/; every
	// secret beneath it is treated as an SSH key (public_key/private_key
	// fields). Empty means the whole per-user prefix.
	PathPrefix string `yaml:"path_prefix,omitempty"`

	// Mount, Role, Principals, TTL, EphemeralKey (vault-ca) describe the SSH
	// CA secrets engine and the certificate to mint. Principals are Go
	// templates evaluated against {vault_username}.
	Mount        string   `yaml:"mount,omitempty"`
	Role         string   `yaml:"role,omitempty"`
	Principals   []string `yaml:"principals,omitempty"`
	TTL          string   `yaml:"ttl,omitempty"`
	EphemeralKey bool     `yaml:"ephemeral_key,omitempty"`
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
	"yaml":       true,
	"json":       true,
	"ini":        true,
	"toml":       true,
	"text":       true,
	"netrc":      true,
	"ssh_config": true,
}

// LoadSystem loads configuration using the platform-appropriate source.
// On Windows, if Group Policy registry keys exist under
// HKLM\SOFTWARE\Policies\goodtune\dotvault, configuration is loaded from
// the registry and the file-based config at path is ignored. Only
// machine-level (HKLM) policy is read; HKCU is intentionally skipped
// because it is user-writable and cannot be treated as a trusted policy
// boundary on unmanaged machines.
// On non-Windows platforms this falls back to Load(path).
//
// When the registry path wins, the returned Config has Managed=true so
// the caller can emit a deployment-fact notification (today: a
// WARN-severity OTel log record via observability.LogRegistryConfigManaged)
// after the OTel logger provider is wired up. Doing so here would
// either spam stdout on every CLI invocation under GPO or vanish into
// the no-op logger that exists before observability.Init runs.
func LoadSystem(path string) (*Config, error) {
	cfg, err := LoadSystemRaw(path)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		if cfg.Managed {
			return nil, fmt.Errorf("validate registry config: %w", err)
		}
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return cfg, nil
}

// LoadSystemRaw is LoadSystem without the final validation pass: it resolves
// the platform-appropriate source (registry vs YAML file, with Managed set
// exactly as LoadSystem does) and parses it, but leaves validation to the
// caller. The remote-config overlay needs this seam: a base that declares
// remote_config may legitimately fail full validation on its own (e.g. zero
// rules), so the loader parses the base, merges the fetched overlay, then
// runs Validate on the merged result.
func LoadSystemRaw(path string) (*Config, error) {
	cfg, managed, err := loadFromRegistry()
	if err != nil {
		return nil, fmt.Errorf("read registry config: %w", err)
	}
	if managed {
		cfg.Managed = true
		return cfg, nil
	}
	return LoadRaw(path)
}

// SystemConfigBypass reports whether the system-wide configuration permits a
// command-line --config override to replace it.
//
// The rule is identical on every platform: a --config override is allowed
// when there is no system-wide configuration at all, or when the system-wide
// configuration explicitly opts in via `bypass_system_config: true`. A
// machine carrying a system config that does not set the flag refuses the
// override, so a managed deployment (Windows Group Policy, or a system config
// file shipped by configuration management) cannot be sidestepped from the
// command line.
//
// "System-wide configuration" means the Windows GPO registry policy when
// present — it wins exactly as LoadSystem treats it — otherwise the YAML file
// at systemPath. systemPath should be paths.SystemConfigPath().
//
// Returns true when no system-wide config exists; otherwise returns the
// bypass flag read from whichever source is authoritative. A registry read
// error, or a system config file that exists but cannot be read or parsed,
// is surfaced as an error rather than silently allowing the override.
func SystemConfigBypass(systemPath string) (bool, error) {
	cfg, managed, err := loadFromRegistry()
	if err != nil {
		return false, fmt.Errorf("read registry config: %w", err)
	}
	if managed {
		return cfg.BypassSystemConfig, nil
	}

	data, err := os.ReadFile(systemPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No system-wide config — the override is unrestricted.
			return true, nil
		}
		return false, fmt.Errorf("read system config %s: %w", systemPath, err)
	}

	// The bypass flag relaxes a security control (it re-enables the --config
	// override), so it can only be trusted from a file that an unprivileged
	// user could not have tampered with. If the system config is group- or
	// world-writable, refuse the bypass: an attacker who can write the file
	// could otherwise flip the flag and point dotvault at their own config.
	// (The daemon's own Load only warns about such permissions; we are stricter
	// here because the decision being made is "may this config be overridden",
	// not "load this config".) Both this case and an indeterminate permission
	// check are surfaced as errors rather than a plain (false, nil): a refusal
	// for a permission reason is not the same as "the config didn't opt in", so
	// returning an error keeps the failure closed AND lets the CLI explain the
	// real cause instead of misleadingly telling the user to set a flag that
	// may already be set.
	if insecure, checkErr := perms.IsGroupWorldWritable(systemPath); checkErr != nil {
		return false, fmt.Errorf("cannot verify permissions of system config %s (refusing --config override): %w", systemPath, checkErr)
	} else if insecure {
		return false, fmt.Errorf("system config %s is group/world or otherwise non-owner writable; refusing --config override because bypass_system_config cannot be trusted from a tamperable file (restrict write access to the owner — e.g. mode 0600/0644 on Unix, or an owner-only ACL on Windows)", systemPath)
	}

	// Parse only enough to read the bypass flag. Deliberately skip
	// validate(): an unrelated validation problem in the system config must
	// not mask the override decision, and a syntactically broken file is
	// surfaced as a parse error rather than silently allowing the bypass.
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return false, fmt.Errorf("parse system config %s: %w", systemPath, err)
	}
	return c.BypassSystemConfig, nil
}

// Load reads and validates a config file at the given path.
func Load(path string) (*Config, error) {
	cfg, err := LoadRaw(path)
	if err != nil {
		return nil, err
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// LoadRaw reads and parses a config file without validating it (the
// group/world-writable permission warning is still emitted). See
// LoadSystemRaw for why the parse/validate seam exists.
func LoadRaw(path string) (*Config, error) {
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

	return &cfg, nil
}

// Validate validates the configuration and applies defaults in place. It is
// the exported counterpart of the validation Load/LoadSystem run internally,
// for callers that assemble a Config from raw parts — the remote-config
// overlay parses the base via LoadRaw/LoadSystemRaw, merges the fetched
// Partial, then validates the merged result here.
func (c *Config) Validate() error {
	return c.validate()
}

// IsMTLSMethod reports whether an auth_method drives the certificate-auth flow:
// "mtls" (key on disk), "mtls+tpm" (key TPM-sealed), or "mtls+os" (key + cert in
// the OS-native certificate store). Every site that gates on the cert-auth path
// (validation, MTLSParams construction) consults this so a new variant is wired
// in one place rather than enumerated as string literals across the codebase.
func IsMTLSMethod(method string) bool {
	switch method {
	case "mtls", "mtls+tpm", "mtls+os":
		return true
	default:
		return false
	}
}

// validateMTLS validates and defaults the vault.mtls block. It is a no-op
// unless auth_method drives the cert-auth flow (see IsMTLSMethod).
func (c *Config) validateMTLS() error {
	method := c.Vault.AuthMethod
	if !IsMTLSMethod(method) {
		return nil
	}
	m := &c.Vault.MTLS

	if m.BootstrapMethod == "" {
		m.BootstrapMethod = "oidc"
	}
	switch m.BootstrapMethod {
	case "ldap", "oidc":
	default:
		return fmt.Errorf("vault.mtls.bootstrap_method %q: must be ldap or oidc", m.BootstrapMethod)
	}

	if m.CertMount == "" {
		m.CertMount = DefaultCertMount
	}
	if m.CertRole == "" {
		return fmt.Errorf("vault.mtls.cert_role is required for auth_method %q", method)
	}
	if m.PKIMount == "" {
		m.PKIMount = DefaultPKIMount
	}
	if m.KeyType == "" {
		m.KeyType = DefaultMTLSKeyType
	}
	switch m.KeyType {
	case "ec":
	case "rsa":
		if method == "mtls+tpm" {
			return fmt.Errorf("vault.mtls.key_type rsa is not supported with auth_method mtls+tpm (the TPM/Secure Enclave backend is EC-only)")
		}
	default:
		return fmt.Errorf("vault.mtls.key_type %q: must be ec or rsa", m.KeyType)
	}
	if m.CommonName == "" {
		m.CommonName = DefaultMTLSCommonName
	}

	// BYO is both-or-neither.
	if (m.BYO.Cert == "") != (m.BYO.Key == "") {
		return fmt.Errorf("vault.mtls.byo: cert and key must be set together")
	}
	// mtls+os cannot import an external private key: the OS-native store
	// (certtostore) installs certificates but offers no key-import path, so the
	// key must be generated in the store. Reject BYO up front rather than failing
	// at login time.
	if method == "mtls+os" && m.BYO.Cert != "" {
		return fmt.Errorf("vault.mtls.byo is not supported with auth_method mtls+os (the OS-native store cannot import an external key); use auth_method mtls for bring-your-own")
	}
	// PKI role is required whenever issuance might run (i.e. no BYO cert).
	if m.BYO.Cert == "" && m.PKIRole == "" {
		return fmt.Errorf("vault.mtls.pki_role is required unless a BYO certificate is supplied")
	}

	if m.ReissueBefore == "" {
		m.ReissueBeforeDur = DefaultReissueBefore
	} else {
		d, err := ParseDuration(m.ReissueBefore)
		if err != nil {
			return fmt.Errorf("vault.mtls.reissue_before %q: %w", m.ReissueBefore, err)
		}
		if d <= 0 {
			return fmt.Errorf("vault.mtls.reissue_before %q: must be positive", m.ReissueBefore)
		}
		m.ReissueBeforeDur = d
	}

	// mtls+os defaults the requested certificate TTL to 30d when unset (the
	// OS-store credential doubles as a browser-presented user identity, so a
	// longer-lived cert is the sensible default); plain mtls/mtls+tpm leave it
	// unset and defer to the PKI role. Either way the role's max_ttl caps it.
	if method == "mtls+os" && m.TTL == "" {
		m.TTL = DefaultMTLSOSTTL
	}
	if m.TTL != "" {
		if _, err := ParseDuration(m.TTL); err != nil {
			return fmt.Errorf("vault.mtls.ttl %q: %w", m.TTL, err)
		}
	}
	return nil
}

func (c *Config) validate() error {
	// Vault address required
	if c.Vault.Address == "" {
		return fmt.Errorf("vault.address is required")
	}

	// Default KV mount
	if c.Vault.KVMount == "" {
		c.Vault.KVMount = DefaultKVMount
	}

	// Default user prefix; ensure exactly one trailing slash so all
	// consumers (sync engine, enrolment manager) build consistent paths.
	if c.Vault.UserPrefix == "" {
		c.Vault.UserPrefix = DefaultUserPrefix
	} else {
		c.Vault.UserPrefix = strings.TrimRight(c.Vault.UserPrefix, "/") + "/"
	}

	// mTLS / cert-auth validation and defaulting, gated on the auth method.
	if err := c.validateMTLS(); err != nil {
		return err
	}

	if c.Vault.OIDCCallbackPort < 0 || c.Vault.OIDCCallbackPort > 65535 {
		return fmt.Errorf("vault.oidc_callback_port %d: must be between 0 and 65535", c.Vault.OIDCCallbackPort)
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

	// Observability validation. The block is optional — only validate
	// shape when the user opted in. The OTel SDK applies its own
	// defaults (60s export interval, standard env-var fallbacks) so
	// most fields stay omittable.
	if c.Observability.Enabled {
		if err := validateOTLPProtocol("observability.protocol", c.Observability.Protocol); err != nil {
			return err
		}
		if err := validateOTLPProtocol("observability.metrics.protocol", c.Observability.Metrics.Protocol); err != nil {
			return err
		}
		if err := validateOTLPProtocol("observability.logs.protocol", c.Observability.Logs.Protocol); err != nil {
			return err
		}
		if err := validateOTLPTemporality("observability.metrics.temporality", c.Observability.Metrics.Temporality); err != nil {
			return err
		}
		// Temporality is a metric concept with no log analogue. Rejecting
		// it on the log signal (rather than silently ignoring it) tells
		// the operator their setting is on the wrong block instead of
		// letting them believe it took effect.
		if c.Observability.Logs.Temporality != "" {
			return fmt.Errorf("observability.logs.temporality %q: temporality applies to the metrics signal only", c.Observability.Logs.Temporality)
		}
		// Both signals explicitly off under an enabled master switch is a
		// contradiction, not a configuration: the operator's intent is
		// unclear (did they mean to disable observability, or did a partial
		// edit leave this behind?), and silently initialising nothing would
		// hide whichever mistake it was.
		if !c.Observability.MetricsSignal().Enabled && !c.Observability.LogsSignal().Enabled {
			return fmt.Errorf("observability.enabled is true but both metrics.enabled and logs.enabled are false; set observability.enabled false instead")
		}
		if c.Observability.RawInterval != "" {
			// Use the project's ParseDuration so observability.export_interval
			// accepts the same "Nd" day shorthand as other duration fields
			// (token_ttl, etc.) — a stdlib time.ParseDuration here would
			// reject `1d` and produce a confusing "unknown unit d" message.
			d, err := ParseDuration(c.Observability.RawInterval)
			if err != nil {
				return fmt.Errorf("observability.export_interval %q: %w", c.Observability.RawInterval, err)
			}
			if d <= 0 {
				return fmt.Errorf("observability.export_interval %q: must be positive", c.Observability.RawInterval)
			}
			c.Observability.ExportInterval = d
		} else if c.Observability.ExportInterval < 0 {
			// ExportInterval can be set programmatically (a test
			// fixture, a future internal config builder) without
			// RawInterval being populated. A negative value would
			// otherwise be passed straight to the OTel SDK's
			// WithInterval (which doesn't validate). Zero is fine
			// — the SDK falls back to its default 60s.
			return fmt.Errorf("observability.export_interval %v: must be positive", c.Observability.ExportInterval)
		}
	}

	// Defence-in-depth: reject CR/LF/NUL in observability header
	// values and CR/LF/NUL/`:` in header names. Runs unconditionally
	// — outside the `Enabled` guard — so a config that's toggled on
	// later (e.g. via env-var-driven enablement or a future feature
	// flag) starts from a sanitised baseline. The OTel SDK itself
	// doesn't validate these characters; catching them here
	// surfaces the problem at startup. CR/LF block plain HTTP
	// header smuggling; NUL is rejected because HTTP/2 and gRPC
	// treat it as a field terminator in some implementations and
	// proxies vary in handling.
	for field, headers := range map[string]map[string]string{
		"observability.headers":         c.Observability.Headers,
		"observability.metrics.headers": c.Observability.Metrics.Headers,
		"observability.logs.headers":    c.Observability.Logs.Headers,
	} {
		for k, v := range headers {
			if strings.ContainsAny(k, "\r\n:\x00") {
				return fmt.Errorf("%s: key %q must not contain CR, LF, NUL, or colon", field, k)
			}
			if strings.ContainsAny(v, "\r\n\x00") {
				return fmt.Errorf("%s[%q]: value must not contain CR, LF, or NUL", field, k)
			}
		}
	}

	// Agent validation. The block is optional — only validate shape when the
	// user opted in. Transport paths are left empty-able: the agent applies
	// per-user defaults at construction (Unix runtime socket / DefaultAgentPipe).
	if c.Agent.Enabled {
		if len(c.Agent.Keys) == 0 {
			return fmt.Errorf("agent.keys: at least one key source is required when the agent is enabled")
		}
		for i, k := range c.Agent.Keys {
			switch k.Source {
			case "kv":
				// path_prefix is optional (empty = whole user prefix).
			case "vault-ca":
				if k.Mount == "" {
					return fmt.Errorf("agent.keys[%d]: mount is required for a vault-ca source", i)
				}
				if k.Role == "" {
					return fmt.Errorf("agent.keys[%d]: role is required for a vault-ca source", i)
				}
				if k.TTL != "" {
					d, err := ParseDuration(k.TTL)
					if err != nil {
						return fmt.Errorf("agent.keys[%d].ttl %q: %w", i, k.TTL, err)
					}
					if d <= 0 {
						return fmt.Errorf("agent.keys[%d].ttl %q: must be positive", i, k.TTL)
					}
				}
			case "":
				return fmt.Errorf("agent.keys[%d]: source is required (kv or vault-ca)", i)
			default:
				return fmt.Errorf("agent.keys[%d]: invalid source %q (must be kv or vault-ca)", i, k.Source)
			}
		}
	}

	// Local API socket. Validated unconditionally (like the header checks
	// above): a relative path is a mistake worth naming whether or not the
	// section is currently enabled.
	if err := c.validateAPI(); err != nil {
		return err
	}

	// Remote-config validation (URL shape, refresh interval, header
	// hygiene). Runs unconditionally — the header character checks apply
	// even when the overlay is disabled, mirroring the observability
	// headers treatment above.
	if err := c.RemoteConfig.validate(); err != nil {
		return err
	}

	// Rules validation. A config carrying a remote overlay may legitimately
	// have zero local rules — the remote document supplies them — so the
	// hard requirement only applies when no remote URL is configured. The
	// merged config (base ⊕ remote) passes through here too: zero rules
	// after the merge is a warning rather than an error, letting the daemon
	// start, idle, and converge when the remote service serves rules.
	if len(c.Rules) == 0 {
		if c.RemoteConfig.URL == "" {
			return fmt.Errorf("at least one rule is required")
		}
		slog.Warn("no sync rules configured; expecting rules from the remote config service", "url", c.RemoteConfig.URL)
	}

	seen := make(map[string]bool)
	for i, r := range c.Rules {
		if err := validateRule(i, r, seen); err != nil {
			return err
		}
	}

	// Enrolments validation
	for key, e := range c.Enrolments {
		if err := validateEnrolment(key, e); err != nil {
			return err
		}
	}

	return nil
}

// validateRule checks a single rule's required fields and name uniqueness
// (seen accumulates names across the containing slice). Shared by the full
// config validation and (*Partial).Validate so the two paths cannot drift.
func validateRule(i int, r Rule, seen map[string]bool) error {
	if r.Name == "" {
		return fmt.Errorf("rules[%d].name is required", i)
	}
	if seen[r.Name] {
		return fmt.Errorf("duplicate rule name %q", r.Name)
	}
	seen[r.Name] = true

	// vault_key is optional: a rule may manage a file with no Vault-backed
	// content (e.g. an ssh_config built purely from {{ username }} and
	// literals). Such a keyless rule renders with an empty data context, so it
	// must carry a template — there is no secret data to fall back on.
	if r.VaultKey == "" && r.Target.Template == "" {
		return fmt.Errorf("rules[%d] (%s): a rule without vault_key must supply target.template (no secret data to write otherwise)", i, r.Name)
	}
	if r.Target.Path == "" {
		return fmt.Errorf("rules[%d] (%s): target.path is required", i, r.Name)
	}
	if !validFormats[r.Target.Format] {
		return fmt.Errorf("rules[%d] (%s): invalid format %q (must be yaml, json, ini, toml, text, netrc, or ssh_config)", i, r.Name, r.Target.Format)
	}
	return nil
}

// validateEnrolment checks one enrolment entry: key shape, engine presence,
// and engine-agnostic settings. Shared by the full config validation and
// (*Partial).Validate so the two paths cannot drift.
func validateEnrolment(key string, e Enrolment) error {
	if strings.TrimSpace(key) == "" {
		return fmt.Errorf("enrolment key must not be empty or whitespace")
	}
	if err := validateEnrolmentKey(key); err != nil {
		return fmt.Errorf("enrolments[%q]: %w", key, err)
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
	return nil
}

// validateEnrolmentKey enforces the shape of an enrolment key. A key is either
// a flat name ("gh") or a single-level group path ("databricks/prod") — the
// group segment becomes a "folder" in the web UI and a nested Vault path
// segment (users/<user>/databricks/prod). Exactly one level of grouping is
// supported: more than one '/', a leading/trailing '/', or an empty segment is
// rejected so the Vault path, the web routes, and the registry round-trip all
// stay well-defined. A backslash is rejected outright because it is the Windows
// registry path separator and would corrupt the GPO enrolment subtree.
func validateEnrolmentKey(key string) error {
	if strings.Contains(key, `\`) {
		return fmt.Errorf("key must not contain a backslash")
	}
	var segments []string
	switch strings.Count(key, "/") {
	case 0:
		segments = []string{key}
	case 1:
		group, name, _ := strings.Cut(key, "/")
		segments = []string{group, name}
	default:
		return fmt.Errorf("key supports at most one '/' grouping level (got %q)", key)
	}
	for _, seg := range segments {
		if strings.TrimSpace(seg) == "" {
			return fmt.Errorf("key must not contain an empty segment (got %q)", key)
		}
		// "." / ".." would produce a confusing Vault path and folder label;
		// reject them so a grouped key always maps to a concrete location.
		if seg == "." || seg == ".." {
			return fmt.Errorf("key segment must not be %q (got %q)", seg, key)
		}
	}
	return nil
}
