// Package observability wires OpenTelemetry metric instruments and the
// OTLP exporter for the dotvault daemon.
//
// The package is designed to be safe to use unconditionally: when no
// provider has been initialised (Init was not called, or the
// observability config block is absent/disabled) the instruments back
// off to the global no-op meter, so every call site can record without
// nil-checking. Initialise once at daemon start, defer Shutdown.
//
// Architecture: lower-level packages (auth, sync, vault, enrol, web)
// import this one and call package-level Record* helpers directly,
// rather than receiving a callback from the daemon entrypoint. This
// matches dotvault's convention for cross-cutting concerns (slog is
// imported at every layer in the same way); both rely on a
// well-behaved no-op default for tests that don't initialise the
// global, and both keep the call sites free of plumbing. Init
// mutates two process-wide globals (otel.SetMeterProvider +
// global.SetLoggerProvider) and rebinds the metric instruments
// (rebindInstruments under instrMu) — it's expected to run exactly
// once per process at startup. Log helpers resolve the logger
// per-call from global.GetLoggerProvider() so no cached handle
// needs rebinding. The test suite in this package does not run
// subtests with t.Parallel(), so the sequential invocations of Init
// in tests do not race; do not add t.Parallel() to any test that
// installs a MeterProvider or LoggerProvider (newTestReader /
// newTestLogProcessor) without also serialising through a sync.Once
// or test-scoped lock.
//
// Attribute conventions:
//   - Outcomes use a small fixed vocabulary ({ok, error, renewed,
//     reauth_required, failed, completed, denied, …}) so the
//     exported series stay bounded. See the per-instrument
//     RecordXxx godoc for the exact set each instrument emits.
//   - We never attach usernames, Vault paths, secret keys, repo URLs,
//     or JFrog server hostnames to instruments — the same scrubbing
//     discipline the slog handlers follow.
package observability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
)

// Config controls observability wiring. Mirrors config.ObservabilityConfig
// but is local to this package so the SDK can be initialised without
// importing the top-level config (avoiding a circular dependency).
type Config struct {
	// Enabled is the master switch. When false, Init returns a no-op
	// Provider and the global instruments remain backed by the OTel
	// no-op meter.
	Enabled bool

	// Metrics and Logs carry each signal's RESOLVED exporter settings —
	// the caller (cmd/dotvault) layers any per-signal config overrides
	// onto the shared fields via config.ObservabilityConfig.ResolveSignal
	// before constructing this. Keeping this package on the resolved shape
	// means the layering semantics live in exactly one place (the config
	// package) and Init never re-derives them.
	Metrics Signal
	Logs    Signal

	// ExportInterval is the periodic metric exporter cadence. Zero means
	// the SDK default (currently 60s). Metrics-only: the log signal uses
	// the SDK's batch processor with its own defaults.
	ExportInterval time.Duration

	// ServiceVersion is the resource attribute used for service.version.
	// Pass main.version so the exported series can be partitioned by
	// release.
	ServiceVersion string
}

// Signal is one signal's exporter settings. The two signals may point at
// entirely separate backends.
type Signal struct {
	// Enabled switches this signal's exporter on. With both signals
	// disabled (or the master switch off) Init returns an inactive
	// Provider.
	Enabled bool

	// Endpoint is the OTLP collector address for this signal. For gRPC:
	// "host:port" (e.g. "localhost:4317"). For HTTP: a *base* URL with no
	// signal-specific path (e.g. "https://otel.example") — the exporters
	// append "/v1/metrics" and "/v1/logs" themselves. Passing a URL that
	// already ends in a signal-specific path routes the signal to the
	// wrong route on the collector. When empty the SDK falls through to
	// OTEL_EXPORTER_OTLP_ENDPOINT (and the signal-specific
	// OTEL_EXPORTER_OTLP_METRICS_ENDPOINT / _LOGS_ENDPOINT variants).
	Endpoint string

	// Protocol selects the exporter implementation: "grpc" (default) or
	// "http/protobuf".
	Protocol string

	// Insecure disables transport security for the gRPC exporter
	// (HTTP/protobuf carries this via the endpoint scheme).
	Insecure bool

	// Headers are attached to every export request for this signal —
	// useful for authenticating to a collector that fronts a vendor
	// backend.
	Headers map[string]string
}

// Provider is a thin wrapper over the SDK MeterProvider and
// LoggerProvider, holding the state needed to flush and shut them down
// cleanly. The zero value represents an inactive provider whose
// Shutdown is a no-op — that's what callers get when observability is
// disabled, so the daemon shutdown path doesn't have to branch on
// whether Init succeeded.
type Provider struct {
	mp       *sdkmetric.MeterProvider
	lp       *sdklog.LoggerProvider
	shutdown func(context.Context) error
}

// Shutdown flushes any pending metric and log exports and tears down
// the provider. Always returns nil for an inactive provider so callers
// can defer it unconditionally.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || p.shutdown == nil {
		return nil
	}
	return p.shutdown(ctx)
}

// ForceFlush blocks until the periodic reader and log processor have
// exported any in-flight records, up to the deadline on ctx. Available
// for callers that want to flush mid-flight without tearing the
// provider down; Shutdown already invokes ForceFlush internally, so
// the one-shot `dotvault sync` and `dotvault run --once` paths rely
// on their deferred Shutdown rather than calling this directly. No-op
// for an inactive provider. Returns errors.Join so a collector outage
// affecting both signals surfaces both failures instead of masking the
// second one.
func (p *Provider) ForceFlush(ctx context.Context) error {
	if p == nil {
		return nil
	}
	var mErr, lErr error
	if p.mp != nil {
		mErr = p.mp.ForceFlush(ctx)
	}
	if p.lp != nil {
		lErr = p.lp.ForceFlush(ctx)
	}
	return errors.Join(mErr, lErr)
}

// Init initialises the OTLP metric and log exporters and installs the
// global MeterProvider and LoggerProvider. Subsequent calls to
// package-level instruments (Sync, Vault, Token, …) record into the
// MeterProvider, and Log* helpers emit through the LoggerProvider.
// When cfg.Enabled is false, Init returns an inactive Provider whose
// Shutdown is a no-op and leaves the global meter and logger
// unchanged (so instruments back off to the OTel no-op meter and log
// emissions go to the no-op global logger).
func Init(ctx context.Context, cfg Config) (*Provider, error) {
	if !cfg.Enabled || (!cfg.Metrics.Enabled && !cfg.Logs.Enabled) {
		return &Provider{}, nil
	}

	// Record the build version for the dotvault.build_info gauge before
	// rebindInstruments runs, so the callback registered against the real
	// provider observes the injected release rather than the "dev" default.
	setBuildVersion(cfg.ServiceVersion)

	// Each signal's exporter is built only when that signal is enabled; a
	// disabled signal's global provider is left untouched, so its consumers
	// — the metric instruments, or the Log* helpers resolving the global
	// LoggerProvider — stay backed by the OTel no-op implementation exactly
	// as if observability were off for it.
	var metricExporter sdkmetric.Exporter
	var logExporter sdklog.Exporter
	var err error

	if cfg.Metrics.Enabled {
		metricExporter, err = buildMetricExporter(ctx, cfg.Metrics)
		if err != nil {
			return nil, fmt.Errorf("build OTLP metric exporter: %w", err)
		}
	}

	if cfg.Logs.Enabled {
		logExporter, err = buildLogExporter(ctx, cfg.Logs)
		if err != nil {
			// metricExporter (when built) already holds a gRPC/HTTP
			// connection; shut it down before the error escapes so a
			// transient log-exporter init failure doesn't leak the metric
			// side. Bounded by the caller's ctx — initObservability passes
			// a 10s budget.
			if metricExporter != nil {
				_ = metricExporter.Shutdown(ctx)
			}
			return nil, fmt.Errorf("build OTLP log exporter: %w", err)
		}
	}

	hostname, _ := os.Hostname()

	// The supplementary resource is deliberately created with an empty
	// schema URL rather than semconv.SchemaURL. resource.Merge errors with
	// "conflicting Schema URL" when both operands carry a non-empty but
	// differing schema, and resource.Default() tracks whichever semconv
	// version the installed otel/sdk embeds — which advances independently
	// of the semconv package this file imports. Hard-coding our schema here
	// reintroduces that conflict on every SDK bump that moves the default
	// schema (e.g. sdk v1.44.0 moved it to 1.41.0 while we import v1.40.0).
	// Leaving it empty lets Merge adopt Default()'s schema, so the
	// attribute keys stay canonical without coupling us to the SDK's
	// semconv revision.
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			"",
			semconv.ServiceName("dotvault"),
			semconv.ServiceVersion(stringOr(cfg.ServiceVersion, "dev")),
			semconv.HostName(hostname),
			semconv.OSTypeKey.String(runtime.GOOS),
			// Raw GOARCH coincides with semconv's host.arch well-known
			// values for every target this project ships (amd64, arm64).
			// They diverge on 32-bit targets (GOARCH "386"/"arm" vs
			// semconv "x86"/"arm32") — host.arch is an open enum so raw
			// values remain legal, but add a mapping here before ever
			// shipping a 32-bit build.
			semconv.HostArchKey.String(runtime.GOARCH),
			semconv.ProcessRuntimeName("go"),
			semconv.ProcessRuntimeVersion(runtime.Version()),
		),
	)
	if err != nil {
		// The built exporters are open — clean them up so the process
		// isn't left with background dialers pointing at a collector for
		// a daemon that never actually started.
		if metricExporter != nil {
			_ = metricExporter.Shutdown(ctx)
		}
		if logExporter != nil {
			_ = logExporter.Shutdown(ctx)
		}
		return nil, fmt.Errorf("build resource: %w", err)
	}

	var mp *sdkmetric.MeterProvider
	if metricExporter != nil {
		readerOpts := []sdkmetric.PeriodicReaderOption{}
		if cfg.ExportInterval > 0 {
			readerOpts = append(readerOpts, sdkmetric.WithInterval(cfg.ExportInterval))
		}
		reader := sdkmetric.NewPeriodicReader(metricExporter, readerOpts...)

		mp = sdkmetric.NewMeterProvider(
			sdkmetric.WithResource(res),
			sdkmetric.WithReader(reader),
		)
		otel.SetMeterProvider(mp)

		// Rebind instruments so subsequent record-site calls hit the
		// active MeterProvider rather than the no-op global captured at
		// process start. The logger handle isn't cached — Log* helpers
		// resolve it from global.GetLoggerProvider() per call — so no
		// equivalent rebind is needed for the log signal. Safe to call
		// repeatedly: instruments are recreated each time, but creation
		// is cheap and Init runs once per process.
		rebindInstruments()
	}

	var lp *sdklog.LoggerProvider
	if logExporter != nil {
		lp = sdklog.NewLoggerProvider(
			sdklog.WithResource(res),
			sdklog.WithProcessor(sdklog.NewBatchProcessor(logExporter)),
		)
		global.SetLoggerProvider(lp)
	}

	mpFinal, lpFinal := mp, lp
	return &Provider{
		mp: mp,
		lp: lp,
		shutdown: func(ctx context.Context) error {
			// Best-effort flush before shutdown so the last batch makes
			// it out even when the caller passes a tight context. Each
			// side may be nil when its signal is disabled.
			var mErr, lErr error
			if mpFinal != nil {
				_ = mpFinal.ForceFlush(ctx)
				mErr = mpFinal.Shutdown(ctx)
			}
			if lpFinal != nil {
				_ = lpFinal.ForceFlush(ctx)
				lErr = lpFinal.Shutdown(ctx)
			}
			return errors.Join(mErr, lErr)
		},
	}, nil
}

func buildMetricExporter(ctx context.Context, sig Signal) (sdkmetric.Exporter, error) {
	warnInsecureHeaders("metrics", sig)

	protocol := resolveProtocol(sig.Protocol, "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL")

	switch protocol {
	case "grpc":
		opts := []otlpmetricgrpc.Option{}
		if sig.Endpoint != "" {
			opts = append(opts, otlpmetricgrpc.WithEndpoint(stripScheme(sig.Endpoint)))
		}
		if sig.Insecure {
			opts = append(opts, otlpmetricgrpc.WithInsecure())
		}
		if len(sig.Headers) > 0 {
			opts = append(opts, otlpmetricgrpc.WithHeaders(sig.Headers))
		}
		return otlpmetricgrpc.New(ctx, opts...)
	case "http/protobuf":
		opts := []otlpmetrichttp.Option{}
		if sig.Endpoint != "" {
			// otlpmetrichttp distinguishes endpoint vs URL: WithEndpoint
			// takes host[:port], WithEndpointURL takes a fully-qualified
			// URL. The user-facing config is a single field, so we infer
			// which to call from the literal presence of "://": url.Parse
			// will happily report `Scheme: "127.0.0.1"` for `127.0.0.1:4317`
			// (interpreting the colon as a scheme separator), so a
			// Scheme-only check would misroute host:port values to
			// WithEndpointURL and produce a confusing init failure. The
			// substring check is what the OTel SDK's own env-var loader
			// does internally for the same reason.
			if strings.Contains(sig.Endpoint, "://") {
				opts = append(opts, otlpmetrichttp.WithEndpointURL(sig.Endpoint))
			} else {
				opts = append(opts, otlpmetrichttp.WithEndpoint(sig.Endpoint))
			}
		}
		if sig.Insecure {
			opts = append(opts, otlpmetrichttp.WithInsecure())
		}
		if len(sig.Headers) > 0 {
			opts = append(opts, otlpmetrichttp.WithHeaders(sig.Headers))
		}
		return otlpmetrichttp.New(ctx, opts...)
	default:
		// Report the *resolved* protocol — when sig.Protocol was
		// empty and we picked the value up from OTEL_EXPORTER_OTLP_*
		// env vars, that's the value the operator actually has in
		// flight, not the empty config field.
		return nil, fmt.Errorf("unsupported observability protocol %q (use grpc or http/protobuf)", protocol)
	}
}

// warnInsecureHeaders is the per-signal footgun guard: insecure transport
// plus auth headers means a bearer token (e.g. a Datadog / Grafana Cloud
// OTLP key) goes over plaintext to that signal's collector. Loopback
// collectors that don't terminate TLS are a legitimate case, but the
// combination usually signals a misconfiguration. Evaluated per signal now
// that the two can point at different backends with different headers —
// one signal being safely configured must not mask the other's plaintext
// token.
func warnInsecureHeaders(signal string, sig Signal) {
	if insecureHeaderFootgun(sig) {
		slog.Warn("OTLP insecure transport enabled with auth headers — bearer tokens will be sent in plaintext; use a TLS-protected endpoint for production", "signal", signal)
	}
}

// insecureHeaderFootgun is the predicate behind warnInsecureHeaders, split
// out so the condition is testable without capturing log output.
func insecureHeaderFootgun(sig Signal) bool {
	return sig.Insecure && len(sig.Headers) > 0
}

// stripScheme normalises an OTLP gRPC endpoint by removing a
// URL-style scheme so the underlying gRPC dialer receives a bare
// host:port (which is what otlpmetricgrpc.WithEndpoint expects).
//
// dns:/// is deliberately preserved: it is a valid gRPC resolver
// prefix (not a URL scheme) that enables the DNS resolver for
// multi-address service discovery / load balancing. Stripping it
// would change the dial-target semantics and break those setups.
func stripScheme(s string) string {
	for _, prefix := range []string{"https://", "http://", "grpc://"} {
		if strings.HasPrefix(s, prefix) {
			return strings.TrimPrefix(s, prefix)
		}
	}
	return s
}

func stringOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// resolveProtocol honours the OpenTelemetry env-var convention when
// the configured protocol is empty: a signal-specific override (e.g.
// OTEL_EXPORTER_OTLP_METRICS_PROTOCOL / _LOGS_PROTOCOL) takes
// precedence over the generic OTEL_EXPORTER_OTLP_PROTOCOL; both fall
// back to gRPC when unset. Without this fallthrough, a
// centrally-managed environment that selects http/protobuf via env
// would be silently overridden to gRPC by the default below.
func resolveProtocol(configured, signalEnvVar string) string {
	protocol := strings.ToLower(strings.TrimSpace(configured))
	if protocol == "" {
		protocol = strings.ToLower(strings.TrimSpace(os.Getenv(signalEnvVar)))
	}
	if protocol == "" {
		protocol = strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")))
	}
	if protocol == "" {
		protocol = "grpc"
	}
	return protocol
}

// buildLogExporter mirrors buildMetricExporter for OTLP log records,
// consuming the log signal's resolved settings (which may name an entirely
// different backend than the metric signal's) and reading the
// signal-specific OTEL_EXPORTER_OTLP_LOGS_PROTOCOL override before the
// generic OTEL_EXPORTER_OTLP_PROTOCOL.
func buildLogExporter(ctx context.Context, sig Signal) (sdklog.Exporter, error) {
	warnInsecureHeaders("logs", sig)

	protocol := resolveProtocol(sig.Protocol, "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL")

	switch protocol {
	case "grpc":
		opts := []otlploggrpc.Option{}
		if sig.Endpoint != "" {
			opts = append(opts, otlploggrpc.WithEndpoint(stripScheme(sig.Endpoint)))
		}
		if sig.Insecure {
			opts = append(opts, otlploggrpc.WithInsecure())
		}
		if len(sig.Headers) > 0 {
			opts = append(opts, otlploggrpc.WithHeaders(sig.Headers))
		}
		return otlploggrpc.New(ctx, opts...)
	case "http/protobuf":
		opts := []otlploghttp.Option{}
		if sig.Endpoint != "" {
			if strings.Contains(sig.Endpoint, "://") {
				opts = append(opts, otlploghttp.WithEndpointURL(sig.Endpoint))
			} else {
				opts = append(opts, otlploghttp.WithEndpoint(sig.Endpoint))
			}
		}
		if sig.Insecure {
			opts = append(opts, otlploghttp.WithInsecure())
		}
		if len(sig.Headers) > 0 {
			opts = append(opts, otlploghttp.WithHeaders(sig.Headers))
		}
		return otlploghttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("unsupported observability protocol %q (use grpc or http/protobuf)", protocol)
	}
}

// Instrument handles. These are rebound from Init so their recorders
// land on whatever MeterProvider the daemon currently has installed.
// All are package-level for ergonomic record-site access — every
// instrumented call site is a single function call with no plumbing.
var (
	instrMu sync.RWMutex

	syncTicks       metric.Int64Counter
	syncDuration    metric.Float64Histogram
	vaultCalls      metric.Int64Counter
	tokenRenewals   metric.Int64Counter
	tokenTTLSeconds metric.Float64Histogram
	enrolAttempts   metric.Int64Counter
	webRequests     metric.Int64Counter
	configReloads   metric.Int64Counter
	remoteFetches   metric.Int64Counter
	sighupAttempts  metric.Int64Counter
	deprecatedUses  metric.Int64Counter

	// buildVersion feeds the dotvault.build_info gauge's version attribute.
	// Set by Init before it rebinds the instruments; empty (a test calling
	// rebindInstruments directly, or a hand-rolled build) reports as "dev",
	// matching the resource's service.version fallback.
	buildVersion string
	// buildInfoReg is the previous rebind's callback registration.
	// Unregistered before re-registering so a repeated rebind (Init after
	// package init, tests swapping providers) doesn't accumulate duplicate
	// observations of the gauge on the same meter.
	buildInfoReg metric.Registration
)

func init() {
	rebindInstruments()
}

// rebindInstruments rebuilds every package-level instrument from the
// currently-installed global MeterProvider. Called from package init
// (no-op meter) and again from Init after the SDK provider is
// installed. Errors building an instrument are silently swallowed
// because metric creation failure is not a daemon-fatal condition —
// the record sites will simply hit a nil receiver and skip the record,
// which is the same behaviour as a disabled provider.
func rebindInstruments() {
	instrMu.Lock()
	defer instrMu.Unlock()

	meter := otel.GetMeterProvider().Meter("github.com/goodtune/dotvault")

	syncTicks, _ = meter.Int64Counter(
		"dotvault.sync.ticks",
		metric.WithDescription("Total sync cycles executed"),
	)
	syncDuration, _ = meter.Float64Histogram(
		"dotvault.sync.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Wall-clock duration of a sync cycle"),
	)
	vaultCalls, _ = meter.Int64Counter(
		"dotvault.vault.calls",
		metric.WithDescription("Vault API call count by operation and status"),
	)
	tokenRenewals, _ = meter.Int64Counter(
		"dotvault.token.renewals",
		metric.WithDescription("Vault token renewal outcomes"),
	)
	tokenTTLSeconds, _ = meter.Float64Histogram(
		"dotvault.token.ttl_remaining",
		metric.WithUnit("s"),
		metric.WithDescription("Vault token TTL remaining at each lifecycle check"),
	)
	enrolAttempts, _ = meter.Int64Counter(
		"dotvault.enrol.attempts",
		metric.WithDescription("Enrolment attempts by engine and outcome"),
	)
	webRequests, _ = meter.Int64Counter(
		"dotvault.web.requests",
		metric.WithDescription("Web UI HTTP request count by route and status class"),
	)
	configReloads, _ = meter.Int64Counter(
		"dotvault.config.reloads",
		metric.WithDescription("Configuration reload attempts and outcomes"),
	)
	remoteFetches, _ = meter.Int64Counter(
		"dotvault.remoteconfig.fetches",
		metric.WithDescription("Remote configuration fetch attempts by outcome"),
	)
	sighupAttempts, _ = meter.Int64Counter(
		"dotvault.sighup.received",
		// Permanently zero on Windows (SIGHUP isn't delivered to
		// processes there; the tray's "Reload config" entry drives the
		// same reload and is not metered here); on Linux and macOS each
		// SIGHUP forces the LifecycleManager to re-read ~/.dotvault-token
		// and runs an immediate config-refresh pass. This counts only the
		// manual SIGHUP path: on Linux the steady-state token-re-read
		// trigger is the in-process inotify watcher (internal/tokenwatch),
		// whose re-reads are deliberately not metered here, so this
		// counter undercounts total token re-reads on Linux. The
		// reload's outcome lands on dotvault.config.reloads; static
		// config sections still require a daemon restart.
		metric.WithDescription("SIGHUP signals received (Linux/macOS only; SIGHUP is not delivered on Windows). Triggers an immediate dotvault-token file re-read and config reload; static config sections still require a daemon restart."),
	)
	deprecatedUses, _ = meter.Int64Counter(
		"dotvault.config.deprecated",
		// The fleet-visibility side of a staged config deprecation:
		// each process start that finds a deprecated field in active use
		// adds one per field, so a collector-side sum grouped by `field`
		// shows how much of the fleet still needs migrating before the
		// removal release can ship. Bounded cardinality — the attribute
		// values are a fixed set of config paths, never user content.
		metric.WithDescription("Deprecated configuration fields in active use, counted once per process start, by field"),
	)

	// dotvault.build_info follows the Prometheus *_build_info convention: a
	// constant-1 gauge whose attributes carry the build identity, there to
	// be joined against — e.g. dotvault.config.deprecated by version tells
	// a fleet operator whether deprecated-config stragglers are just old
	// builds. The same identity also rides every series as OTel resource
	// attributes (service.version, os.type, host.arch, …), but not every
	// backend surfaces resource/target_info well, and the join idiom
	// expects a metric. Attributes mirror `dotvault version --json`;
	// all values are process constants, so cardinality is one series per
	// build. The previous registration (if any) is dropped first so
	// repeated rebinds don't observe the gauge twice on one meter.
	if buildInfoReg != nil {
		_ = buildInfoReg.Unregister()
		buildInfoReg = nil
	}
	buildInfo, err := meter.Int64ObservableGauge(
		"dotvault.build_info",
		metric.WithDescription("Build identity as a constant-1 gauge: version, go_version, os, arch"),
	)
	if err == nil {
		observation := metric.WithAttributes(
			attribute.String("version", stringOr(buildVersion, "dev")),
			attribute.String("go_version", runtime.Version()),
			attribute.String("os", runtime.GOOS),
			attribute.String("arch", runtime.GOARCH),
		)
		buildInfoReg, _ = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
			o.ObserveInt64(buildInfo, 1, observation)
			return nil
		}, buildInfo)
	}
}

// setBuildVersion stores the release version the dotvault.build_info gauge
// reports. Called by Init ahead of its rebindInstruments so the callback
// registered on the real provider carries the injected main.version.
func setBuildVersion(v string) {
	instrMu.Lock()
	buildVersion = v
	instrMu.Unlock()
}

// RecordSyncTick increments the sync-tick counter with the outcome
// attribute. The sync engine emits "ok" (every rule succeeded) or
// "error" (at least one rule failed); per-rule skip cases roll up
// into "ok" at the cycle level so there's no separate "skipped"
// outcome to forecast.
func RecordSyncTick(ctx context.Context, outcome string) {
	instrMu.RLock()
	c := syncTicks
	instrMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
}

// RecordSyncDuration records a sync-cycle duration in seconds.
func RecordSyncDuration(ctx context.Context, d time.Duration, outcome string) {
	instrMu.RLock()
	h := syncDuration
	instrMu.RUnlock()
	if h == nil {
		return
	}
	h.Record(ctx, d.Seconds(), metric.WithAttributes(attribute.String("outcome", outcome)))
}

// RecordVaultCall records a single Vault API call with bounded op/status
// attributes. Pass concrete strings only (no formatted error messages)
// or the time-series cardinality will explode.
func RecordVaultCall(ctx context.Context, op, status string) {
	instrMu.RLock()
	c := vaultCalls
	instrMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(
		attribute.String("op", op),
		attribute.String("status", status),
	))
}

// RecordTokenRenewal records the outcome of a token renewal attempt.
// Outcomes emitted today: "renewed", "reauth_required", "failed".
func RecordTokenRenewal(ctx context.Context, outcome string) {
	instrMu.RLock()
	c := tokenRenewals
	instrMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
}

// RecordTokenTTL records the observed token TTL in seconds. Recorded on
// every lifecycle check so the histogram captures the renewal-driven
// sawtooth pattern.
func RecordTokenTTL(ctx context.Context, ttl time.Duration) {
	instrMu.RLock()
	h := tokenTTLSeconds
	instrMu.RUnlock()
	if h == nil {
		return
	}
	h.Record(ctx, ttl.Seconds())
}

// RecordEnrolAttempt records an enrolment attempt by engine and outcome.
// Engine values pass through classifyEngine in internal/enrol, so the
// label is one of {"copy","databricks","github","jfrog","ssh","unknown"}. Outcomes
// emitted today: "completed", "error".
func RecordEnrolAttempt(ctx context.Context, engine, outcome string) {
	instrMu.RLock()
	c := enrolAttempts
	instrMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(
		attribute.String("engine", engine),
		attribute.String("outcome", outcome),
	))
}

// RecordWebRequest records a web-UI HTTP request. Route is the static
// route template (e.g. "/api/v1/status"), not the request path —
// dynamic segments would unbound the cardinality. Status class is the
// 1xx/2xx/3xx/4xx/5xx bucket; full status codes would similarly
// inflate cardinality.
func RecordWebRequest(ctx context.Context, route string, statusClass string) {
	instrMu.RLock()
	c := webRequests
	instrMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(
		attribute.String("route", route),
		attribute.String("status_class", statusClass),
	))
}

// RecordConfigReload records a config reload attempt. Outcomes:
// "no_change", "applied", "error".
func RecordConfigReload(ctx context.Context, outcome string) {
	instrMu.RLock()
	c := configReloads
	instrMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
}

// RecordRemoteConfigFetch records a remote-config fetch attempt and where
// the document resolved from. Outcomes: "fresh" (200), "not_modified" (304
// validating the cache), "cache_fallback" (fetch failed, last-known-good
// used), "base_only" (fetch failed, no usable cache).
func RecordRemoteConfigFetch(ctx context.Context, outcome string) {
	instrMu.RLock()
	c := remoteFetches
	instrMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
}

// RecordSIGHUP records a SIGHUP receipt. Each SIGHUP triggers an
// immediate ~/.dotvault-token re-read via LifecycleManager.Reload plus
// an immediate config-refresh pass; the counter surfaces how often that
// path fires.
func RecordSIGHUP(ctx context.Context) {
	instrMu.RLock()
	c := sighupAttempts
	instrMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1)
}

// RecordDeprecatedConfig records one deprecated configuration field found
// in active use, by its dotted YAML path (e.g. "observability.endpoint").
// Called once per field per process start, so a collector-side sum grouped
// by `field` measures fleet-wide migration progress ahead of the field's
// removal release. Pass only fixed config paths — never user-supplied
// values — to keep the attribute cardinality bounded.
func RecordDeprecatedConfig(ctx context.Context, field string) {
	instrMu.RLock()
	c := deprecatedUses
	instrMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(attribute.String("field", field)))
}

// LogRegistryConfigManaged emits a WARN-severity OTel log record
// signalling that the daemon's configuration came from the Windows
// Registry (Group Policy) and the file at path is being ignored.
// Routed through the OTel logger rather than slog because the message
// surfaces a deployment fact an operator cares about (GPO mode is
// active) but is *not* something an end-user running the CLI should
// see on stdout/stderr — slog there leaks an INFO line out of every
// CLI invocation on a GPO-managed Windows box. When observability is
// disabled the global LoggerProvider is a no-op and the record is
// silently dropped, which is exactly the desired behaviour.
//
// Resolves the logger from the current global LoggerProvider on every
// call rather than caching a handle behind a mutex. The previous
// cached-handle design carried an exported RebindGlobalLogger purely
// for tests; this is called once per daemon/sync startup so a single
// global lookup per emit is fine and removes that test-only API from
// the production surface.
func LogRegistryConfigManaged(ctx context.Context, path string) {
	l := global.GetLoggerProvider().Logger(loggerName)
	var rec log.Record
	rec.SetTimestamp(time.Now())
	rec.SetSeverity(log.SeverityWarn)
	rec.SetSeverityText("WARN")
	rec.SetBody(log.StringValue("configuration loaded from Windows Registry (Group Policy); file-based config is ignored"))
	rec.AddAttributes(log.String("path", path))
	l.Emit(ctx, rec)
}
