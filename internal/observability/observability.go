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
// global.SetLoggerProvider) and their associated rebinds
// (rebindInstruments under instrMu, rebindLogger under loggerMu) —
// it's expected to run exactly once per process at startup. The test
// suite in this package does not run subtests with t.Parallel(), so
// the sequential invocations of Init in tests do not race; do not
// add t.Parallel() to any test that installs a MeterProvider or
// LoggerProvider (newTestReader / newTestLogProcessor) without also
// serialising through a sync.Once or test-scoped lock.
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

	// Endpoint is the OTLP collector address (e.g. "localhost:4317" for
	// gRPC, "https://otel.example/v1/metrics" for HTTP). When empty the
	// SDK falls through to OTEL_EXPORTER_OTLP_ENDPOINT.
	Endpoint string

	// Protocol selects the exporter implementation: "grpc" (default) or
	// "http/protobuf".
	Protocol string

	// Insecure disables transport security for the gRPC exporter
	// (HTTP/protobuf carries this via the endpoint scheme).
	Insecure bool

	// Headers are attached to every export request — useful for
	// authenticating to a collector that fronts a vendor backend.
	Headers map[string]string

	// ExportInterval is the periodic exporter cadence. Zero means the
	// SDK default (currently 60s).
	ExportInterval time.Duration

	// ServiceVersion is the resource attribute used for service.version.
	// Pass main.version so the exported series can be partitioned by
	// release.
	ServiceVersion string
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
	if !cfg.Enabled {
		return &Provider{}, nil
	}

	metricExporter, err := buildExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("build OTLP metric exporter: %w", err)
	}

	logExporter, err := buildLogExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("build OTLP log exporter: %w", err)
	}

	hostname, _ := os.Hostname()

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("dotvault"),
			semconv.ServiceVersion(stringOr(cfg.ServiceVersion, "dev")),
			semconv.HostName(hostname),
			semconv.OSTypeKey.String(runtime.GOOS),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("build resource: %w", err)
	}

	readerOpts := []sdkmetric.PeriodicReaderOption{}
	if cfg.ExportInterval > 0 {
		readerOpts = append(readerOpts, sdkmetric.WithInterval(cfg.ExportInterval))
	}
	reader := sdkmetric.NewPeriodicReader(metricExporter, readerOpts...)

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
	)
	otel.SetMeterProvider(mp)

	lp := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExporter)),
	)
	global.SetLoggerProvider(lp)

	// Rebind instruments and the package-level logger so subsequent
	// record-site calls hit the active providers rather than the no-op
	// globals captured at process start. Safe to call repeatedly —
	// instruments are recreated each time, but creation is cheap and
	// Init runs once per process.
	rebindInstruments()
	rebindLogger()

	return &Provider{
		mp: mp,
		lp: lp,
		shutdown: func(ctx context.Context) error {
			// Best-effort flush before shutdown so the last batch makes
			// it out even when the caller passes a tight context.
			_ = mp.ForceFlush(ctx)
			_ = lp.ForceFlush(ctx)
			return errors.Join(mp.Shutdown(ctx), lp.Shutdown(ctx))
		},
	}, nil
}

func buildExporter(ctx context.Context, cfg Config) (sdkmetric.Exporter, error) {
	// Footgun guard: insecure transport + auth headers means a
	// bearer token (e.g. a Datadog / Grafana Cloud OTLP key) goes
	// over plaintext to the collector on both the metric and log
	// exports (the cfg.Headers map is reused for both signals).
	// Loopback collectors that don't terminate TLS are a legitimate
	// case, but the combination usually signals a misconfiguration.
	// Logged once here (rather than duplicated in buildLogExporter)
	// because buildExporter runs first during Init.
	if cfg.Insecure && len(cfg.Headers) > 0 {
		slog.Warn("OTLP insecure transport enabled with auth headers — bearer tokens will be sent in plaintext on both metric and log exports; use a TLS-protected endpoint for production")
	}

	protocol := resolveProtocol(cfg.Protocol, "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL")

	switch protocol {
	case "grpc":
		opts := []otlpmetricgrpc.Option{}
		if cfg.Endpoint != "" {
			opts = append(opts, otlpmetricgrpc.WithEndpoint(stripScheme(cfg.Endpoint)))
		}
		if cfg.Insecure {
			opts = append(opts, otlpmetricgrpc.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlpmetricgrpc.WithHeaders(cfg.Headers))
		}
		return otlpmetricgrpc.New(ctx, opts...)
	case "http/protobuf":
		opts := []otlpmetrichttp.Option{}
		if cfg.Endpoint != "" {
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
			if strings.Contains(cfg.Endpoint, "://") {
				opts = append(opts, otlpmetrichttp.WithEndpointURL(cfg.Endpoint))
			} else {
				opts = append(opts, otlpmetrichttp.WithEndpoint(cfg.Endpoint))
			}
		}
		if cfg.Insecure {
			opts = append(opts, otlpmetrichttp.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlpmetrichttp.WithHeaders(cfg.Headers))
		}
		return otlpmetrichttp.New(ctx, opts...)
	default:
		// Report the *resolved* protocol — when cfg.Protocol was
		// empty and we picked the value up from OTEL_EXPORTER_OTLP_*
		// env vars, that's the value the operator actually has in
		// flight, not the empty config field.
		return nil, fmt.Errorf("unsupported observability protocol %q (use grpc or http/protobuf)", protocol)
	}
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
// cfg.Protocol is empty: a signal-specific override (e.g.
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

// buildLogExporter mirrors buildExporter for OTLP log records. It
// reuses the same Endpoint / Insecure / Headers / Protocol knobs as
// the metric exporter — a single observability block configures both
// signals against the same collector — but reads the
// signal-specific OTEL_EXPORTER_OTLP_LOGS_PROTOCOL override before
// the generic OTEL_EXPORTER_OTLP_PROTOCOL.
func buildLogExporter(ctx context.Context, cfg Config) (sdklog.Exporter, error) {
	protocol := resolveProtocol(cfg.Protocol, "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL")

	switch protocol {
	case "grpc":
		opts := []otlploggrpc.Option{}
		if cfg.Endpoint != "" {
			opts = append(opts, otlploggrpc.WithEndpoint(stripScheme(cfg.Endpoint)))
		}
		if cfg.Insecure {
			opts = append(opts, otlploggrpc.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlploggrpc.WithHeaders(cfg.Headers))
		}
		return otlploggrpc.New(ctx, opts...)
	case "http/protobuf":
		opts := []otlploghttp.Option{}
		if cfg.Endpoint != "" {
			if strings.Contains(cfg.Endpoint, "://") {
				opts = append(opts, otlploghttp.WithEndpointURL(cfg.Endpoint))
			} else {
				opts = append(opts, otlploghttp.WithEndpoint(cfg.Endpoint))
			}
		}
		if cfg.Insecure {
			opts = append(opts, otlploghttp.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlploghttp.WithHeaders(cfg.Headers))
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
	sighupAttempts  metric.Int64Counter
)

func init() {
	rebindInstruments()
	rebindLogger()
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
	sighupAttempts, _ = meter.Int64Counter(
		"dotvault.sighup.received",
		// Permanently zero on Windows (SIGHUP isn't delivered to
		// processes there); on Linux and macOS each SIGHUP forces
		// the LifecycleManager to re-read ~/.vault-token. Full
		// config reload still requires a daemon restart.
		metric.WithDescription("SIGHUP signals received (Linux/macOS only; SIGHUP is not delivered on Windows). Triggers an immediate vault-token file re-read; full config reload still requires a daemon restart."),
	)
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
// label is one of {"copy","github","jfrog","ssh","unknown"}. Outcomes
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

// RecordSIGHUP records a SIGHUP receipt. Each SIGHUP triggers an
// immediate ~/.vault-token re-read via LifecycleManager.Reload;
// the counter surfaces how often that path fires.
func RecordSIGHUP(ctx context.Context) {
	instrMu.RLock()
	c := sighupAttempts
	instrMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1)
}

// Package-level logger handle for OTel log emissions. Rebound by
// rebindLogger from the currently-installed global LoggerProvider —
// the OTel no-op at package init, the SDK LoggerProvider after Init.
// Log* helpers below dereference this under loggerMu so concurrent
// Init / emit calls stay safe. Reads use the global directly via
// rebindLogger rather than calling global.GetLoggerProvider on every
// emit so the hot path doesn't take a lock for atomic-pointer
// dereferences inside the OTel global accessor.
var (
	loggerMu sync.RWMutex
	logger   log.Logger
)

func rebindLogger() {
	loggerMu.Lock()
	defer loggerMu.Unlock()
	logger = global.GetLoggerProvider().Logger("github.com/goodtune/dotvault")
}

// RebindGlobalLogger is the exported sibling of rebindLogger, intended
// for downstream test packages that need to swap the global
// LoggerProvider (via global.SetLoggerProvider) and force the
// package-level logger handle to re-bind onto it. Production code
// must not call this — Init handles the rebind during normal
// startup. Lives in production code rather than a *_test.go file
// because external test packages can't reach unexported symbols.
func RebindGlobalLogger() { rebindLogger() }

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
func LogRegistryConfigManaged(ctx context.Context, path string) {
	loggerMu.RLock()
	l := logger
	loggerMu.RUnlock()
	if l == nil {
		return
	}
	var rec log.Record
	rec.SetTimestamp(time.Now())
	rec.SetSeverity(log.SeverityWarn)
	rec.SetSeverityText("WARN")
	rec.SetBody(log.StringValue("configuration loaded from Windows Registry (Group Policy); file-based config is ignored"))
	rec.AddAttributes(log.String("path", path))
	l.Emit(ctx, rec)
}
