// Package observability wires OpenTelemetry metric instruments and the
// OTLP exporter for the dotvault daemon.
//
// The package is designed to be safe to use unconditionally: when no
// provider has been initialised (Init was not called, or the
// observability config block is absent/disabled) the instruments back
// off to the global no-op meter, so every call site can record without
// nil-checking. Initialise once at daemon start, defer Shutdown.
//
// Attribute conventions:
//   - Outcomes use a small fixed vocabulary ({ok, error, skipped,
//     renewed, reauth_required, failed, completed, denied, …}) so the
//     exported series stay bounded.
//   - We never attach usernames, Vault paths, secret keys, repo URLs,
//     or JFrog server hostnames to instruments — the same scrubbing
//     discipline the slog handlers follow.
package observability

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
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

// Provider is a thin wrapper over an SDK MeterProvider, holding the
// state needed to flush and shut it down cleanly. The zero value
// represents an inactive provider whose Shutdown is a no-op — that's
// what callers get when observability is disabled, so the daemon
// shutdown path doesn't have to branch on whether Init succeeded.
type Provider struct {
	mp       *sdkmetric.MeterProvider
	shutdown func(context.Context) error
}

// Shutdown flushes any pending metric exports and tears down the
// provider. Always returns nil for an inactive provider so callers
// can defer it unconditionally.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || p.shutdown == nil {
		return nil
	}
	return p.shutdown(ctx)
}

// ForceFlush blocks until the periodic reader has exported any
// in-flight metrics, up to the deadline on ctx. Used by `dotvault sync`
// and `dotvault run --once` so cron-style invocations don't drop their
// last cycle's metrics. No-op for an inactive provider.
func (p *Provider) ForceFlush(ctx context.Context) error {
	if p == nil || p.mp == nil {
		return nil
	}
	return p.mp.ForceFlush(ctx)
}

// Init initialises the OTLP metric exporter and installs a global
// MeterProvider. Subsequent calls to package-level instruments (Sync,
// Vault, Token, …) record into this provider. When cfg.Enabled is
// false, Init returns an inactive Provider whose Shutdown is a no-op
// and leaves the global meter unchanged (so instruments back off to
// the OTel no-op meter).
func Init(ctx context.Context, cfg Config) (*Provider, error) {
	if !cfg.Enabled {
		return &Provider{}, nil
	}

	exporter, err := buildExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("build OTLP exporter: %w", err)
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
	reader := sdkmetric.NewPeriodicReader(exporter, readerOpts...)

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
	)
	otel.SetMeterProvider(mp)

	// Rebind instruments so subsequent record-site calls hit the active
	// MeterProvider rather than the no-op global captured at process
	// start. Safe to call repeatedly — instruments are recreated each
	// time, but creation is cheap and Init runs once per process.
	rebindInstruments()

	return &Provider{
		mp: mp,
		shutdown: func(ctx context.Context) error {
			// Best-effort flush before shutdown so the last batch makes
			// it out even when the caller passes a tight context.
			_ = mp.ForceFlush(ctx)
			return mp.Shutdown(ctx)
		},
	}, nil
}

func buildExporter(ctx context.Context, cfg Config) (sdkmetric.Exporter, error) {
	// Honour the OpenTelemetry env-var convention when cfg.Protocol
	// is empty: a metrics-specific override
	// (OTEL_EXPORTER_OTLP_METRICS_PROTOCOL) takes precedence over the
	// generic one (OTEL_EXPORTER_OTLP_PROTOCOL); both fall back to
	// gRPC when unset. Without this fallthrough, a centrally-managed
	// environment that selects http/protobuf via env would be
	// silently overridden to gRPC by the default below.
	protocol := strings.ToLower(strings.TrimSpace(cfg.Protocol))
	if protocol == "" {
		protocol = strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL")))
	}
	if protocol == "" {
		protocol = strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")))
	}
	if protocol == "" {
		protocol = "grpc"
	}

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
			// which to call from whether the value parses as a URL with
			// a scheme.
			if u, err := url.Parse(cfg.Endpoint); err == nil && u.Scheme != "" {
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
		return nil, fmt.Errorf("unsupported observability protocol %q (use grpc or http/protobuf)", cfg.Protocol)
	}
}

func stripScheme(s string) string {
	for _, prefix := range []string{"https://", "http://", "grpc://", "dns:///"} {
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
		metric.WithDescription("SIGHUP signals received (config reload is currently not implemented)"),
	)
}

// RecordSyncTick increments the sync-tick counter with the outcome
// attribute. Outcomes are drawn from a closed vocabulary
// ({"ok","error","skipped"}) so cardinality stays bounded.
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
// Outcomes: "renewed", "reauth_required", "failed", "skipped".
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
// Engines are the registered set ({"copy","github","jfrog","ssh"}),
// outcomes a closed vocabulary ({"completed","skipped","error"}).
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

// RecordSIGHUP records a SIGHUP receipt. Useful even before live reload
// is implemented: it surfaces how often operators try to reload.
func RecordSIGHUP(ctx context.Context) {
	instrMu.RLock()
	c := sighupAttempts
	instrMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1)
}
