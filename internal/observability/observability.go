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
// Attribute conventions. The rules below are about *instrument*
// attributes — the per-record labels passed to a Record* helper, which
// multiply the exported time series. Resource attributes are a
// different thing and are governed separately: a resource attribute is
// one fixed value for the whole process, attached once to every metric
// and log record, and adds no series at all. That is why the resource
// built in Init legitimately carries user.name and a fully-qualified
// host.name while the instrument rules forbid the same values as
// labels.
//
//   - Outcomes use a small fixed vocabulary ({ok, error, renewed,
//     reauth_required, failed, completed, denied, …}) so the
//     exported series stay bounded. See the per-instrument
//     RecordXxx godoc for the exact set each instrument emits.
//   - We never attach usernames, Vault paths, secret keys, repo URLs,
//     or JFrog server hostnames to *instruments* — the same scrubbing
//     discipline the slog handlers follow. The one deliberate exception is
//     the `host` label on the SSH forward instruments (dotvault.ssh.*):
//     unlike a JFrog server URL, it names an entry in the operator's own
//     small, statically-configured remote list — see
//     docs/superpowers/specs/2026-08-09-managed-ssh-forwards-design.md — so
//     the cardinality bound holds for the same reason a Vault path's does
//     not.
//   - The identity attributes on the resource (service.name,
//     service.version, user.name, host.name, os.type, host.arch, the
//     process runtime pair) are process constants, so they identify the
//     emitting daemon without inflating cardinality. They ride every
//     exported metric *and* every exported log record, because the
//     MeterProvider and the LoggerProvider share one resource — see
//     buildResource.
package observability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/paths"
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

	// Endpoint is the OTLP collector address for this signal, and both
	// signals share one contract. A full URL with a scheme is the
	// recommended form: the scheme carries the TLS intent (https → TLS,
	// http → plaintext) and an explicit path is used verbatim — no mount
	// path is assumed, so a vendor route like
	// "https://collector.example/tenant/v1/metrics" works as written. A
	// URL without a path gets the OTLP standard "/v1/metrics" /
	// "/v1/logs" appended (http/protobuf only; gRPC has no URL path).
	// Bare "host:port" also works — canonical for gRPC — with TLS then
	// governed by Insecure. A "grpc://" prefix is tolerated and stripped
	// (carrying no TLS meaning); "dns:///" is preserved as a gRPC
	// resolver target. When empty the SDK falls through to
	// OTEL_EXPORTER_OTLP_ENDPOINT (and the signal-specific
	// OTEL_EXPORTER_OTLP_METRICS_ENDPOINT / _LOGS_ENDPOINT variants).
	Endpoint string

	// Protocol selects the exporter implementation: "grpc" (default) or
	// "http/protobuf".
	Protocol string

	// Insecure disables transport security. Meaningful for scheme-less
	// endpoints; an endpoint URL's scheme already carries the TLS intent,
	// and Insecure true additionally forces plaintext over it.
	Insecure bool

	// Temporality is the metric temporality preference: "cumulative",
	// "delta", or "lowmemory", mirroring the vocabulary (and instrument-
	// kind mapping) of OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE.
	// Empty falls through to that env var, then the SDK default
	// (cumulative). Metrics-only — config validation rejects it on the
	// log signal, and buildLogExporter ignores it.
	Temporality string

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

	res, err := buildResource(ctx, cfg)
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

// hostNameLookupTimeout bounds the FQDN resolver call made once at Init.
// The daemon's startup is behind this, so a laptop on a captive-portal
// network with a black-holed resolver must not stall it: two seconds is
// generous for a nameserver that is going to answer at all, and the
// fallback (the short os.Hostname value) is perfectly usable.
//
// A var rather than a const purely so the timeout path can be tested
// without a test that really sleeps for two seconds; production never
// assigns it.
var hostNameLookupTimeout = 2 * time.Second

// Test seams. Package-level vars rather than parameters so the resource
// stays buildable from cfg alone; tests swap them and restore with
// t.Cleanup.
//
// lookupCNAME resolves the canonical name of a host. LookupCNAME is
// chosen over the LookupIP+LookupAddr (PTR) route deliberately: it is a
// single *forward* lookup, so it goes through the same search-domain
// list the host already uses to resolve its own name — which is exactly
// what qualifies a short hostname, and what `hostname -f` relies on.
// The reverse route depends on a PTR record that DHCP-addressed laptops
// and cloud instances frequently do not have, and when one does exist it
// is often an ISP- or provider-generated name unrelated to the host's
// identity; worse, a short name in /etc/hosts commonly resolves to
// 127.0.0.1, whose PTR is "localhost". Both failure shapes would replace
// a correct short name with a wrong qualified one, which is worse than
// not qualifying at all.
var (
	lookupCNAME     = net.DefaultResolver.LookupCNAME
	osHostname      = os.Hostname
	currentUsername = paths.Username
)

// resolveHostName returns the value for the host.name resource
// attribute: the FQDN when one can be established, else whatever
// os.Hostname reported.
//
// A name that already contains a dot is treated as qualified and
// returned as-is — no lookup. Otherwise a single bounded LookupCNAME
// runs; its result is accepted only if it is actually qualified (has a
// dot) and is not a localhost alias, since a resolver that answers the
// short name from /etc/hosts can return exactly that. Every other
// outcome — resolver error, timeout, empty hostname, unqualified or
// loopback answer — falls back to the short name. This never returns an
// error: observability must not fail because DNS did not answer.
func resolveHostName(ctx context.Context) string {
	hostname, _ := osHostname()
	if hostname == "" || strings.Contains(hostname, ".") {
		return hostname
	}

	lookupCtx, cancel := context.WithTimeout(ctx, hostNameLookupTimeout)
	defer cancel()

	cname, err := lookupCNAME(lookupCtx, hostname)
	if err != nil {
		slog.Debug("could not qualify hostname for the host.name resource attribute; using the short name", "hostname", hostname, "error", err)
		return hostname
	}
	cname = strings.TrimSuffix(cname, ".")
	if !strings.Contains(cname, ".") || hasPrefixFold(cname, "localhost.") {
		return hostname
	}
	return cname
}

// buildResource assembles the OTel resource shared by the MeterProvider
// and the LoggerProvider, so every exported metric and log record
// carries the same process identity.
func buildResource(ctx context.Context, cfg Config) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName("dotvault"),
		semconv.ServiceVersion(stringOr(cfg.ServiceVersion, "dev")),
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
	}

	// host.name is omitted rather than attached empty when os.Hostname
	// reports nothing usable, symmetric with user.name below: an empty
	// string is not a host identity, and a present-but-blank attribute is
	// harder to reason about at the collector than an absent one.
	if hostname := resolveHostName(ctx); hostname != "" {
		attrs = append(attrs, semconv.HostName(hostname))
	}

	// user.name identifies which per-user daemon emitted a series — the
	// unit dotvault is deployed as. Omitted rather than fatal when the
	// OS lookup fails: observability is never allowed to stop the daemon
	// starting, matching the ignored error on os.Hostname above.
	if username, err := currentUsername(); err != nil {
		slog.Debug("could not resolve the current user for the user.name resource attribute; omitting it", "error", err)
	} else if username != "" {
		attrs = append(attrs, semconv.UserName(username))
	}

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
	return resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("", attrs...),
	)
}

func buildMetricExporter(ctx context.Context, sig Signal) (sdkmetric.Exporter, error) {
	warnInsecureHeaders("metrics", sig)

	protocol := resolveProtocol(sig.Protocol, "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL")

	temporality, err := temporalitySelector(sig.Temporality)
	if err != nil {
		return nil, err
	}

	switch protocol {
	case "grpc":
		opts := []otlpmetricgrpc.Option{}
		if sig.Endpoint != "" {
			// An http(s) scheme carries the TLS intent (WithEndpointURL
			// derives insecure from it), matching the http/protobuf path
			// below so the scheme means the same thing on every protocol.
			// Other prefixes keep the historical handling: grpc:// is
			// stripped, dns:/// passes through as a gRPC resolver target.
			if hasHTTPScheme(sig.Endpoint) {
				warnGRPCSchemeDowngrade("metrics", sig)
				opts = append(opts, otlpmetricgrpc.WithEndpointURL(sig.Endpoint))
			} else {
				opts = append(opts, otlpmetricgrpc.WithEndpoint(stripScheme(sig.Endpoint)))
			}
		}
		if sig.Insecure {
			opts = append(opts, otlpmetricgrpc.WithInsecure())
		}
		if len(sig.Headers) > 0 {
			opts = append(opts, otlpmetricgrpc.WithHeaders(sig.Headers))
		}
		if temporality != nil {
			opts = append(opts, otlpmetricgrpc.WithTemporalitySelector(temporality))
		}
		return otlpmetricgrpc.New(ctx, opts...)
	case "http/protobuf":
		opts := []otlpmetrichttp.Option{}
		if sig.Endpoint != "" {
			// otlpmetrichttp distinguishes endpoint vs URL: WithEndpoint
			// takes host[:port], WithEndpointURL takes a fully-qualified
			// URL. The single user-facing field routes on hasHTTPScheme —
			// the same predicate as the gRPC branch, so the scheme means
			// the same thing on every protocol — with anything else
			// treated as a dial target (a stray grpc:// stripped rather
			// than fed to WithEndpointURL, where its non-https scheme
			// would silently select plaintext).
			if hasHTTPScheme(sig.Endpoint) {
				opts = append(opts, otlpmetrichttp.WithEndpointURL(sig.Endpoint))
			} else {
				opts = append(opts, otlpmetrichttp.WithEndpoint(stripScheme(sig.Endpoint)))
			}
		}
		if sig.Insecure {
			opts = append(opts, otlpmetrichttp.WithInsecure())
		}
		if len(sig.Headers) > 0 {
			opts = append(opts, otlpmetrichttp.WithHeaders(sig.Headers))
		}
		if temporality != nil {
			opts = append(opts, otlpmetrichttp.WithTemporalitySelector(temporality))
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
// out so the condition is testable without capturing log output. Plaintext
// transport arrives two ways — the Insecure flag, or an explicit http://
// scheme on the endpoint (which WithEndpointURL translates to insecure on
// every protocol) — and the guard must catch both, or the recommended
// full-URL form would be exactly the shape that ships a bearer token over
// cleartext unwarned.
func insecureHeaderFootgun(sig Signal) bool {
	plaintext := sig.Insecure || hasPrefixFold(sig.Endpoint, "http://")
	return plaintext && len(sig.Headers) > 0
}

// warnGRPCSchemeDowngrade flags the one shape whose meaning this release
// changed: a gRPC endpoint written as "http://host:port". Previous releases
// stripped the scheme and attempted TLS; the scheme now selects plaintext,
// matching http/protobuf. A config that was (mis)written that way against a
// TLS collector will stop exporting and start sending its HTTP/2 preface —
// headers included — in cleartext, so the change must be loud: one WARN per
// exporter build naming the fix for each intent.
func warnGRPCSchemeDowngrade(signal string, sig Signal) {
	if hasPrefixFold(sig.Endpoint, "http://") {
		slog.Warn("gRPC OTLP endpoint has an http:// scheme, which now selects PLAINTEXT transport (earlier releases ignored the scheme and used TLS) — use https:// or drop the scheme to keep TLS, or keep http:// if plaintext is intended", "signal", signal)
	}
}

// temporalitySelector maps the configured temporality preference onto the
// SDK selector, using the exact vocabulary and instrument-kind mapping of
// OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE so an operator who knows
// the env var knows the config field: "cumulative" (everything cumulative,
// the OTLP default), "delta" (counters, observable counters, and histograms
// delta; up-down counters stay cumulative), "lowmemory" (only synchronous
// counters and histograms delta). Empty returns a nil selector — the option
// is then not passed at all, so the SDK's own env-var reading applies,
// consistent with every other empty exporter field. A non-empty value
// overrides the env var, also like every other field. An unknown value is a
// config error surfaced at Init rather than the env var's warn-and-ignore,
// because a config file is validated where an ambient variable is tolerated.
func temporalitySelector(preference string) (sdkmetric.TemporalitySelector, error) {
	switch strings.ToLower(strings.TrimSpace(preference)) {
	case "":
		return nil, nil
	case "cumulative":
		return sdkmetric.DefaultTemporalitySelector, nil
	case "delta":
		return sdkmetric.DeltaTemporalitySelector, nil
	case "lowmemory":
		return sdkmetric.LowMemoryTemporalitySelector, nil
	default:
		return nil, fmt.Errorf("unsupported metric temporality %q (use cumulative, delta, or lowmemory)", preference)
	}
}

// hasHTTPScheme reports whether an endpoint is written as a full http(s)
// URL — the form whose scheme carries the TLS intent on every protocol.
// Deliberately a prefix check, not url.Parse: parsing "127.0.0.1:4317"
// yields Scheme "127.0.0.1", so a parse-based check would misclassify the
// canonical host:port form. Case-insensitive, because URL schemes are:
// url.Parse canonicalises "HTTP://" to scheme "http", so a case-sensitive
// check here would route the uppercase form away from WithEndpointURL —
// and past the plaintext warnings — while the SDK would still have
// treated it as plaintext had it arrived.
func hasHTTPScheme(s string) bool {
	return hasPrefixFold(s, "https://") || hasPrefixFold(s, "http://")
}

// hasPrefixFold is strings.HasPrefix under Unicode case-folding — the
// one predicate all scheme checks share so their case handling cannot
// drift apart.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// stripScheme normalises an OTLP gRPC endpoint by removing a
// URL-style scheme so the underlying gRPC dialer receives a bare
// host:port (which is what otlpmetricgrpc.WithEndpoint expects).
// http(s):// endpoints are routed through WithEndpointURL before this
// runs (their scheme carries TLS intent); this handles the leftovers —
// grpc:// is stripped as a tolerated no-meaning prefix, in any case
// (schemes are case-insensitive).
//
// dns:/// is deliberately preserved: it is a valid gRPC resolver
// prefix (not a URL scheme) that enables the DNS resolver for
// multi-address service discovery / load balancing. Stripping it
// would change the dial-target semantics and break those setups.
func stripScheme(s string) string {
	for _, prefix := range []string{"https://", "http://", "grpc://"} {
		if hasPrefixFold(s, prefix) {
			return s[len(prefix):]
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
			// Same scheme contract as the metric exporter: http(s) URLs
			// carry TLS intent via WithEndpointURL, everything else is a
			// dial target (grpc:// stripped, dns:/// preserved).
			if hasHTTPScheme(sig.Endpoint) {
				warnGRPCSchemeDowngrade("logs", sig)
				opts = append(opts, otlploggrpc.WithEndpointURL(sig.Endpoint))
			} else {
				opts = append(opts, otlploggrpc.WithEndpoint(stripScheme(sig.Endpoint)))
			}
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
			// Same routing as the metric http branch: hasHTTPScheme →
			// full URL, anything else a dial target with stray schemes
			// stripped.
			if hasHTTPScheme(sig.Endpoint) {
				opts = append(opts, otlploghttp.WithEndpointURL(sig.Endpoint))
			} else {
				opts = append(opts, otlploghttp.WithEndpoint(stripScheme(sig.Endpoint)))
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

	// SSH forward instruments (internal/sshfwd's managed remotes). See the
	// Record* helpers below for the attribute contract each one accepts.
	sshConnections       metric.Int64Gauge
	sshReconnects        metric.Int64Counter
	sshConnectFailures   metric.Int64Counter
	sshKeepaliveFailures metric.Int64Counter
	sshForwardActive     metric.Int64UpDownCounter
	sshForwardConnsTotal metric.Int64Counter
	sshForwardFailures   metric.Int64Counter

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

	sshConnections, _ = meter.Int64Gauge(
		"dotvault.ssh.connections",
		metric.WithDescription("Managed SSH remote connection state by host: 1 while connected, 0 otherwise"),
	)
	sshReconnects, _ = meter.Int64Counter(
		"dotvault.ssh.reconnect_total",
		metric.WithDescription("Managed SSH remote reconnect attempts by host, counted once per dropped connection redial"),
	)
	sshConnectFailures, _ = meter.Int64Counter(
		"dotvault.ssh.connect_failure_total",
		metric.WithDescription("Managed SSH remote connection-attempt failures by host and error class"),
	)
	sshKeepaliveFailures, _ = meter.Int64Counter(
		"dotvault.ssh.keepalive_failure_total",
		metric.WithDescription("Managed SSH remote keepalive strike-threshold failures by host"),
	)
	sshForwardActive, _ = meter.Int64UpDownCounter(
		"dotvault.ssh.forward_connections_active",
		metric.WithDescription("Currently active relayed connections on a managed SSH remote's forward, by host"),
	)
	sshForwardConnsTotal, _ = meter.Int64Counter(
		"dotvault.ssh.forward_connections_total",
		metric.WithDescription("Total relayed connections accepted on a managed SSH remote's forward, by host"),
	)
	sshForwardFailures, _ = meter.Int64Counter(
		"dotvault.ssh.forward_failure_total",
		metric.WithDescription("Managed SSH remote forward-target dial failures by host (the local API surface could not be reached for an accepted connection)"),
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

// RecordSSHConnState records a managed SSH remote's connected/disconnected
// state for dotvault.ssh.connections, a synchronous gauge that reports the
// instantaneous value (1 while connected, 0 otherwise) rather than a running
// total. Call this only on an actual state transition — entering
// StateConnected, or leaving it — never once per run-loop retry attempt, or
// the series reads as flapping for a remote that is simply redialling a
// still-dead connection.
func RecordSSHConnState(ctx context.Context, host string, connected bool) {
	instrMu.RLock()
	g := sshConnections
	instrMu.RUnlock()
	if g == nil {
		return
	}
	v := int64(0)
	if connected {
		v = 1
	}
	g.Record(ctx, v, metric.WithAttributes(attribute.String("host", host)))
}

// RecordSSHReconnect increments dotvault.ssh.reconnect_total for host. Call
// once per completed reconnect — when a previously established connection
// has been torn down and the remote redials — not for the very first
// connection attempt.
func RecordSSHReconnect(ctx context.Context, host string) {
	instrMu.RLock()
	c := sshReconnects
	instrMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(attribute.String("host", host)))
}

// RecordSSHConnectFailure increments dotvault.ssh.connect_failure_total,
// labelled by host and class. class must be one of sshfwd's fixed
// ErrorClass values (dns, network-unreachable, connection-refused,
// handshake, authentication, host-key, remote-socket-bind, home-probe,
// config, other) — pass sshfwd.Classify(err)'s result converted to a
// string, never an error message or any other free-form text, or the label
// cardinality is unbounded.
func RecordSSHConnectFailure(ctx context.Context, host, class string) {
	instrMu.RLock()
	c := sshConnectFailures
	instrMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(
		attribute.String("host", host),
		attribute.String("class", class),
	))
}

// RecordSSHKeepaliveFailure increments dotvault.ssh.keepalive_failure_total
// for host. Call once when Keepalive's consecutive-strike threshold is
// reached and the connection is being torn down as a result — not once per
// individual missed keepalive round-trip, and not for an ordinary shutdown
// (ctx cancellation), which is not a keepalive failure.
func RecordSSHKeepaliveFailure(ctx context.Context, host string) {
	instrMu.RLock()
	c := sshKeepaliveFailures
	instrMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(attribute.String("host", host)))
}

// RecordSSHForwardConn records one forward connection accepted (delta > 0)
// or closed (delta < 0) on a managed SSH remote's forward, by host. It
// updates dotvault.ssh.forward_connections_active — an up-down counter, so
// the exported series is the running sum of every delta this function has
// ever recorded for that host, i.e. the current active count — and, for an
// accepted connection, increments dotvault.ssh.forward_connections_total.
// Intended as the direct backing for serveListener's per-connection onConn
// callback, so it is called once per accept and once per close, not on a
// timer or a loop.
func RecordSSHForwardConn(ctx context.Context, host string, delta int) {
	instrMu.RLock()
	active := sshForwardActive
	total := sshForwardConnsTotal
	instrMu.RUnlock()
	if active != nil {
		active.Add(ctx, int64(delta), metric.WithAttributes(attribute.String("host", host)))
	}
	if delta > 0 && total != nil {
		total.Add(ctx, int64(delta), metric.WithAttributes(attribute.String("host", host)))
	}
}

// RecordSSHForwardFailure increments dotvault.ssh.forward_failure_total,
// labelled by host (bounded by the user's configured remote list, like every
// other SSH instrument's host label). Recorded when an accepted forward
// connection cannot be relayed because the local target dial failed — the
// forward's own accept loop keeps running, so this is a per-attempt failure
// count, not a fatal condition.
func RecordSSHForwardFailure(ctx context.Context, host string) {
	instrMu.RLock()
	c := sshForwardFailures
	instrMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(attribute.String("host", host)))
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
	rec.SetBody(attribute.StringValue("configuration loaded from Windows Registry (Group Policy); file-based config is ignored"))
	rec.AddAttributes(attribute.String("path", path))
	l.Emit(ctx, rec)
}
