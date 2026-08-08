package observability

import (
	"context"
	"runtime"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestInitDisabled confirms the disabled path returns an inactive
// provider whose Shutdown / ForceFlush are no-ops and never reach the
// SDK exporter (which would otherwise require a reachable collector).
func TestInitDisabled(t *testing.T) {
	p, err := Init(context.Background(), Config{Enabled: false})
	if err != nil {
		t.Fatalf("Init disabled: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown of inactive provider returned %v", err)
	}
	if err := p.ForceFlush(context.Background()); err != nil {
		t.Errorf("ForceFlush of inactive provider returned %v", err)
	}
}

// TestRecordWithoutInit confirms package-level record helpers are
// callable before Init runs (the no-op meter is installed by package
// init). This is the contract every call site depends on — they
// invoke Record* unconditionally and must never panic on a nil
// instrument.
func TestRecordWithoutInit(t *testing.T) {
	ctx := context.Background()
	// None of these should panic.
	RecordSyncTick(ctx, "ok")
	RecordSyncDuration(ctx, 100*time.Millisecond, "ok")
	RecordVaultCall(ctx, "read", "ok")
	RecordTokenRenewal(ctx, "renewed")
	RecordTokenTTL(ctx, time.Hour)
	RecordEnrolAttempt(ctx, "ssh", "completed")
	RecordWebRequest(ctx, "/api/v1/status", "2xx")
	RecordConfigReload(ctx, "no_change")
	RecordSIGHUP(ctx)
}

// TestRecordReachesActiveMeterProvider is the behavioural test for
// rebindInstruments: after the package-level Record* helpers are
// rebuilt to point at the active MeterProvider, a recorded counter
// must actually appear in the provider's reader. Without this
// assertion, rebindInstruments could be a no-op and TestInitDisabled
// + TestRecordWithoutInit would still pass (both rely on the
// no-op meter being the failure mode).
//
// Uses a ManualReader installed directly on a test-local
// MeterProvider, then routes the global meter provider at it via
// otel.SetMeterProvider so the package-level instruments rebind
// onto our reader. Cleanup restores the previous global so other
// tests don't see our reader.
func TestRecordReachesActiveMeterProvider(t *testing.T) {
	reader := newTestReader(t)

	ctx := context.Background()
	RecordSyncTick(ctx, "ok")
	RecordVaultCall(ctx, "read", "ok")
	RecordEnrolAttempt(ctx, "ssh", "completed")
	RecordDeprecatedConfig(ctx, "observability.endpoint")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("reader.Collect: %v", err)
	}

	counters := map[string]int64{}
	deprecatedHasFieldAttr := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			var total int64
			for _, dp := range sum.DataPoints {
				total += dp.Value
				if m.Name == "dotvault.config.deprecated" {
					if v, ok := dp.Attributes.Value(attribute.Key("field")); ok && v.AsString() == "observability.endpoint" {
						deprecatedHasFieldAttr = true
					}
				}
			}
			counters[m.Name] = total
		}
	}
	// The field attribute is the fleet-migration contract for
	// dotvault.config.deprecated — a collector-side sum grouped by `field`
	// only measures anything if the attribute is actually attached.
	if !deprecatedHasFieldAttr {
		t.Error(`dotvault.config.deprecated datapoint lacks the field="observability.endpoint" attribute`)
	}

	for _, name := range []string{
		"dotvault.sync.ticks",
		"dotvault.vault.calls",
		"dotvault.enrol.attempts",
		"dotvault.config.deprecated",
	} {
		if counters[name] < 1 {
			t.Errorf("counter %q = %d, want ≥1 — rebindInstruments did not wire it to the active provider", name, counters[name])
		}
	}
}

// TestInitBadProtocol verifies the validation path rejects unknown
// transport values up front so misconfiguration surfaces at startup
// rather than at first export.
func TestInitBadProtocol(t *testing.T) {
	_, err := Init(context.Background(), Config{
		Enabled: true,
		Metrics: Signal{Enabled: true, Protocol: "smoke-signals"},
		Logs:    Signal{Enabled: true, Protocol: "smoke-signals"},
	})
	if err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
}

// TestLogRegistryConfigManagedNoProvider confirms the helper is safe
// to call before Init wires up the SDK LoggerProvider. The contract
// mirrors the metric Record* helpers — call sites invoke it
// unconditionally and rely on the no-op global swallowing the record
// when observability is disabled. This is the whole point of routing
// through OTel rather than slog: a CLI invocation on a GPO-managed
// Windows box must not leak the "configuration loaded from Windows
// Registry" message to stdout.
func TestLogRegistryConfigManagedNoProvider(t *testing.T) {
	// Must not panic. The helper resolves the logger from the
	// current global LoggerProvider on each call — at this point in
	// the test suite (no recording provider installed), that's the
	// OTel no-op global, and the record is silently dropped.
	LogRegistryConfigManaged(context.Background(), `C:\ProgramData\dotvault\config.yaml`)
}

// TestLogRegistryConfigManagedReachesActiveProvider verifies that
// once an SDK LoggerProvider is installed via global.SetLoggerProvider,
// the helper resolves it and emits a WARN-severity record with the
// expected body and path attribute. Without this assertion, a future
// regression that hard-codes the no-op global inside the helper
// (or otherwise bypasses the global lookup) would still let
// TestLogRegistryConfigManagedNoProvider pass.
func TestLogRegistryConfigManagedReachesActiveProvider(t *testing.T) {
	rec := newTestLogProcessor(t)

	const path = `C:\ProgramData\dotvault\config.yaml`
	LogRegistryConfigManaged(context.Background(), path)

	records := rec.Snapshot()
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	r := records[0]
	if got, want := r.Severity(), log.SeverityWarn; got != want {
		t.Errorf("severity = %v, want %v", got, want)
	}
	if body := bodyString(t, r.Body()); body != "configuration loaded from Windows Registry (Group Policy); file-based config is ignored" {
		t.Errorf("body = %q", body)
	}
	var foundPath bool
	r.WalkAttributes(func(kv log.KeyValue) bool {
		if kv.Key == "path" {
			foundPath = true
			if got := kv.Value.AsString(); got != path {
				t.Errorf("path attribute = %q, want %q", got, path)
			}
		}
		return true
	})
	if !foundPath {
		t.Error("path attribute not present on emitted record")
	}
}

// TestInitBuildsResource locks in the empty-schema-URL contract in
// Init (observability.go): the custom resource must merge with
// resource.Default() without a "conflicting Schema URL" error,
// regardless of which semconv schema the installed otel/sdk pins in
// Default(). This is the regression guard for the otel/sdk bump that
// moved Default()'s schema ahead of the semconv version this package
// imports — without the empty schema URL, Init returns an error here.
// TestProtocolFallthroughToEnv covers this too, incidentally, but its
// name signposts protocol selection rather than resource construction.
func TestInitBuildsResource(t *testing.T) {
	prevMP := otel.GetMeterProvider()
	prevLP := global.GetLoggerProvider()
	t.Cleanup(func() {
		otel.SetMeterProvider(prevMP)
		global.SetLoggerProvider(prevLP)
		rebindInstruments()
	})

	t.Cleanup(func() { setBuildVersion("") })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p, err := Init(ctx, Config{
		Enabled:        true,
		Metrics:        Signal{Enabled: true, Endpoint: "127.0.0.1:0", Insecure: true},
		Logs:           Signal{Enabled: true, Endpoint: "127.0.0.1:0", Insecure: true},
		ServiceVersion: "9.9.9-init-test",
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if p == nil {
		t.Fatal("Init returned a nil provider")
	}
	// Init must thread cfg.ServiceVersion through to the build_info gauge
	// (setBuildVersion before its rebind) — TestBuildInfoGauge covers the
	// seam, this covers the caller: dropping the setBuildVersion call in
	// Init would ship version="dev" on every tagged build.
	instrMu.RLock()
	gotVersion := buildVersion
	instrMu.RUnlock()
	if gotVersion != "9.9.9-init-test" {
		t.Errorf("buildVersion after Init = %q, want %q", gotVersion, "9.9.9-init-test")
	}
	_ = p.Shutdown(ctx)
}

// TestProtocolFallthroughToEnv confirms an empty cfg.Protocol picks
// up the OTel env-var convention. The metrics-specific override wins
// over the generic one, matching the SDK's documented precedence.
func TestProtocolFallthroughToEnv(t *testing.T) {
	// Init mutates two process-wide globals (MeterProvider and
	// LoggerProvider). Save and restore both so later tests in the
	// same package don't observe a non-default or Shutdown()'d
	// provider — mirrors newTestReader / newTestLogProcessor's
	// discipline. The MeterProvider also needs an explicit instrument
	// rebind because Record* helpers cache instrument handles; the
	// logger has no such cache, so the global restore is sufficient.
	prevMP := otel.GetMeterProvider()
	prevLP := global.GetLoggerProvider()
	t.Cleanup(func() {
		otel.SetMeterProvider(prevMP)
		global.SetLoggerProvider(prevLP)
		rebindInstruments()
	})

	// Pointing at an unreachable collector with a short context means
	// the test exits quickly while still exercising the protocol
	// selection. We don't need the export to succeed — we only care
	// that the http/protobuf branch was taken (and didn't error out
	// at the unsupported-protocol guard, which it would have if the
	// env var hadn't been read).
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "http/protobuf")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p, err := Init(ctx, Config{
		Enabled: true,
		Metrics: Signal{Enabled: true, Endpoint: "127.0.0.1:0", Insecure: true},
		Logs:    Signal{Enabled: true, Endpoint: "127.0.0.1:0", Insecure: true},
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	_ = p.Shutdown(ctx)

	// Generic env var alone (metrics-specific override absent) must
	// still feed through.
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	p, err = Init(ctx, Config{
		Enabled: true,
		Metrics: Signal{Enabled: true, Endpoint: "127.0.0.1:0", Insecure: true},
		Logs:    Signal{Enabled: true, Endpoint: "127.0.0.1:0", Insecure: true},
	})
	if err != nil {
		t.Fatalf("Init (generic env): %v", err)
	}
	_ = p.Shutdown(ctx)
}

// TestInitSignalSelective pins the per-signal contract: initialising with
// one signal disabled must leave that signal's process-wide global
// untouched, so its call sites (metric instruments, or the Log* helpers)
// stay backed by the OTel no-op implementation exactly as
// if observability were off for that signal — while the enabled signal gets
// a real provider.
func TestInitSignalSelective(t *testing.T) {
	prevMP := otel.GetMeterProvider()
	prevLP := global.GetLoggerProvider()
	t.Cleanup(func() {
		otel.SetMeterProvider(prevMP)
		global.SetLoggerProvider(prevLP)
		rebindInstruments()
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Logs only: the MeterProvider global must not move.
	p, err := Init(ctx, Config{
		Enabled: true,
		Logs:    Signal{Enabled: true, Endpoint: "127.0.0.1:0", Insecure: true},
	})
	if err != nil {
		t.Fatalf("Init (logs only): %v", err)
	}
	if got := otel.GetMeterProvider(); got != prevMP {
		t.Error("logs-only Init replaced the global MeterProvider; metrics should have stayed no-op")
	}
	if got := global.GetLoggerProvider(); got == prevLP {
		t.Error("logs-only Init did not install a LoggerProvider")
	}
	_ = p.Shutdown(ctx)
	global.SetLoggerProvider(prevLP)

	// Metrics only: the LoggerProvider global must not move.
	p, err = Init(ctx, Config{
		Enabled: true,
		Metrics: Signal{Enabled: true, Endpoint: "127.0.0.1:0", Insecure: true},
	})
	if err != nil {
		t.Fatalf("Init (metrics only): %v", err)
	}
	if got := global.GetLoggerProvider(); got != prevLP {
		t.Error("metrics-only Init replaced the global LoggerProvider; logs should have stayed no-op")
	}
	if got := otel.GetMeterProvider(); got == prevMP {
		t.Error("metrics-only Init did not install a MeterProvider")
	}
	_ = p.Shutdown(ctx)
	otel.SetMeterProvider(prevMP)
	rebindInstruments()

	// Master on, both signals off: inactive provider, neither global moves.
	p, err = Init(ctx, Config{Enabled: true})
	if err != nil {
		t.Fatalf("Init (both disabled): %v", err)
	}
	if otel.GetMeterProvider() != prevMP || global.GetLoggerProvider() != prevLP {
		t.Error("Init with both signals disabled must leave both globals untouched")
	}
	_ = p.Shutdown(ctx)
}

// TestEndpointSchemeRouting pins the predicate pair that decides how an
// endpoint reaches the SDK — the headline of the scheme-carries-TLS
// contract. hasHTTPScheme owns the "full URL, scheme is meaningful" branch
// (WithEndpointURL); everything else is a dial target where stripScheme
// removes a stray grpc:// and preserves dns:/// resolver targets. Both
// protocols route through the same pair, so these tables pin the routing
// for gRPC and http/protobuf alike.
func TestEndpointSchemeRouting(t *testing.T) {
	urlForm := map[string]bool{
		"http://127.0.0.1:4317":                  true,
		"https://collector.example":              true,
		"https://collector.example/t/v1/metrics": true,
		"127.0.0.1:4317":                         false,
		"collector.example:4317":                 false,
		"grpc://collector.example:4317":          false,
		"dns:///collector.example:4317":          false,
		"":                                       false,
	}
	for endpoint, want := range urlForm {
		if got := hasHTTPScheme(endpoint); got != want {
			t.Errorf("hasHTTPScheme(%q) = %v, want %v", endpoint, got, want)
		}
	}

	stripped := map[string]string{
		"grpc://collector.example:4317": "collector.example:4317",
		"collector.example:4317":        "collector.example:4317",
		"dns:///collector.example:4317": "dns:///collector.example:4317",
		// Dead at the current call sites (hasHTTPScheme routes these to
		// WithEndpointURL first) but kept as defence in depth — pinned so
		// a future call-site change doesn't find surprising behaviour.
		"https://collector.example:4317": "collector.example:4317",
	}
	for in, want := range stripped {
		if got := stripScheme(in); got != want {
			t.Errorf("stripScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBuildInfoGauge pins the Prometheus-convention build-identity gauge:
// constant value 1, one series per build, attributes mirroring
// `dotvault version --json` (version / go_version / os / arch), with the
// version flowing from setBuildVersion — the seam Init uses to inject
// main.version — and repeated rebinds replacing rather than stacking the
// callback registration.
func TestBuildInfoGauge(t *testing.T) {
	// newTestReader first: its LIFO cleanup rebinds onto the restored
	// provider, and setBuildVersion's cleanup must have run by then so the
	// restore-time registration doesn't carry the test version.
	reader := newTestReader(t)
	setBuildVersion("1.2.3-test")
	t.Cleanup(func() { setBuildVersion("") })
	// A second rebind on the same meter must unregister the first
	// callback; two live registrations would observe the gauge twice.
	rebindInstruments()

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("reader.Collect: %v", err)
	}

	var points []metricdata.DataPoint[int64]
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "dotvault.build_info" {
				continue
			}
			g, ok := m.Data.(metricdata.Gauge[int64])
			if !ok {
				t.Fatalf("dotvault.build_info data type = %T, want Gauge[int64]", m.Data)
			}
			points = append(points, g.DataPoints...)
		}
	}
	if len(points) != 1 {
		t.Fatalf("dotvault.build_info datapoints = %d, want exactly 1 (duplicate registrations stack observations)", len(points))
	}
	dp := points[0]
	if dp.Value != 1 {
		t.Errorf("build_info value = %d, want the constant 1", dp.Value)
	}
	for key, want := range map[string]string{
		"version":    "1.2.3-test",
		"go_version": runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
	} {
		v, ok := dp.Attributes.Value(attribute.Key(key))
		if !ok || v.AsString() != want {
			t.Errorf("build_info attribute %q = %q (present=%v), want %q", key, v.AsString(), ok, want)
		}
	}
}

// TestTemporalitySelector pins the config-to-SDK mapping and its contract
// with the OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE vocabulary:
// empty means "don't pass the option" (nil selector — the SDK then reads the
// env var itself), each named preference maps onto the SDK selector with the
// spec's instrument-kind split, and an unknown name is a hard error rather
// than the env var's warn-and-ignore.
func TestTemporalitySelector(t *testing.T) {
	t.Run("empty falls through (nil selector)", func(t *testing.T) {
		sel, err := temporalitySelector("")
		if err != nil {
			t.Fatalf("temporalitySelector: %v", err)
		}
		if sel != nil {
			t.Error("empty preference must yield a nil selector so the SDK's env-var reading applies")
		}
	})

	t.Run("unknown name errors", func(t *testing.T) {
		if _, err := temporalitySelector("sideways"); err == nil {
			t.Error("want an error for an unknown temporality preference")
		}
	})

	t.Run("normalization matches validation", func(t *testing.T) {
		// config.validateOTLPTemporality accepts mixed case and padding;
		// a value that validates must resolve here or a validated config
		// would fail at Init. Lockstep normalization is the contract.
		for _, v := range []string{"Delta", "CUMULATIVE", " lowmemory "} {
			sel, err := temporalitySelector(v)
			if err != nil {
				t.Errorf("temporalitySelector(%q): %v — validation would have accepted this", v, err)
			}
			if sel == nil {
				t.Errorf("temporalitySelector(%q) = nil selector", v)
			}
		}
	})

	t.Run("selector is consulted by the exporter builders", func(t *testing.T) {
		// The pure mapping above proves nothing about wiring: an invalid
		// preference must fail the build on BOTH protocol paths, which is
		// the cheapest observable proof that buildMetricExporter consults
		// the selector at all (a live collector would be needed to observe
		// the temporality itself).
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		for _, protocol := range []string{"grpc", "http/protobuf"} {
			if _, err := buildMetricExporter(ctx, Signal{
				Protocol:    protocol,
				Endpoint:    "127.0.0.1:0",
				Insecure:    true,
				Temporality: "sideways",
			}); err == nil {
				t.Errorf("buildMetricExporter(%s) with invalid temporality: want error, got nil", protocol)
			}
		}
	})

	// The kind→temporality split per preference, straight from the spec:
	// delta flips counters, observable counters, and histograms;
	// lowmemory flips only the synchronous counter and histogram;
	// cumulative flips nothing. UpDownCounters stay cumulative throughout.
	kinds := map[string]sdkmetric.InstrumentKind{
		"counter":            sdkmetric.InstrumentKindCounter,
		"histogram":          sdkmetric.InstrumentKindHistogram,
		"observable_counter": sdkmetric.InstrumentKindObservableCounter,
		"updown_counter":     sdkmetric.InstrumentKindUpDownCounter,
	}
	wantDelta := map[string]map[string]bool{
		"cumulative": {},
		"delta":      {"counter": true, "histogram": true, "observable_counter": true},
		"lowmemory":  {"counter": true, "histogram": true},
	}
	for preference, deltaKinds := range wantDelta {
		t.Run(preference, func(t *testing.T) {
			sel, err := temporalitySelector(preference)
			if err != nil {
				t.Fatalf("temporalitySelector(%q): %v", preference, err)
			}
			if sel == nil {
				t.Fatalf("temporalitySelector(%q) = nil, want a selector", preference)
			}
			for name, kind := range kinds {
				got := sel(kind)
				want := metricdata.CumulativeTemporality
				if deltaKinds[name] {
					want = metricdata.DeltaTemporality
				}
				if got != want {
					t.Errorf("%s(%s) = %v, want %v", preference, name, got, want)
				}
			}
		})
	}
}

// TestInsecureHeaderFootgun pins the warning predicate: it must fire for
// the plaintext-transport-plus-auth-headers combination however the
// plaintext arrives — the Insecure flag or an explicit http:// scheme on
// the endpoint (the recommended full-URL form must not be the unwarned
// path) — and stay quiet otherwise.
func TestInsecureHeaderFootgun(t *testing.T) {
	auth := map[string]string{"Authorization": "Bearer x"}
	cases := []struct {
		name string
		sig  Signal
		want bool
	}{
		{"insecure with headers", Signal{Insecure: true, Headers: auth}, true},
		{"insecure without headers", Signal{Insecure: true}, false},
		{"insecure with empty headers map", Signal{Insecure: true, Headers: map[string]string{}}, false},
		{"tls with headers", Signal{Headers: auth}, false},
		{"neither", Signal{}, false},
		{"http scheme with headers", Signal{Endpoint: "http://collector.example:4318", Headers: auth}, true},
		{"http scheme without headers", Signal{Endpoint: "http://collector.example:4318"}, false},
		{"https scheme with headers", Signal{Endpoint: "https://collector.example", Headers: auth}, false},
		{"schemeless endpoint with headers", Signal{Endpoint: "collector.example:4317", Headers: auth}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := insecureHeaderFootgun(tc.sig); got != tc.want {
				t.Errorf("insecureHeaderFootgun = %v, want %v", got, tc.want)
			}
		})
	}
}
