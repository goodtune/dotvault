package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
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
	RecordSSHConnState(ctx, "example.com", true)
	RecordSSHReconnect(ctx, "example.com")
	RecordSSHConnectFailure(ctx, "example.com", "dns")
	RecordSSHKeepaliveFailure(ctx, "example.com")
	RecordSSHForwardConn(ctx, "example.com", 1)
	RecordSSHForwardFailure(ctx, "example.com")
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

// TestSSHInstrumentsReachActiveMeterProvider is the SSH-forward sibling of
// TestRecordReachesActiveMeterProvider: it pins that rebindInstruments wires
// every new instrument to the active provider, and that each one is the
// instrument kind its doc promises — dotvault.ssh.connections and
// dotvault.ssh.forward_connections_active must behave like gauges (an
// absolute/net-current value), not accumulate like the *_total counters.
func TestSSHInstrumentsReachActiveMeterProvider(t *testing.T) {
	reader := newTestReader(t)
	ctx := context.Background()

	RecordSSHConnState(ctx, "a.example.com", true)
	RecordSSHReconnect(ctx, "a.example.com")
	RecordSSHConnectFailure(ctx, "a.example.com", "dns")
	RecordSSHKeepaliveFailure(ctx, "a.example.com")
	RecordSSHForwardConn(ctx, "a.example.com", 1)
	RecordSSHForwardConn(ctx, "a.example.com", 1)
	RecordSSHForwardConn(ctx, "a.example.com", -1)
	RecordSSHForwardFailure(ctx, "a.example.com")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("reader.Collect: %v", err)
	}

	var (
		gotConnGauge          bool
		gotForwardActive      int64
		forwardFailureHasHost bool
		counters              = map[string]int64{}
	)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch data := m.Data.(type) {
			case metricdata.Gauge[int64]:
				if m.Name == "dotvault.ssh.connections" {
					for _, dp := range data.DataPoints {
						if dp.Value == 1 {
							gotConnGauge = true
						}
					}
				}
			case metricdata.Sum[int64]:
				var total int64
				for _, dp := range data.DataPoints {
					total += dp.Value
					if m.Name == "dotvault.ssh.forward_failure_total" {
						if v, ok := dp.Attributes.Value(attribute.Key("host")); ok && v.AsString() == "a.example.com" {
							forwardFailureHasHost = true
						}
					}
				}
				if m.Name == "dotvault.ssh.forward_connections_active" {
					gotForwardActive = total
				} else {
					counters[m.Name] = total
				}
			}
		}
	}

	// forward_failure_total must carry the host label like every other SSH
	// instrument — an operator managing several forwards needs to tell them
	// apart on this counter, not just in an adjacent log line.
	if !forwardFailureHasHost {
		t.Error(`dotvault.ssh.forward_failure_total datapoint lacks the host="a.example.com" attribute`)
	}

	if !gotConnGauge {
		t.Error("dotvault.ssh.connections did not report a datapoint of 1 — rebindInstruments did not wire the gauge to the active provider")
	}
	// Two accepted (+1, +1) and one closed (-1) nets to 1 active — an
	// up-down counter, not a monotonic counter, so this would be 3 if the
	// instrument kind regressed to a plain Int64Counter.
	if gotForwardActive != 1 {
		t.Errorf("dotvault.ssh.forward_connections_active = %d, want 1 (net of two accepts and one close)", gotForwardActive)
	}
	for _, name := range []string{
		"dotvault.ssh.reconnect_total",
		"dotvault.ssh.connect_failure_total",
		"dotvault.ssh.keepalive_failure_total",
		"dotvault.ssh.forward_connections_total",
		"dotvault.ssh.forward_failure_total",
	} {
		if counters[name] < 1 {
			t.Errorf("counter %q = %d, want ≥1 — rebindInstruments did not wire it to the active provider", name, counters[name])
		}
	}
	// forward_connections_total must count only the two accepts, never the
	// close (delta < 0) — a close is not a new connection.
	if got := counters["dotvault.ssh.forward_connections_total"]; got != 2 {
		t.Errorf("dotvault.ssh.forward_connections_total = %d, want 2 (only the two accepted deltas)", got)
	}
}

// TestSSHConnectFailureClassAttributeBounded pins the cardinality guarantee
// that makes dotvault.ssh.connect_failure_total safe to export: the `class`
// attribute is exactly the string handed to RecordSSHConnectFailure, with no
// hidden transformation that could leak free-form text through — the bound
// itself is enforced by the caller (internal/sshfwd's fail(), which must
// pass sshfwd.Classify(err)'s fixed result, never err.Error()) and is
// exercised there; this test pins the attribute plumbing that guarantee
// relies on.
func TestSSHConnectFailureClassAttributeBounded(t *testing.T) {
	reader := newTestReader(t)
	ctx := context.Background()

	// The fixed vocabulary sshfwd.ErrorClass defines (state.go), duplicated
	// here as plain strings rather than importing internal/sshfwd — this
	// package sits below sshfwd in the dependency graph (sshfwd imports
	// observability to call these helpers) and must not import back up.
	classes := []string{
		"dns", "network-unreachable", "connection-refused", "handshake",
		"authentication", "host-key", "remote-socket-bind", "home-probe",
		"config", "other",
	}
	for _, c := range classes {
		RecordSSHConnectFailure(ctx, "b.example.com", c)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("reader.Collect: %v", err)
	}

	seen := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "dotvault.ssh.connect_failure_total" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("dotvault.ssh.connect_failure_total: unexpected data type %T", m.Data)
			}
			for _, dp := range sum.DataPoints {
				v, ok := dp.Attributes.Value(attribute.Key("class"))
				if !ok {
					t.Fatal("connect-failure datapoint missing class attribute")
				}
				seen[v.AsString()] = true
			}
		}
	}

	for _, c := range classes {
		if !seen[c] {
			t.Errorf("class %q not recorded on dotvault.ssh.connect_failure_total", c)
		}
	}
	if len(seen) != len(classes) {
		t.Errorf("saw %d distinct class attribute values, want exactly %d — an unbounded or malformed label would show up as extra or missing values here", len(seen), len(classes))
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
	r.WalkAttributes(func(kv attribute.KeyValue) bool {
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

	// Pin the host.name seams so this test never makes a real resolver
	// call — buildResource qualifies the hostname during Init, and an
	// unbounded-looking DNS round trip has no business in a unit test.
	fakeHostname(t, "box")
	fakeCNAME(t, func(_ context.Context, host string) (string, error) { return host + ".example.com.", nil })

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
		// Schemes are case-insensitive (url.Parse canonicalises them), so
		// the routing predicate must fold case or the uppercase form would
		// skip WithEndpointURL — and the plaintext warnings — while still
		// meaning plaintext to any parser that did accept it.
		"HTTP://127.0.0.1:4317":         true,
		"HTTPS://collector.example":     true,
		"127.0.0.1:4317":                false,
		"collector.example:4317":        false,
		"grpc://collector.example:4317": false,
		"dns:///collector.example:4317": false,
		"":                              false,
	}
	for endpoint, want := range urlForm {
		if got := hasHTTPScheme(endpoint); got != want {
			t.Errorf("hasHTTPScheme(%q) = %v, want %v", endpoint, got, want)
		}
	}

	stripped := map[string]string{
		"grpc://collector.example:4317": "collector.example:4317",
		"GRPC://collector.example:4317": "collector.example:4317",
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
		{"uppercase http scheme with headers", Signal{Endpoint: "HTTP://collector.example:4318", Headers: auth}, true},
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

func TestEnsureSignalPath(t *testing.T) {
	cases := []struct {
		endpoint string
		want     string
	}{
		// Path-less URLs get the signal path appended — the documented
		// contract, upheld here since OTel v1.45 stopped defaulting it.
		{"http://127.0.0.1:4318", "http://127.0.0.1:4318/v1/metrics"},
		{"https://collector.example", "https://collector.example/v1/metrics"},
		// A bare trailing slash is spelling, not intent.
		{"http://127.0.0.1:4318/", "http://127.0.0.1:4318/v1/metrics"},
		// Explicit paths are used verbatim — no assumed mount path.
		{"https://collector.example/tenant/v1/metrics", "https://collector.example/tenant/v1/metrics"},
		{"https://collector.example/custom", "https://collector.example/custom"},
		// Query strings survive.
		{"http://127.0.0.1:4318?x=1", "http://127.0.0.1:4318/v1/metrics?x=1"},
	}
	for _, tc := range cases {
		if got := ensureSignalPath(tc.endpoint, "/v1/metrics"); got != tc.want {
			t.Errorf("ensureSignalPath(%q) = %q, want %q", tc.endpoint, got, tc.want)
		}
	}
}

// TestHTTPExporterTargetsDefaultSignalPath is the end-to-end pin for the
// path-less-endpoint contract: an http/protobuf exporter built from a URL
// with no path must POST to the OTLP-standard signal path, not the root.
// This regressed when OTel v1.45.0 changed WithEndpointURL to pin a
// path-less URL's request path to "/"; ensureSignalPath now supplies the
// default on our side of the seam.
func TestHTTPExporterTargetsDefaultSignalPath(t *testing.T) {
	paths := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
	}))
	defer srv.Close()

	ctx := context.Background()

	me, err := buildMetricExporter(ctx, Signal{Enabled: true, Endpoint: srv.URL, Protocol: "http/protobuf"})
	if err != nil {
		t.Fatalf("buildMetricExporter: %v", err)
	}
	t.Cleanup(func() { _ = me.Shutdown(context.Background()) })
	if err := me.Export(ctx, &metricdata.ResourceMetrics{}); err != nil {
		t.Fatalf("metric export: %v", err)
	}
	select {
	case p := <-paths:
		if p != "/v1/metrics" {
			t.Errorf("metric export path = %q, want /v1/metrics", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no metric export request arrived")
	}

	le, err := buildLogExporter(ctx, Signal{Enabled: true, Endpoint: srv.URL, Protocol: "http/protobuf"})
	if err != nil {
		t.Fatalf("buildLogExporter: %v", err)
	}
	t.Cleanup(func() { _ = le.Shutdown(context.Background()) })
	if err := le.Export(ctx, make([]sdklog.Record, 1)); err != nil {
		t.Fatalf("log export: %v", err)
	}
	select {
	case p := <-paths:
		if p != "/v1/logs" {
			t.Errorf("log export path = %q, want /v1/logs", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no log export request arrived")
	}

	// An explicit path must be used verbatim — the append is only for
	// path-less URLs.
	me2, err := buildMetricExporter(ctx, Signal{Enabled: true, Endpoint: srv.URL + "/tenant/v1/metrics", Protocol: "http/protobuf"})
	if err != nil {
		t.Fatalf("buildMetricExporter: %v", err)
	}
	t.Cleanup(func() { _ = me2.Shutdown(context.Background()) })
	if err := me2.Export(ctx, &metricdata.ResourceMetrics{}); err != nil {
		t.Fatalf("metric export: %v", err)
	}
	select {
	case p := <-paths:
		if p != "/tenant/v1/metrics" {
			t.Errorf("explicit-path export path = %q, want /tenant/v1/metrics", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no explicit-path export request arrived")
	}
}
