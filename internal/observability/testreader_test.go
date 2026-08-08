package observability

import (
	"context"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// newTestReader installs a test-local MeterProvider backed by a
// ManualReader as the global, rebinds the package-level instruments
// onto it, and registers a Cleanup that restores the previous global.
//
// The returned reader can be Collect()ed against to assert what the
// instruments emitted during the test. Lives in a _test.go file so
// its `testing` import doesn't leak into production builds; if other
// packages' tests ever need this helper, lift it into an
// `observabilitytest` subpackage rather than promoting it back into
// the production tree.
func newTestReader(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)
	rebindInstruments()
	t.Cleanup(func() {
		// Restore the previous provider and rebind instruments back
		// onto it. Without this, the next test would still record
		// against our shut-down provider and Collect would no-op.
		otel.SetMeterProvider(prev)
		rebindInstruments()
		_ = provider.Shutdown(context.Background())
	})
	return reader
}

// recordingLogProcessor is a minimal sdklog.Processor that captures
// every emitted record into an in-memory slice — the log-side
// equivalent of metric's ManualReader. The SDK does not ship a
// ManualReader for logs, and a BatchProcessor + manual ForceFlush
// would complicate the assertion (records leave through an exporter,
// not the processor), so a tiny custom processor is the cleanest
// fixture for asserting what LogRegistryConfigManaged emitted.
type recordingLogProcessor struct {
	mu      sync.Mutex
	records []sdklog.Record
	// enabled backs Enabled below; defaults to true via newTestLogProcessor
	// so existing callers see no behaviour change. A test can flip it to
	// false to simulate a LoggerProvider that reports itself disabled
	// (mirroring the real no-op provider's Logger.Enabled, which always
	// returns false) and assert emit-side code short-circuits before
	// OnEmit is ever called.
	enabled bool
}

func (p *recordingLogProcessor) OnEmit(_ context.Context, r *sdklog.Record) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records = append(p.records, *r)
	return nil
}

func (p *recordingLogProcessor) Enabled(context.Context, sdklog.EnabledParameters) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.enabled
}

func (p *recordingLogProcessor) Shutdown(context.Context) error   { return nil }
func (p *recordingLogProcessor) ForceFlush(context.Context) error { return nil }

func (p *recordingLogProcessor) Snapshot() []sdklog.Record {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]sdklog.Record, len(p.records))
	copy(out, p.records)
	return out
}

// newTestLogProcessor installs a recording LoggerProvider as the
// global and registers a Cleanup that restores the previous global.
// Mirrors newTestReader for the log signal. No rebind is needed —
// Log* helpers resolve the logger per call from
// global.GetLoggerProvider().
func newTestLogProcessor(t *testing.T) *recordingLogProcessor {
	t.Helper()
	rec := &recordingLogProcessor{enabled: true}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(rec))
	prev := global.GetLoggerProvider()
	global.SetLoggerProvider(provider)
	t.Cleanup(func() {
		global.SetLoggerProvider(prev)
		_ = provider.Shutdown(context.Background())
	})
	return rec
}

// bodyString returns the record's body as a Go string, asserting the
// stored Value is a string kind. Test-only helper.
func bodyString(t *testing.T, v log.Value) string {
	t.Helper()
	if v.Kind() != log.KindString {
		t.Fatalf("body kind = %v, want String", v.Kind())
	}
	return v.AsString()
}
