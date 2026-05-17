package observability

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// newTestReader installs a test-local MeterProvider backed by a
// ManualReader as the global, rebinds the package-level instruments
// onto it, and registers a Cleanup that restores the previous global.
//
// The returned reader can be Collect()ed against to assert what the
// instruments emitted during the test. Lives in a non-test file so
// the web package's tests can import it through a sibling helper if
// needed in the future — keeping it inside the observability package
// preserves the package-level instrument-rebind contract.
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
		_ = provider.Shutdown(testContext())
	})
	return reader
}

// testContext returns a background context, broken out so test
// helpers don't need to import the context package inline.
func testContext() context.Context { return context.Background() }
