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
