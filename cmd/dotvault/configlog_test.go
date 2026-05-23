package main

import (
	"context"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/goodtune/dotvault/internal/config"
)

// recordingProcessor captures every emitted log record. Duplicated
// from internal/observability/testreader_test.go because that
// package's test helper isn't importable from outside, and the
// alternative (lifting it to a public observabilitytest package) is
// more scaffolding than this one assertion warrants.
type recordingProcessor struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (p *recordingProcessor) OnEmit(_ context.Context, r *sdklog.Record) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records = append(p.records, *r)
	return nil
}

func (p *recordingProcessor) Enabled(context.Context, sdklog.EnabledParameters) bool {
	return true
}

func (p *recordingProcessor) Shutdown(context.Context) error   { return nil }
func (p *recordingProcessor) ForceFlush(context.Context) error { return nil }

func (p *recordingProcessor) snapshot() []sdklog.Record {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]sdklog.Record, len(p.records))
	copy(out, p.records)
	return out
}

// installRecordingLogger swaps in a LoggerProvider that records every
// emitted record and registers cleanup to restore the previous
// global. observability.LogRegistryConfigManaged resolves its logger
// from global.GetLoggerProvider() per call, so swapping the global
// is sufficient — no cached handle to rebind. observability.Init is
// the only other thing that touches this global, and it runs once
// at daemon startup — never inside tests — so there is no race with
// parallel test execution as long as no caller invokes
// observability.Init concurrently with these tests.
func installRecordingLogger(t *testing.T) *recordingProcessor {
	t.Helper()
	rec := &recordingProcessor{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(rec))
	prev := global.GetLoggerProvider()
	global.SetLoggerProvider(provider)
	t.Cleanup(func() {
		global.SetLoggerProvider(prev)
		_ = provider.Shutdown(context.Background())
	})
	return rec
}

// TestEmitConfigSourceLog pins down the wiring between the daemon
// entry points (runDaemon, runSync) and
// observability.LogRegistryConfigManaged. The helper is two lines —
// trivially deletable in a refactor — and the regression mode it
// guards against is operator-visible only on GPO-managed Windows
// boxes, where the symptom (the WARN record stops reaching the
// collector) is silent unless someone is actively watching their
// OTLP backend. This test fails loudly in CI instead.
func TestEmitConfigSourceLog(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		wantRecords int
	}{
		{
			name:        "managed-emits",
			cfg:         &config.Config{Managed: true},
			wantRecords: 1,
		},
		{
			name:        "unmanaged-silent",
			cfg:         &config.Config{Managed: false},
			wantRecords: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := installRecordingLogger(t)
			emitConfigSourceLog(context.Background(), tc.cfg)
			if got := len(rec.snapshot()); got != tc.wantRecords {
				t.Fatalf("emitConfigSourceLog: got %d records, want %d", got, tc.wantRecords)
			}
		})
	}
}
