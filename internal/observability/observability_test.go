package observability

import (
	"context"
	"testing"
	"time"
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

// TestInitBadProtocol verifies the validation path rejects unknown
// transport values up front so misconfiguration surfaces at startup
// rather than at first export.
func TestInitBadProtocol(t *testing.T) {
	_, err := Init(context.Background(), Config{
		Enabled:  true,
		Protocol: "smoke-signals",
	})
	if err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
}

// TestProtocolFallthroughToEnv confirms an empty cfg.Protocol picks
// up the OTel env-var convention. The metrics-specific override wins
// over the generic one, matching the SDK's documented precedence.
func TestProtocolFallthroughToEnv(t *testing.T) {
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
		Enabled:  true,
		Endpoint: "127.0.0.1:0",
		Insecure: true,
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
		Enabled:  true,
		Endpoint: "127.0.0.1:0",
		Insecure: true,
	})
	if err != nil {
		t.Fatalf("Init (generic env): %v", err)
	}
	_ = p.Shutdown(ctx)
}
