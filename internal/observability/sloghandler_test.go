package observability

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	otelnoop "go.opentelemetry.io/otel/log/noop"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// findAttr returns the value for key in rec's attributes, failing the
// test if the key is absent.
func findAttr(t *testing.T, rec sdklog.Record, key string) otellog.Value {
	t.Helper()
	var found *otellog.Value
	rec.WalkAttributes(func(kv otellog.KeyValue) bool {
		if kv.Key == key {
			v := kv.Value
			found = &v
			return false
		}
		return true
	})
	if found == nil {
		t.Fatalf("attribute %q not found on record", key)
	}
	return *found
}

// TestSlogHandlerMirrorsToStderrAndOTel confirms a single log call
// reaches both the wrapped stderr handler and the OTel LoggerProvider —
// the whole point of the bridge is that neither sink loses records
// relative to the other.
func TestSlogHandlerMirrorsToStderrAndOTel(t *testing.T) {
	rec := newTestLogProcessor(t)

	var buf bytes.Buffer
	next := slog.NewTextHandler(&buf, nil)
	logger := slog.New(NewSlogHandler(next))

	logger.Info("hello world", "key", "value")

	if !bytes.Contains(buf.Bytes(), []byte("hello world")) {
		t.Errorf("stderr sink missing message, got %q", buf.String())
	}

	records := rec.Snapshot()
	if len(records) != 1 {
		t.Fatalf("got %d OTel records, want 1", len(records))
	}
	if got := bodyString(t, records[0].Body()); got != "hello world" {
		t.Errorf("OTel record body = %q, want %q", got, "hello world")
	}
	if got := findAttr(t, records[0], "key"); got.AsString() != "value" {
		t.Errorf("OTel record attr key = %q, want %q", got.AsString(), "value")
	}
}

// TestSlogHandlerNoOpWithoutInit confirms logging through the bridge
// against the genuine OTel no-op LoggerProvider (what's installed before
// any Init call) does not panic and does not block stderr output — the
// same "safe to call unconditionally" contract every other Log* helper
// in this package relies on. The provider is installed explicitly rather
// than relying on incidental global state left over from test order,
// since other tests in this package install and restore their own
// providers.
func TestSlogHandlerNoOpWithoutInit(t *testing.T) {
	prev := global.GetLoggerProvider()
	global.SetLoggerProvider(otelnoop.NewLoggerProvider())
	t.Cleanup(func() { global.SetLoggerProvider(prev) })

	var buf bytes.Buffer
	next := slog.NewTextHandler(&buf, nil)
	logger := slog.New(NewSlogHandler(next))

	logger.Warn("no provider installed")

	if !bytes.Contains(buf.Bytes(), []byte("no provider installed")) {
		t.Errorf("stderr sink missing message, got %q", buf.String())
	}
}

// TestSlogHandlerSeverityMapping asserts the four slog levels dotvault
// actually uses map onto the expected OTel severity tier.
func TestSlogHandlerSeverityMapping(t *testing.T) {
	rec := newTestLogProcessor(t)
	logger := slog.New(NewSlogHandler(slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelDebug})))

	logger.Debug("d")
	logger.Info("i")
	logger.Warn("w")
	logger.Error("e")

	records := rec.Snapshot()
	if len(records) != 4 {
		t.Fatalf("got %d records, want 4", len(records))
	}
	want := []otellog.Severity{
		otellog.SeverityDebug,
		otellog.SeverityInfo,
		otellog.SeverityWarn,
		otellog.SeverityError,
	}
	for i, r := range records {
		if r.Severity() != want[i] {
			t.Errorf("record %d severity = %v, want %v", i, r.Severity(), want[i])
		}
	}
}

// TestSlogHandlerWithAttrsAndGroup confirms handler-level attrs (added
// via With/WithGroup, as slog.Default().With(...) does) reach the OTel
// record with the group nesting flattened into a dotted key prefix.
func TestSlogHandlerWithAttrsAndGroup(t *testing.T) {
	rec := newTestLogProcessor(t)

	base := slog.New(NewSlogHandler(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	logger := base.With("component", "sync").WithGroup("rule").With("name", "gh-token")

	logger.Info("synced")

	records := rec.Snapshot()
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if got := findAttr(t, records[0], "component"); got.AsString() != "sync" {
		t.Errorf("component attr = %q, want %q", got.AsString(), "sync")
	}
	if got := findAttr(t, records[0], "rule.name"); got.AsString() != "gh-token" {
		t.Errorf("rule.name attr = %q, want %q", got.AsString(), "gh-token")
	}
}

// TestSlogHandlerEnabledDelegatesToNext confirms level filtering stays
// owned by the wrapped handler — the bridge must not independently gate
// or widen what's considered enabled.
func TestSlogHandlerEnabledDelegatesToNext(t *testing.T) {
	next := slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn})
	h := NewSlogHandler(next)

	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Enabled(Info) = true, want false when next is configured for Warn")
	}
	if !h.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("Enabled(Warn) = false, want true")
	}
}

// TestSlogHandlerSkipsDisabledLogger confirms emit() exits via
// logger.Enabled before building a Record when the LoggerProvider reports
// itself disabled for the record's severity — this is what keeps the
// bridge cheap under the default no-op LoggerProvider (Enabled always
// false) without a cfg.Observability.Enabled branch at the wrap site. A
// processor configured to reject everything stands in for the no-op
// provider's Enabled()==false behaviour while still letting the test
// assert the processor was never reached.
func TestSlogHandlerSkipsDisabledLogger(t *testing.T) {
	rec := newTestLogProcessor(t)
	rec.enabled = false

	logger := slog.New(NewSlogHandler(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	logger.Info("should not reach the processor")

	if got := rec.Snapshot(); len(got) != 0 {
		t.Fatalf("got %d records, want 0 (Enabled()==false should have short-circuited)", len(got))
	}
}

// stringerOnly implements fmt.Stringer but not json.Marshaler, so
// slogValueToOTel's KindAny fallback must prefer String() over
// json.Marshal (matching slog's own precedence).
type stringerOnly struct{ redacted string }

func (s stringerOnly) String() string { return "stringer-output" }

// jsonRedacted has an unexported field and a json:"-" field — a struct
// attr relying on either to keep a value out of the JSON-format stderr
// sink. json.Marshal omits both; fmt.Sprint ("%v" reflection) would not.
type jsonRedacted struct {
	Public   string `json:"public"`
	Secret   string `json:"-"`
	internal string //nolint:unused // exercises %v's unexported-field leak
}

// TestSlogValueToOTelAnyFallback confirms the KindAny fallback matches
// JSON-marshal semantics (error/Stringer first, then json.Marshal)
// instead of fmt.Sprint's "%v", which would otherwise dump unexported
// and json:"-" struct fields that the JSON stderr sink never shows.
func TestSlogValueToOTelAnyFallback(t *testing.T) {
	if got := slogValueToOTel(slog.AnyValue(errTestSentinel)).AsString(); got != "sentinel error" {
		t.Errorf("error fallback = %q, want %q", got, "sentinel error")
	}
	if got := slogValueToOTel(slog.AnyValue(stringerOnly{redacted: "x"})).AsString(); got != "stringer-output" {
		t.Errorf("Stringer fallback = %q, want %q", got, "stringer-output")
	}

	got := slogValueToOTel(slog.AnyValue(jsonRedacted{Public: "p", Secret: "s", internal: "i"})).AsString()
	if !bytes.Contains([]byte(got), []byte(`"public":"p"`)) {
		t.Errorf("json fallback = %q, want it to contain the public field", got)
	}
	if bytes.Contains([]byte(got), []byte("s")) && bytes.Contains([]byte(got), []byte(`"Secret"`)) {
		t.Errorf("json fallback = %q, leaked the json:\"-\" field", got)
	}
	if bytes.Contains([]byte(got), []byte("internal")) {
		t.Errorf("json fallback = %q, leaked the unexported field", got)
	}
}

type sentinelError struct{ msg string }

func (e sentinelError) Error() string { return e.msg }

var errTestSentinel = sentinelError{msg: "sentinel error"}

// TestSlogHandlerRecordLevelGroup confirms a slog.Group passed as a
// record attribute (as opposed to a handler-level WithGroup) converts to
// an OTel MapValue with its nested keys intact — the KindGroup branch of
// slogValueToOTel, which no other test exercised.
func TestSlogHandlerRecordLevelGroup(t *testing.T) {
	rec := newTestLogProcessor(t)
	logger := slog.New(NewSlogHandler(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	logger.Info("synced", slog.Group("rule", slog.String("name", "gh-token"), slog.Int("version", 3)))

	records := rec.Snapshot()
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	got := findAttr(t, records[0], "rule")
	if got.Kind() != otellog.KindMap {
		t.Fatalf("rule attr kind = %v, want KindMap", got.Kind())
	}
	kvs := got.AsMap()
	want := map[string]otellog.Value{
		"name":    otellog.StringValue("gh-token"),
		"version": otellog.Int64Value(3),
	}
	if len(kvs) != len(want) {
		t.Fatalf("got %d nested keys, want %d", len(kvs), len(want))
	}
	for _, kv := range kvs {
		wv, ok := want[kv.Key]
		if !ok {
			t.Errorf("unexpected nested key %q", kv.Key)
			continue
		}
		if !kv.Value.Equal(wv) {
			t.Errorf("nested key %q = %v, want %v", kv.Key, kv.Value, wv)
		}
	}
}
