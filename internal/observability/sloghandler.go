package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
)

// loggerName is the OTel instrumentation-scope name used for every log
// record this package emits, whether via the slog bridge or
// LogRegistryConfigManaged directly. Kept as one constant so the two
// emission paths can't drift.
const loggerName = "github.com/goodtune/dotvault"

// NewSlogHandler wraps next so every record it handles is also mirrored
// to the current global OTel LoggerProvider. next keeps full ownership
// of its own level filtering and output (text/JSON to stderr) — this
// wrapper never suppresses, reorders, or alters what next receives, it
// only adds a second sink alongside it.
//
// The OTel side resolves its logger from global.GetLoggerProvider() on
// every call, exactly like LogRegistryConfigManaged, rather than caching
// a handle: that's what lets this be wrapped unconditionally in
// setupLogging (called before config is loaded and before Init runs).
// Before Init, and whenever observability is disabled, the global
// provider is the OTel no-op implementation, whose Logger.Enabled always
// returns false — emit() checks that before doing any attribute
// conversion, so the disabled/no-op path costs one Logger() call plus
// one Enabled() call and never builds a Record or walks attrs. No
// branch on cfg.Observability.Enabled is needed at the call site,
// matching this package's existing no-op-backed convention for metrics
// and Log* helpers.
func NewSlogHandler(next slog.Handler) slog.Handler {
	return &otelSlogHandler{next: next}
}

// scopedAttr pairs an attr added via WithAttrs with the dotted group
// prefix that was active at the time it was added — WithGroup only
// scopes attrs and record fields that come *after* it, so a flat
// []slog.Attr plus a single "current groups" list (as tracked by an
// earlier version of this handler) would incorrectly re-scope
// already-added attrs into a group opened later in the chain.
type scopedAttr struct {
	prefix string // "" or a dot-joined, dot-terminated group path, e.g. "rule."
	attr   slog.Attr
}

type otelSlogHandler struct {
	next        slog.Handler
	scopedAttrs []scopedAttr
	groupPrefix string // "" or dot-terminated, applies to record-level Attrs and to attrs added by a future WithAttrs
}

func (h *otelSlogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *otelSlogHandler) Handle(ctx context.Context, record slog.Record) error {
	err := h.next.Handle(ctx, record)
	h.emit(ctx, record)
	return err
}

func (h *otelSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	merged := make([]scopedAttr, 0, len(h.scopedAttrs)+len(attrs))
	merged = append(merged, h.scopedAttrs...)
	for _, a := range attrs {
		merged = append(merged, scopedAttr{prefix: h.groupPrefix, attr: a})
	}
	return &otelSlogHandler{next: h.next.WithAttrs(attrs), scopedAttrs: merged, groupPrefix: h.groupPrefix}
}

func (h *otelSlogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &otelSlogHandler{next: h.next.WithGroup(name), scopedAttrs: h.scopedAttrs, groupPrefix: h.groupPrefix + name + "."}
}

// emit builds an OTel log record from a handled slog.Record and sends it
// through the current global LoggerProvider. Attribute keys carry any
// active WithGroup nesting as a dotted prefix (e.g. "sync.rule.name")
// since the OTel log data model has no first-class notion of slog's
// handler groups — this mirrors the convention slog's own JSON/text
// handlers use for nested groups in flat output.
//
// Checks logger.Enabled before building the record: the no-op
// implementation's Enabled always returns false, so the disabled/pre-Init
// path exits before paying for the attribute walk and conversion below —
// this is what keeps NewSlogHandler safe to wrap unconditionally without
// threading cfg.Observability.Enabled through setupLogging.
func (h *otelSlogHandler) emit(ctx context.Context, record slog.Record) {
	logger := global.GetLoggerProvider().Logger(loggerName)

	sev, sevText := otelSeverity(record.Level)
	if !logger.Enabled(ctx, otellog.EnabledParameters{Severity: sev}) {
		return
	}

	var rec otellog.Record
	rec.SetTimestamp(record.Time)
	rec.SetBody(otellog.StringValue(record.Message))
	rec.SetSeverity(sev)
	rec.SetSeverityText(sevText)

	for _, sa := range h.scopedAttrs {
		addOTelAttr(&rec, sa.prefix, sa.attr)
	}
	record.Attrs(func(a slog.Attr) bool {
		addOTelAttr(&rec, h.groupPrefix, a)
		return true
	})

	logger.Emit(ctx, rec)
}

// otelSeverity maps an slog.Level onto the base OTel Severity for its
// tier (Debug/Info/Warn/Error) — dotvault only ever logs at those four
// levels, so the *N sub-tiers OTel reserves for finer distinctions are
// unused. SeverityText carries the level's own String() so a custom
// level offset (e.g. slog.LevelWarn+2) is still visible on the exported
// record instead of being collapsed into "WARN".
func otelSeverity(level slog.Level) (otellog.Severity, string) {
	var sev otellog.Severity
	switch {
	case level < slog.LevelInfo:
		sev = otellog.SeverityDebug
	case level < slog.LevelWarn:
		sev = otellog.SeverityInfo
	case level < slog.LevelError:
		sev = otellog.SeverityWarn
	default:
		sev = otellog.SeverityError
	}
	return sev, level.String()
}

// addOTelAttr converts a single slog.Attr into an OTel KeyValue and adds
// it to rec, prefixing the key with the dot-terminated group path that
// was active when the attr was recorded. Empty attrs (slog's convention
// for an elided value, e.g. from a LogValuer that wants to suppress
// itself) are skipped rather than emitted as a bare key.
func addOTelAttr(rec *otellog.Record, prefix string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	rec.AddAttributes(otellog.KeyValue{Key: prefix + a.Key, Value: slogValueToOTel(a.Value)})
}

// slogValueToOTel converts a resolved slog.Value into the equivalent
// OTel log.Value. Kinds with no direct OTel counterpart (Duration, Time)
// are rendered as their canonical string form rather than a numeric
// encoding, matching what slog's own text/JSON handlers print.
func slogValueToOTel(v slog.Value) otellog.Value {
	switch v.Kind() {
	case slog.KindBool:
		return otellog.BoolValue(v.Bool())
	case slog.KindDuration:
		return otellog.StringValue(v.Duration().String())
	case slog.KindFloat64:
		return otellog.Float64Value(v.Float64())
	case slog.KindInt64:
		return otellog.Int64Value(v.Int64())
	case slog.KindString:
		return otellog.StringValue(v.String())
	case slog.KindTime:
		return otellog.StringValue(v.Time().Format(time.RFC3339Nano))
	case slog.KindUint64:
		return otellog.Int64Value(int64(v.Uint64()))
	case slog.KindGroup:
		group := v.Group()
		kvs := make([]otellog.KeyValue, 0, len(group))
		for _, a := range group {
			a.Value = a.Value.Resolve()
			if a.Equal(slog.Attr{}) {
				continue
			}
			kvs = append(kvs, otellog.KeyValue{Key: a.Key, Value: slogValueToOTel(a.Value)})
		}
		return otellog.MapValue(kvs...)
	default:
		return otellog.StringValue(anyToString(v.Any()))
	}
}

// anyToString renders a slog.KindAny value the way slog's own JSONHandler
// would (via error/Stringer, then json.Marshal), rather than fmt.Sprint's
// "%v" reflection. %v walks unexported and json:"-" struct fields that
// JSON marshalling omits — a struct attr relied on to redact a field via
// tags in the JSON-format stderr sink would otherwise be fully dumped
// once it also reaches this OTLP export path. json.Marshal failures
// (channels, funcs, cyclic values) fall back to fmt.Sprint, matching
// what a bare log line would have shown anyway.
func anyToString(v any) string {
	if err, ok := v.(error); ok {
		return err.Error()
	}
	if s, ok := v.(fmt.Stringer); ok {
		return s.String()
	}
	if b, err := json.Marshal(v); err == nil {
		return string(b)
	}
	return fmt.Sprint(v)
}
