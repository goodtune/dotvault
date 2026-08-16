package observability

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/paths"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// collectResourceAttrs builds the daemon's resource, attaches it to a
// ManualReader-backed provider, records through a real instrument, and
// returns the attribute set that arrived on the collected export. This
// asserts what a collector would actually receive, not merely what
// buildResource returned.
func collectResourceAttrs(t *testing.T) attribute.Set {
	t.Helper()
	res, err := buildResource(context.Background(), Config{ServiceVersion: "1.2.3"})
	if err != nil {
		t.Fatalf("buildResource: %v", err)
	}
	reader := newTestReaderWithResource(t, res)

	// A record is needed or the export carries no scope metrics; the
	// resource rides the ResourceMetrics envelope regardless, but
	// collecting an empty export would not prove the wiring.
	RecordSyncTick(context.Background(), "ok")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(rm.ScopeMetrics) == 0 {
		t.Fatal("collected export carried no scope metrics")
	}
	if rm.Resource == nil {
		t.Fatal("collected export carried no resource")
	}
	return *rm.Resource.Set()
}

func attrValue(t *testing.T, set attribute.Set, key string) (string, bool) {
	t.Helper()
	v, ok := set.Value(attribute.Key(key))
	if !ok {
		return "", false
	}
	return v.AsString(), true
}

// fakeHostname pins os.Hostname's seam so the host running the tests
// cannot decide whether the qualifying path is exercised.
func fakeHostname(t *testing.T, name string) {
	t.Helper()
	prev := osHostname
	osHostname = func() (string, error) { return name, nil }
	t.Cleanup(func() { osHostname = prev })
}

func fakeCNAME(t *testing.T, fn func(context.Context, string) (string, error)) {
	t.Helper()
	prev := lookupCNAME
	lookupCNAME = fn
	t.Cleanup(func() { lookupCNAME = prev })
}

func TestResourceCarriesUserName(t *testing.T) {
	want, err := paths.Username()
	if err != nil {
		t.Skipf("paths.Username unavailable on this host: %v", err)
	}
	fakeHostname(t, "box")
	fakeCNAME(t, func(_ context.Context, host string) (string, error) { return host + ".example.com.", nil })

	got, ok := attrValue(t, collectResourceAttrs(t), "user.name")
	if !ok {
		t.Fatal("user.name absent from the exported resource")
	}
	if got != want {
		t.Errorf("user.name = %q, want %q (paths.Username)", got, want)
	}
}

func TestResourceUserNameOmittedWhenLookupFails(t *testing.T) {
	prev := currentUsername
	currentUsername = func() (string, error) { return "", errors.New("no such user") }
	t.Cleanup(func() { currentUsername = prev })
	fakeHostname(t, "box")
	fakeCNAME(t, func(_ context.Context, host string) (string, error) { return host + ".example.com.", nil })

	set := collectResourceAttrs(t)
	if v, ok := attrValue(t, set, "user.name"); ok {
		t.Errorf("user.name present as %q despite a failed lookup; want it omitted", v)
	}
	// The build must not have been derailed: the rest of the resource
	// is intact, which is what "does not fail Init" means here.
	if v, ok := attrValue(t, set, "service.name"); !ok || v != "dotvault" {
		t.Errorf("service.name = %q (present=%v), want \"dotvault\"", v, ok)
	}
	if v, ok := attrValue(t, set, "host.name"); !ok || v == "" {
		t.Errorf("host.name = %q (present=%v), want a non-empty value", v, ok)
	}
}

func TestResourceHostNameQualified(t *testing.T) {
	fakeHostname(t, "box")
	var asked string
	fakeCNAME(t, func(_ context.Context, host string) (string, error) {
		asked = host
		return "box.corp.example.com.", nil
	})

	got, ok := attrValue(t, collectResourceAttrs(t), "host.name")
	if !ok {
		t.Fatal("host.name absent from the exported resource")
	}
	if asked != "box" {
		t.Errorf("lookupCNAME asked for %q, want the short hostname %q", asked, "box")
	}
	// The trailing root dot must be trimmed and the qualified name used.
	if want := "box.corp.example.com"; got != want {
		t.Errorf("host.name = %q, want %q", got, want)
	}
}

func TestResourceHostNameFallsBackAndStillExports(t *testing.T) {
	fakeHostname(t, "box")
	fakeCNAME(t, func(context.Context, string) (string, error) { return "", errors.New("SERVFAIL") })

	got, ok := attrValue(t, collectResourceAttrs(t), "host.name")
	if !ok {
		t.Fatal("host.name absent from the exported resource")
	}
	if got != "box" {
		t.Errorf("host.name = %q, want the os.Hostname fallback %q", got, "box")
	}
}

func TestResolveHostNameFallbacks(t *testing.T) {
	tests := []struct {
		name   string
		lookup func(context.Context, string) (string, error)
	}{
		{
			name:   "resolver error",
			lookup: func(context.Context, string) (string, error) { return "", errors.New("SERVFAIL") },
		},
		{
			// The error must be honoured even when a name came back
			// with it: a partial answer accompanying a failure is not
			// an identity we should publish. Without the err check the
			// qualification guard alone would happily accept this.
			name: "resolver error alongside a qualified answer",
			lookup: func(context.Context, string) (string, error) {
				return "stale.example.com.", errors.New("SERVFAIL")
			},
		},
		{
			name: "timeout",
			lookup: func(ctx context.Context, _ string) (string, error) {
				// Outlive the bounded lookup: block until the derived
				// context's deadline fires, then report it as the
				// resolver would. If resolveHostName did not bound the
				// call this would hang the test rather than fall back.
				<-ctx.Done()
				return "", ctx.Err()
			},
		},
		{
			name:   "unqualified answer",
			lookup: func(_ context.Context, host string) (string, error) { return host + ".", nil },
		},
		{
			name:   "localhost alias from /etc/hosts",
			lookup: func(context.Context, string) (string, error) { return "localhost.localdomain.", nil },
		},
		{
			name:   "empty answer",
			lookup: func(context.Context, string) (string, error) { return "", nil },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeHostname(t, "box")
			fakeCNAME(t, tc.lookup)

			start := time.Now()
			got := resolveHostName(context.Background())
			if got != "box" {
				t.Errorf("resolveHostName = %q, want the os.Hostname fallback %q", got, "box")
			}
			if elapsed := time.Since(start); elapsed > hostNameLookupTimeout+2*time.Second {
				t.Errorf("resolveHostName took %s, want it bounded near %s", elapsed, hostNameLookupTimeout)
			}
		})
	}
}

func TestResolveHostNameSkipsLookupWhenAlreadyQualified(t *testing.T) {
	fakeHostname(t, "box.corp.example.com")
	fakeCNAME(t, func(context.Context, string) (string, error) {
		t.Error("lookupCNAME called even though os.Hostname was already qualified")
		return "", errors.New("must not be called")
	})

	if got := resolveHostName(context.Background()); got != "box.corp.example.com" {
		t.Errorf("resolveHostName = %q, want %q unchanged", got, "box.corp.example.com")
	}
}
