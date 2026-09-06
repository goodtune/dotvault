package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// relayingSource is a fakeSource that also implements upstreamReporter, so
// Status treats it as a source that reports upstreams.
type relayingSource struct {
	fakeSource
	eps []string
}

func (r *relayingSource) Endpoints() []string { return r.eps }

// upstreamsField returns the raw JSON of the source's "upstreams" key and
// whether the key was present at all. Asserting on the decoded object rather
// than a substring of the whole document keeps the check exact: the point of
// these tests is the wire shape, but "upstreams" as a bare token can appear in
// an error string or a key comment, which a substring search would mistake for
// the field.
func upstreamsField(t *testing.T, ss SourceStatus) (json.RawMessage, bool) {
	t.Helper()
	raw, err := json.Marshal(ss)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	v, ok := obj["upstreams"]
	return v, ok
}

// TestStatusUpstreamsHasThreeStates pins the JSON shape of SourceStatus.Upstreams.
//
// The field is documented as the machine-readable answer to "what did
// auto-detection find?", and that question has three answers, not two. A plain
// []string with omitempty cannot carry them: encoding/json drops a non-nil
// empty slice exactly as it drops a nil one, so a relay that found nothing
// serialised identically to a source that reports no upstreams at all — the
// very distinction the field exists to report.
func TestStatusUpstreamsHasThreeStates(t *testing.T) {
	tests := []struct {
		name        string
		src         Source
		wantPresent bool
		want        string
	}{
		{
			name:        "source reporting no upstreams omits the field entirely",
			src:         &fakeSource{name: "kv", typ: "kv"},
			wantPresent: false,
		},
		{
			name:        "relay that found nothing reports an empty list",
			src:         &relayingSource{fakeSource: fakeSource{name: "relay", typ: "agent"}},
			wantPresent: true,
			want:        `[]`,
		},
		{
			name: "relay reports the endpoints it is shadowing",
			src: &relayingSource{
				fakeSource: fakeSource{name: "relay", typ: "agent"},
				eps:        []string{"/run/user/1000/ssh-agent.socket"},
			},
			wantPresent: true,
			want:        `["/run/user/1000/ssh-agent.socket"]`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := NewBackend([]Source{tc.src}).Status(context.Background())
			if len(st.Sources) != 1 {
				t.Fatalf("Sources = %d, want 1", len(st.Sources))
			}
			got, present := upstreamsField(t, st.Sources[0])
			if present != tc.wantPresent {
				t.Fatalf("upstreams present = %v, want %v (raw %s)", present, tc.wantPresent, got)
			}
			if tc.wantPresent && string(got) != tc.want {
				t.Errorf("upstreams = %s, want %s", got, tc.want)
			}
		})
	}
}

// scanningRelaySource models what the real relay does: it does not know its
// endpoints until a scan has run, and the scan happens inside Identities.
type scanningRelaySource struct {
	fakeSource
	found   []string
	scanned bool
}

func (r *scanningRelaySource) Identities(ctx context.Context) ([]Identity, error) {
	r.scanned = true
	return r.fakeSource.Identities(ctx)
}

func (r *scanningRelaySource) Endpoints() []string {
	if !r.scanned {
		return nil
	}
	return r.found
}

// TestStatusReadsUpstreamsAfterIdentities pins the ordering Backend.Status
// documents: Endpoints is consulted *after* Identities, so an auto-detecting
// relay reports the endpoints from the scan just performed rather than the
// previous one. Hoisting the upstreamReporter block above the Identities call
// makes this fail — the earlier table cannot catch it, because its fake knows
// its endpoints before anything asks.
//
// It doubles as the only case where a source reports an error and upstreams
// together: a relay whose scan found agents can still fail to list from them,
// and both facts belong in the snapshot.
func TestStatusReadsUpstreamsAfterIdentities(t *testing.T) {
	src := &scanningRelaySource{
		fakeSource: fakeSource{name: "relay", typ: "agent", idErr: errors.New("dial refused")},
		found:      []string{"/run/user/1000/ssh-agent.socket"},
	}

	st := NewBackend([]Source{src}).Status(context.Background())
	if len(st.Sources) != 1 {
		t.Fatalf("Sources = %d, want 1", len(st.Sources))
	}
	ss := st.Sources[0]

	got, present := upstreamsField(t, ss)
	if !present {
		t.Fatal("upstreams absent; Endpoints was read before Identities had scanned")
	}
	if want := `["/run/user/1000/ssh-agent.socket"]`; string(got) != want {
		t.Errorf("upstreams = %s, want %s", got, want)
	}
	if ss.Error != "dial refused" {
		t.Errorf("Error = %q, want %q — a failing listing must not suppress the endpoints found", ss.Error, "dial refused")
	}
}
