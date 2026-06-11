package configsvc

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/configsvc/store"
)

func newTestStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), "sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func putLayer(t *testing.T, st store.Store, key, doc string) {
	t.Helper()
	if err := st.PutLayer(context.Background(), key, []byte(doc)); err != nil {
		t.Fatalf("put layer %q: %v", key, err)
	}
}

func composePartial(t *testing.T, st store.Store, keys []string) (*config.Partial, string) {
	t.Helper()
	c := &Composer{Store: st}
	doc, etag, err := c.Compose(context.Background(), keys)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	p, err := config.ParsePartial(doc)
	if err != nil {
		t.Fatalf("served document does not round-trip through ParsePartial: %v\n%s", err, doc)
	}
	return p, etag
}

func TestValidIdentitySegment(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"alice", true},
		{"Alice Smith", true}, // Windows account names may contain spaces
		{"linux", true},
		{"dev.team-1_x", true},
		{"", false},
		{"../global", false},
		{"a/b", false},
		{`DOMAIN\alice`, false},
		{"..", false},
		{"a..b", false}, // conservatively rejected
		{"a\nb", false},
		{"a\x00b", false},
		{"a\x7fb", false},
	}
	for _, tt := range tests {
		if got := ValidIdentitySegment(tt.in); got != tt.want {
			t.Errorf("ValidIdentitySegment(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestValidLayerKey(t *testing.T) {
	tests := []struct {
		key string
		ok  bool
	}{
		{"global", true},
		{"os/linux", true},
		{"group/sydney", true},
		{"user/Alice Smith", true},
		{"os/Linux", false}, // would never be served: composition lowercases
		{"global/extra", false},
		{"nonsense", false},
		{"team/sydney", false},
		{"user/..", false},
		{"user/", false},
		{"", false},
		{"os/a/b", false},
	}
	for _, tt := range tests {
		err := ValidLayerKey(tt.key)
		if (err == nil) != tt.ok {
			t.Errorf("ValidLayerKey(%q) = %v, want ok=%v", tt.key, err, tt.ok)
		}
	}
}

func TestLayerKeys(t *testing.T) {
	got := LayerKeys("Linux", "alice", []string{"sydney", "auckland", "newyork"})
	want := []string{"global", "os/linux", "group/auckland", "group/newyork", "group/sydney", "user/alice"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LayerKeys = %v, want %v", got, want)
	}
}

func TestComposePrecedence(t *testing.T) {
	st := newTestStore(t)
	putLayer(t, st, "global", `
rules:
  - name: shared
    vault_key: global-key
    target: {path: ~/global.txt, format: text}
  - name: global-only
    vault_key: g
    target: {path: ~/g.txt, format: text}
sync:
  interval: 15m
`)
	putLayer(t, st, "os/linux", `
rules:
  - name: shared
    vault_key: os-key
    target: {path: ~/os.txt, format: text}
`)
	putLayer(t, st, "user/alice", `
rules:
  - name: shared
    vault_key: user-key
    target: {path: ~/user.txt, format: text}
sync:
  interval: 5m
`)

	p, _ := composePartial(t, st, LayerKeys("linux", "alice", nil))

	// Later layers replace same-named rules wholesale, keeping position.
	if len(p.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(p.Rules))
	}
	if p.Rules[0].Name != "shared" || p.Rules[0].VaultKey != "user-key" {
		t.Fatalf("rules[0] = %s/%s, want shared/user-key", p.Rules[0].Name, p.Rules[0].VaultKey)
	}
	if p.Rules[1].Name != "global-only" {
		t.Fatalf("rules[1] = %s, want global-only", p.Rules[1].Name)
	}
	if p.Sync == nil || p.Sync.RawInterval != "5m" {
		t.Fatalf("sync = %+v, want interval 5m", p.Sync)
	}
}

func TestComposeMultiGroupUnion(t *testing.T) {
	st := newTestStore(t)
	putLayer(t, st, "group/sydney", `
enrolments:
  sydney-tool: {engine: github}
`)
	putLayer(t, st, "group/newyork", `
enrolments:
  newyork-tool: {engine: github}
`)

	p, _ := composePartial(t, st, LayerKeys("linux", "bob", []string{"sydney", "newyork"}))
	if len(p.Enrolments) != 2 {
		t.Fatalf("enrolments = %v, want union of both groups", p.Enrolments)
	}
	for _, key := range []string{"sydney-tool", "newyork-tool"} {
		if _, ok := p.Enrolments[key]; !ok {
			t.Fatalf("enrolments missing %q: %v", key, p.Enrolments)
		}
	}
}

func TestComposeDeterministicETag(t *testing.T) {
	st := newTestStore(t)
	putLayer(t, st, "global", `
enrolments:
  zeta: {engine: github}
  alpha: {engine: ssh}
  mid: {engine: jfrog, settings: {url: "https://x.example", b: "2", a: "1"}}
rules:
  - name: r1
    vault_key: k
    target: {path: ~/r1.txt, format: text}
`)

	keys := LayerKeys("linux", "alice", []string{"b", "a"})
	c := &Composer{Store: st}
	doc1, etag1, err := c.Compose(context.Background(), keys)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	for i := 0; i < 5; i++ {
		doc2, etag2, err := c.Compose(context.Background(), keys)
		if err != nil {
			t.Fatalf("Compose: %v", err)
		}
		if string(doc1) != string(doc2) || etag1 != etag2 {
			t.Fatalf("composition not deterministic:\n%s\n--- vs ---\n%s", doc1, doc2)
		}
	}
	if !strings.HasPrefix(etag1, `"`) || !strings.HasSuffix(etag1, `"`) {
		t.Fatalf("etag %q is not a quoted strong validator", etag1)
	}
}

func TestComposeMissingLayersSkipSilently(t *testing.T) {
	st := newTestStore(t)
	putLayer(t, st, "global", `
rules:
  - name: only
    vault_key: k
    target: {path: ~/o.txt, format: text}
`)
	// Unknown user, unknown os, no groups: global alone composes fine.
	p, _ := composePartial(t, st, LayerKeys("plan9", "stranger", nil))
	if len(p.Rules) != 1 || p.Rules[0].Name != "only" {
		t.Fatalf("rules = %+v, want the global rule alone", p.Rules)
	}
}

func TestComposeEmptyStore(t *testing.T) {
	st := newTestStore(t)
	p, etag := composePartial(t, st, LayerKeys("linux", "nobody", nil))
	if len(p.Rules) != 0 || len(p.Enrolments) != 0 || p.Sync != nil {
		t.Fatalf("empty store composed non-empty partial: %+v", p)
	}
	if etag == "" {
		t.Fatal("empty composition must still carry an ETag")
	}
}

func TestComposeCorruptLayerNamesKey(t *testing.T) {
	st := newTestStore(t)
	tests := []struct {
		name string
		doc  string
	}{
		{"unparseable", ":\n  - ["},
		{"static section", "vault:\n  address: https://evil.example\n"},
		{"invalid rule", "rules:\n  - name: bad\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			putLayer(t, st, "group/broken", tt.doc)
			c := &Composer{Store: st}
			_, _, err := c.Compose(context.Background(), []string{"group/broken"})
			var le *LayerError
			if err == nil || !errors.As(err, &le) {
				t.Fatalf("Compose error = %v, want LayerError", err)
			}
			if le.Key != "group/broken" {
				t.Fatalf("LayerError.Key = %q, want group/broken", le.Key)
			}
		})
	}
}

// TestComposeOutputIsValidPartialWire double-checks the wire contract end to
// end: the served bytes must parse under the client's ParsePartial and the
// re-marshalled form must be byte-identical (the determinism the ETag relies
// on is a property of marshalling, not of one lucky run).
func TestComposeOutputIsValidPartialWire(t *testing.T) {
	st := newTestStore(t)
	putLayer(t, st, "global", `
rules:
  - name: r
    vault_key: k
    target:
      path: ~/r.txt
      format: text
      template: "{{ .value }}"
enrolments:
  e: {engine: ssh, settings: {passphrase: unsafe}}
`)
	c := &Composer{Store: st}
	doc, _, err := c.Compose(context.Background(), []string{"global"})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	p, err := config.ParsePartial(doc)
	if err != nil {
		t.Fatalf("ParsePartial: %v", err)
	}
	again, err := yaml.Marshal(p)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if string(again) != string(doc) {
		t.Fatalf("marshalling is not stable:\n%s\n--- vs ---\n%s", doc, again)
	}
}
