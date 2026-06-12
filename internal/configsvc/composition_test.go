package configsvc

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/configsvc/groups"
)

func TestParseKind(t *testing.T) {
	tests := []struct {
		in      string
		wantErr string
	}{
		{"global", ""},
		{"os", ""},
		{"group", ""},
		{"device", ""},
		{"user", ""},
		{"os+group", ""},
		{"os+user", ""},
		{"group+user", ""},
		{"os+group+device+user", ""},
		{"group+os", "canonical order"},
		{"user+os", "canonical order"},
		{"os+os", "repeated"},
		{"region", "unknown dimension"},
		{"os+region", "unknown dimension"},
		{"", "must not be empty"},
	}
	for _, tt := range tests {
		kind, err := ParseKind(tt.in)
		if tt.wantErr == "" {
			if err != nil {
				t.Errorf("ParseKind(%q) = %v", tt.in, err)
			} else if kind.String() != tt.in {
				t.Errorf("ParseKind(%q).String() = %q, want round-trip", tt.in, kind.String())
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("ParseKind(%q) = %v, want error containing %q", tt.in, err, tt.wantErr)
		}
	}
}

func TestParseKindNamesCanonicalSpelling(t *testing.T) {
	_, err := ParseKind("user+os+group")
	if err == nil || !strings.Contains(err.Error(), `"os+group+user"`) {
		t.Fatalf("ParseKind error = %v, want the canonical spelling named", err)
	}
}

func TestParseCompositionOrder(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		wantErr string
	}{
		{"the example from the design", []string{"os", "group", "device", "user", "os+group", "os+user", "group+user", "os+group+user"}, ""},
		{"global is an ordinary entry", []string{"global", "user"}, ""},
		// Arbitrary ordering between entries is the operator's call: a
		// combination may precede its parts, global may come last.
		{"combination before its parts", []string{"os+group+user", "os", "global"}, ""},
		{"empty", nil, "at least one entry"},
		{"duplicate entry", []string{"os", "user", "os"}, "listed twice"},
		{"bad kind", []string{"os", "site"}, "unknown dimension"},
		{"non-canonical spelling", []string{"group+os"}, "canonical order"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comp, err := ParseCompositionOrder(tt.entries)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ParseCompositionOrder: %v", err)
				}
				if got := comp.Kinds(); !reflect.DeepEqual(got, tt.entries) {
					t.Fatalf("Kinds() = %v, want the declared order %v verbatim", got, tt.entries)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ParseCompositionOrder = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestCompositionKeysExpansion(t *testing.T) {
	comp, err := ParseCompositionOrder([]string{
		"os", "group", "device", "user", "os+group", "os+user", "group+user", "os+group+user",
	})
	if err != nil {
		t.Fatal(err)
	}

	dims := RequestDims{OS: "Windows", User: "gary", Device: "LAPTOP-7", Groups: []string{"sydney", "auckland"}}
	got := comp.Keys(dims)
	want := []string{
		"os/windows",
		"group/auckland", "group/sydney",
		"device/laptop-7",
		"user/gary",
		"os+group/windows/auckland", "os+group/windows/sydney",
		"os+user/windows/gary",
		"group+user/auckland/gary", "group+user/sydney/gary",
		"os+group+user/windows/auckland/gary", "os+group+user/windows/sydney/gary",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Keys() =\n%v\nwant\n%v", got, want)
	}

	// No groups: every group-bearing kind contributes nothing, the rest
	// stand. No device: device kinds skip.
	got = comp.Keys(RequestDims{OS: "linux", User: "gary"})
	want = []string{"os/linux", "user/gary", "os+user/linux/gary"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Keys() without groups/device = %v, want %v", got, want)
	}
}

func TestNormalizeDevice(t *testing.T) {
	tests := []struct{ in, want string }{
		{"LAPTOP-7", "laptop-7"},       // Windows NetBIOS convention
		{"laptop-7.local", "laptop-7"}, // macOS default
		{"laptop-7.corp.example", "laptop-7"},
		{"laptop-7", "laptop-7"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := NormalizeDevice(tt.in); got != tt.want {
			t.Errorf("NormalizeDevice(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCompositionKeysEmptyLaterDimension(t *testing.T) {
	// An EARLIER dimension is multi-valued while a LATER one is empty: the
	// kind must contribute nothing — no partial keys may leak out of the
	// expansion.
	comp, err := ParseCompositionOrder([]string{"group+device", "group"})
	if err != nil {
		t.Fatal(err)
	}
	got := comp.Keys(RequestDims{OS: "linux", User: "gary", Groups: []string{"sydney", "auckland"}})
	want := []string{"group/auckland", "group/sydney"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Keys() with empty later dimension = %v, want %v (no group+device keys)", got, want)
	}
}

func TestCompositionDeclaredOrderIsPrecedence(t *testing.T) {
	// user listed BEFORE global: the global layer must override the user
	// layer, because the declared order is the merge order — no implicit
	// specificity.
	comp, err := ParseCompositionOrder([]string{"user", "global"})
	if err != nil {
		t.Fatal(err)
	}
	got := comp.Keys(RequestDims{OS: "linux", User: "alice"})
	if want := []string{"user/alice", "global"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Keys() = %v, want %v", got, want)
	}

	st := newTestStore(t)
	putLayer(t, st, "user/alice", "sync:\n  interval: 5m\n")
	putLayer(t, st, "global", "sync:\n  interval: 15m\n")
	c := &Composer{Store: st}
	doc, _, err := c.Compose(context.Background(), got)
	if err != nil {
		t.Fatal(err)
	}
	p, err := config.ParsePartial(doc)
	if err != nil {
		t.Fatal(err)
	}
	if p.Sync == nil || p.Sync.RawInterval != "15m" {
		t.Fatalf("sync = %+v, want global's 15m winning (it is listed last)", p.Sync)
	}
}

func TestDefaultCompositionMatchesLegacyOrder(t *testing.T) {
	got := DefaultComposition().Keys(RequestDims{OS: "Linux", User: "alice", Groups: []string{"sydney", "newyork"}})
	want := []string{"global", "os/linux", "group/newyork", "group/sydney", "user/alice"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("default Keys() = %v, want the original fixed sequence %v", got, want)
	}
	// LayerKeys is the same thing by definition.
	if lk := LayerKeys("Linux", "alice", []string{"sydney", "newyork"}); !reflect.DeepEqual(lk, want) {
		t.Fatalf("LayerKeys = %v, want %v", lk, want)
	}
}

func TestCompositionAllowsKey(t *testing.T) {
	comp, err := ParseCompositionOrder([]string{"global", "os", "os+group"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"global", "os/linux", "os+group/linux/sydney"} {
		if err := comp.AllowsKey(key); err != nil {
			t.Errorf("AllowsKey(%q) = %v, want allowed", key, err)
		}
	}
	for _, key := range []string{"user/alice", "group/sydney", "os+group+user/linux/sydney/alice"} {
		if err := comp.AllowsKey(key); err == nil || !strings.Contains(err.Error(), "never be served") {
			t.Errorf("AllowsKey(%q) = %v, want never-served refusal", key, err)
		}
	}
}

func TestValidLayerKeyCombinations(t *testing.T) {
	tests := []struct {
		key string
		ok  bool
	}{
		{"os+group/linux/sydney", true},
		{"os+group+user/linux/sydney/Alice Smith", true},
		{"group+user/sydney/alice", true},
		{"device/laptop-7", true},
		{"os+group/linux", false},              // missing a value
		{"os+group/linux/sydney/extra", false}, // too many values
		{"group+os/sydney/linux", false},       // non-canonical kind
		{"os+group/Linux/sydney", false},       // os value must be lowercase
		{"device/LAPTOP-7", false},             // device value must be lowercase
		{"os+group/linux/../escape", false},    // traversal in a value
		{"os+region/linux/apac", false},        // unknown dimension
		{"global/extra", false},                // global takes no values
		{"", false},                            // empty key
		{"os+group//sydney", false},            // empty value segment
		{"os/linux/", false},                   // trailing slash = empty value
		{"device/laptop-7.local", false},       // device keys use the short hostname
	}
	for _, tt := range tests {
		err := ValidLayerKey(tt.key)
		if (err == nil) != tt.ok {
			t.Errorf("ValidLayerKey(%q) = %v, want ok=%v", tt.key, err, tt.ok)
		}
	}
}

// TestServerComposesCombinationsInDeclaredOrder drives the whole feature
// over HTTP: an explicit order with combination kinds, the device dimension
// from the hostname header, and an unlisted-but-stored kind never served.
func TestServerComposesCombinationsInDeclaredOrder(t *testing.T) {
	comp, err := ParseCompositionOrder([]string{"global", "os", "os+group", "os+group+user", "device"})
	if err != nil {
		t.Fatal(err)
	}
	st := newTestStore(t)
	ctx := context.Background()
	putLayer(t, st, "global", "sync:\n  interval: 60m\n")
	putLayer(t, st, "os/windows", "sync:\n  interval: 45m\n")
	putLayer(t, st, "os+group/windows/sydney", "sync:\n  interval: 30m\n")
	putLayer(t, st, "os+group+user/windows/sydney/gary", "sync:\n  interval: 5m\n")
	putLayer(t, st, "device/laptop-7", "enrolments:\n  device-tool: {engine: github}\n")
	// Stored under a kind NOT in the order: never looked up, never served.
	putLayer(t, st, "user/gary", "sync:\n  interval: 1m\n")
	if err := st.PutGroups(ctx, "gary", []string{"sydney"}); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(NewServer(st, groups.NewStatic(st), WithComposition(comp)).Handler())
	t.Cleanup(ts.Close)

	resp := get(t, ts.URL+"/v1/config", map[string]string{
		"X-Dotvault-OS":       "Windows",
		"X-Dotvault-User":     "gary",
		"X-Dotvault-Hostname": "LAPTOP-7",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/config = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	p, err := config.ParsePartial(body)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if p.Sync == nil || p.Sync.RawInterval != "5m" {
		t.Fatalf("sync = %+v, want the os+group+user layer's 5m (most specific listed last), not the unlisted user layer's 1m:\n%s", p.Sync, body)
	}
	if _, ok := p.Enrolments["device-tool"]; !ok {
		t.Fatalf("device layer not composed from the hostname header:\n%s", body)
	}

	// Same request without the hostname header: device kinds skip cleanly.
	resp = get(t, ts.URL+"/v1/config", map[string]string{
		"X-Dotvault-OS":   "windows",
		"X-Dotvault-User": "gary",
	})
	body, _ = io.ReadAll(resp.Body)
	p, err = config.ParsePartial(body)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(p.Enrolments) != 0 {
		t.Fatalf("device layer served without a device value: %v", p.Enrolments)
	}

	// A traversal-capable hostname is rejected like the other dimensions.
	resp = get(t, ts.URL+"/v1/config", map[string]string{
		"X-Dotvault-OS":       "windows",
		"X-Dotvault-User":     "gary",
		"X-Dotvault-Hostname": "../escape",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET with traversal hostname = %d, want 400", resp.StatusCode)
	}
}

func TestAdminLayerPutRefusesUnlistedKind(t *testing.T) {
	comp, err := ParseCompositionOrder([]string{"global", "os"})
	if err != nil {
		t.Fatal(err)
	}
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.PutGroups(ctx, "alice", []string{adminGroup}); err != nil {
		t.Fatal(err)
	}
	svc := NewServer(st, groups.NewStatic(st), WithComposition(comp))
	svc.EnableAdmin(AdminConfig{Group: adminGroup, SessionTTL: time.Hour}, fakeAuth{"alice": "s3cret"})
	ts := httptest.NewServer(svc.Handler())
	t.Cleanup(ts.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	login(t, ts, client, "alice", "s3cret")

	// A grammatically valid key whose kind is not in the order: refused
	// with a message saying why, so dead config cannot be published.
	resp := adminDo(t, ts, client, http.MethodPut, "/v1/admin/layers/user/alice", "application/yaml", "sync:\n  interval: 5m\n")
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("PUT unlisted kind = %d, want 422", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "never be served") {
		t.Fatalf("422 body = %q, want the never-served explanation", body)
	}
	// GET and DELETE remain grammar-only so leftovers can be cleaned up.
	putLayer(t, st, "user/alice", "sync:\n  interval: 5m\n")
	if resp := adminDo(t, ts, client, http.MethodGet, "/v1/admin/layers/user/alice", "", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET unlisted-but-stored layer = %d, want 200", resp.StatusCode)
	}
	if resp := adminDo(t, ts, client, http.MethodDelete, "/v1/admin/layers/user/alice", "", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE unlisted-but-stored layer = %d, want 204", resp.StatusCode)
	}
}

func TestSeedCombinationLayers(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("global.yaml", "sync:\n  interval: 60m\n")
	// Sibling branches at both value levels, so the walker's slice-copy
	// discipline is exercised: a shared backing array would cross-pollute
	// the keys.
	write("os+group/linux/sydney.yaml", "sync:\n  interval: 5m\n")
	write("os+group/linux/newyork.yaml", "sync:\n  interval: 6m\n")
	write("os+group/windows/sydney.yaml", "sync:\n  interval: 7m\n")
	write("os+group+user/linux/sydney/gary.yaml", "sync:\n  interval: 1m\n")

	comp, err := ParseCompositionOrder([]string{"global", "os+group", "os+group+user"})
	if err != nil {
		t.Fatal(err)
	}
	st := newTestStore(t)
	summary, err := Seed(context.Background(), st, dir, comp)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	// Write order is global first, then lexicographic — '+' sorts before
	// '/', so os+group+user precedes os+group. Only determinism matters.
	want := []string{
		"global",
		"os+group+user/linux/sydney/gary",
		"os+group/linux/newyork",
		"os+group/linux/sydney",
		"os+group/windows/sydney",
	}
	if !reflect.DeepEqual(summary.Layers, want) {
		t.Fatalf("seeded layers = %v, want %v", summary.Layers, want)
	}
}

func TestSeedRejectsWrongDepthAndUnlistedKind(t *testing.T) {
	comp, err := ParseCompositionOrder([]string{"global", "os+group"})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("file at the wrong depth", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "os+group"), 0o755); err != nil {
			t.Fatal(err)
		}
		// os+group needs two value levels; this file sits at one.
		if err := os.WriteFile(filepath.Join(dir, "os+group", "linux.yaml"), []byte("sync:\n  interval: 5m\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		st := newTestStore(t)
		if _, err := Seed(context.Background(), st, dir, comp); err == nil || !strings.Contains(err.Error(), "value level") {
			t.Fatalf("Seed = %v, want wrong-depth complaint", err)
		}
	})

	t.Run("kind not in the order", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "user"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "user", "alice.yaml"), []byte("sync:\n  interval: 5m\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		st := newTestStore(t)
		if _, err := Seed(context.Background(), st, dir, comp); err == nil || !strings.Contains(err.Error(), "never be served") {
			t.Fatalf("Seed = %v, want never-served refusal", err)
		}
		if keys, _ := st.ListLayers(context.Background(), ""); len(keys) != 0 {
			t.Fatalf("store contains %v after refused seed", keys)
		}
	})
}

func TestLoadConfigCompositionOrder(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
store:
  driver: sqlite
  dsn: ":memory:"
composition:
  order: [os, group, user, os+group, os+group+user]
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	want := []string{"os", "group", "user", "os+group", "os+group+user"}
	if got := cfg.CompositionOrder().Kinds(); !reflect.DeepEqual(got, want) {
		t.Fatalf("CompositionOrder = %v, want %v", got, want)
	}

	// Absent block → the default (legacy) order.
	cfg, err = LoadConfig(writeConfig(t, "store:\n  driver: sqlite\n  dsn: ':memory:'\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.CompositionOrder().Kinds(); !reflect.DeepEqual(got, []string{"global", "os", "group", "user"}) {
		t.Fatalf("default CompositionOrder = %v", got)
	}

	// Invalid entries fail the load.
	if _, err := LoadConfig(writeConfig(t, "store: {driver: sqlite, dsn: ':memory:'}\ncomposition:\n  order: [group+os]\n")); err == nil || !strings.Contains(err.Error(), "canonical order") {
		t.Fatalf("LoadConfig with non-canonical kind = %v, want error", err)
	}

	// An EXPLICIT empty list is an error, not a silent fall-through to the
	// default — the operator who wrote it intended to restrict.
	if _, err := LoadConfig(writeConfig(t, "store: {driver: sqlite, dsn: ':memory:'}\ncomposition:\n  order: []\n")); err == nil || !strings.Contains(err.Error(), "at least one entry") {
		t.Fatalf("LoadConfig with explicit empty order = %v, want at-least-one-entry error", err)
	}
}
