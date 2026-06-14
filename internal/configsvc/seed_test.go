package configsvc

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSeedValidFixture(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	summary, err := Seed(ctx, st, filepath.Join("testdata", "seed-valid"), nil)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	wantLayers := []string{"global", "group/sydney", "os/linux", "user/alice"}
	if !reflect.DeepEqual(summary.Layers, wantLayers) {
		t.Fatalf("seeded layers = %v, want %v", summary.Layers, wantLayers)
	}
	if want := []string{"alice", "bob"}; !reflect.DeepEqual(summary.Users, want) {
		t.Fatalf("seeded users = %v, want %v", summary.Users, want)
	}

	keys, err := st.ListLayers(ctx, "")
	if err != nil {
		t.Fatalf("ListLayers: %v", err)
	}
	if !reflect.DeepEqual(keys, wantLayers) {
		t.Fatalf("stored layers = %v, want %v", keys, wantLayers)
	}
	groups, ok, err := st.GetGroups(ctx, "bob")
	if err != nil || !ok {
		t.Fatalf("GetGroups(bob) = ok=%v err=%v", ok, err)
	}
	if want := []string{"sydney", "newyork"}; !reflect.DeepEqual(groups, want) {
		t.Fatalf("bob's groups = %v, want %v", groups, want)
	}

	// The seeded store composes end to end.
	p, _ := composePartial(t, st, LayerKeys("linux", "alice", groupsOf(t, st, "alice")))
	if p.Sync == nil || p.Sync.RawInterval != "5m" {
		t.Fatalf("composed sync = %+v, want the user layer's 5m", p.Sync)
	}
	if _, ok := p.Enrolments["sydney-tool"]; !ok {
		t.Fatalf("composed enrolments = %+v, want sydney-tool", p.Enrolments)
	}
}

func groupsOf(t *testing.T, st interface {
	GetGroups(ctx context.Context, user string) ([]string, bool, error)
}, user string) []string {
	t.Helper()
	groups, _, err := st.GetGroups(context.Background(), user)
	if err != nil {
		t.Fatalf("GetGroups(%s): %v", user, err)
	}
	return groups
}

func TestSeedInvalidLayerWritesNothing(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	_, err := Seed(ctx, st, filepath.Join("testdata", "seed-invalid"), nil)
	if err == nil {
		t.Fatal("Seed with invalid fixture succeeded, want error")
	}
	if !strings.Contains(err.Error(), `"group/broken"`) {
		t.Fatalf("Seed error %q does not name the invalid layer", err)
	}
	// Validate-before-write: the valid global layer must not have landed.
	keys, err := st.ListLayers(ctx, "")
	if err != nil {
		t.Fatalf("ListLayers: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("store contains %v after failed seed, want nothing", keys)
	}
}

func TestSeedRejectsStrayFiles(t *testing.T) {
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

	write("global.yaml", "sync:\n  interval: 5m\n")
	write("globl.yaml", "sync:\n  interval: 5m\n") // typo'd filename
	st := newTestStore(t)
	if _, err := Seed(context.Background(), st, dir, nil); err == nil || !strings.Contains(err.Error(), "globl.yaml") {
		t.Fatalf("Seed error = %v, want complaint about globl.yaml", err)
	}
}

func TestSeedRejectsUnknownSubdir(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "oss"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oss", "linux.yaml"), []byte("sync:\n  interval: 5m\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := newTestStore(t)
	if _, err := Seed(context.Background(), st, dir, nil); err == nil || !strings.Contains(err.Error(), "oss") {
		t.Fatalf("Seed error = %v, want complaint about the oss/ directory", err)
	}
}

func TestSeedRejectsMalformedGroupsFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"scalar membership", "alice: 5\n"},
		{"list document", "- alice\n- bob\n"},
		{"unparseable", ":\n  - [\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "groups.yaml"), []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}
			st := newTestStore(t)
			if _, err := Seed(context.Background(), st, dir, nil); err == nil || !strings.Contains(err.Error(), "groups.yaml") {
				t.Fatalf("Seed error = %v, want complaint about groups.yaml", err)
			}
		})
	}
}

func TestSeedMissingDirectory(t *testing.T) {
	st := newTestStore(t)
	if _, err := Seed(context.Background(), st, filepath.Join(t.TempDir(), "nope"), nil); err == nil {
		t.Fatal("Seed of missing directory succeeded, want error")
	}
}
